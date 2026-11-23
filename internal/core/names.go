package core

import (
	"bufio"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// Names in the access rules of the peers: files.corp.lan, or *.corp.lan for every name under corp.lan. Their
// addresses aren't known in advance, so a peer with names asks Authway Server for its DNS (its configuration file
// says so, and the firewall sends it there anyway once it's logged in). Authway Server asks the DNS servers of the
// server, and before the answer goes back, the addresses it gives for the names of the rules, inside the networks of
// the server, open for that peer: for the time to live of the answer and LearnedMargin more. The connections opened
// meanwhile stay open after that; new ones need a new answer.

const (
	DefaultResolverPort = 8154
	// a learned address stays open this much longer than the answer holds: the devices keep their answers a little
	// longer than they should
	LearnedMargin = 10 * time.Minute
	// and a day at most
	LearnedMax = 24 * time.Hour
	// the addresses a peer can have learned at once: past it, the new ones wait for others to expire
	MaxLearned = 1024
)

// learnedPeer is what a peer learned: its interface and its addresses in its tunnel, the keys of the sets of the
// firewall, and until when each address it learned stays open
type learnedPeer struct {
	iface        string
	peer4, peer6 netip.Addr
	until        map[netip.Addr]time.Time
	// a warning when it reached MaxLearned, once
	full bool
}

// hasNames tells whether access rules have names
func hasNames(access []string) bool {
	return len(names.Rules(access)) > 0
}

// namePeerLocked finds the peer with names of a tunnel address, logged in on a server with a login: what the DNS
// server of those peers answers.
func (s *Service) namePeerLocked(address netip.Addr) (*store.Server, *store.Peer, []names.Rule, bool) {
	servers, err := s.db.Q().Servers()
	if err != nil {
		return nil, nil, nil, false
	}
	server, peer4, ok := inTunnel(servers, address)
	if !ok || !peer4.IsValid() || !server.Enabled {
		return nil, nil, nil, false
	}
	peers, err := s.db.Q().Peers(server.ID)
	if err != nil {
		return nil, nil, nil, false
	}
	for index := range peers {
		peer := &peers[index]
		if !peer.Enabled || peer.Address != peer4.String() {
			continue
		}
		rules := names.Rules(peer.Access)
		if len(rules) == 0 || peer.Blocked {
			return nil, nil, nil, false
		}
		if server.Gated() {
			if session, ok := s.openSessionOfLocked(peer.ID); !ok || session.PausedAt != 0 {
				return nil, nil, nil, false
			}
		}
		return server, peer, rules, true
	}
	return nil, nil, nil, false
}

// Resolver gives the DNS servers that the queries of a peer with names go to, by its tunnel address: those of its
// server, or the ones of the container when it has none. false when the address isn't a peer with names, logged in.
func (s *Service) Resolver(address netip.Addr) ([]netip.AddrPort, bool) {
	s.mu.Lock()
	server, _, _, ok := s.namePeerLocked(address)
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	// not the server itself: the queries would come back here
	own := map[netip.Addr]bool{}
	if tunnel, err := netip.ParsePrefix(server.Network); err == nil {
		own[serverAddress(tunnel.Masked())] = true
	}
	if tunnel6 := tunnel6Of(server); tunnel6.IsValid() {
		own[serverAddress(tunnel6)] = true
	}
	var upstreams []netip.AddrPort
	for _, text := range server.DNS {
		if address, err := netip.ParseAddr(text); err == nil && !own[address] {
			upstreams = append(upstreams, netip.AddrPortFrom(address, uint16(s.opts.UpstreamPort)))
		}
	}
	if len(upstreams) == 0 {
		upstreams = systemResolvers()
	}
	return upstreams, len(upstreams) > 0
}

// Learn reads the answer to a DNS query of a peer: when it's for a name of its access rules, the addresses it gives
// inside the networks of its server open for that peer at once, before the answer goes back to the device.
func (s *Service) Learn(address netip.Addr, reply []byte) {
	asked, answers, ok := names.Answer(reply)
	if !ok || len(answers) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	server, peer, rules, ok := s.namePeerLocked(address)
	if !ok || !names.Match(rules, asked) {
		return
	}
	tunnel, err := netip.ParsePrefix(server.Network)
	if err != nil {
		return
	}
	tunnel6 := tunnel6Of(server)
	peer4, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return
	}
	peer6, _ := address6(tunnel.Masked(), tunnel6, peer4)
	networks := parsePrefixes(server.Networks)
	entry := s.learned[peer.ID]
	if entry == nil || entry.iface != server.Interface || entry.peer4 != peer4 || entry.peer6 != peer6 {
		entry = &learnedPeer{iface: server.Interface, peer4: peer4, peer6: peer6, until: map[netip.Addr]time.Time{}}
		s.learned[peer.ID] = entry
	}
	now := s.now()
	var added []network.Learned
	var texts []string
	for _, answer := range answers {
		address := answer.Addr
		key := peer4
		if address.Is6() {
			key = peer6
		}
		// only inside the networks of the server, of a version its tunnel carries
		if !key.IsValid() || !insideAny(netip.PrefixFrom(address, address.BitLen()), networks) {
			continue
		}
		until := now.Add(min(answer.TTL+LearnedMargin, LearnedMax))
		if before, known := entry.until[address]; known {
			if until.After(before) {
				entry.until[address] = until
			}
			continue
		}
		if len(entry.until) >= MaxLearned {
			if !entry.full {
				s.log.Warn("a peer learned too many addresses from its names: the new ones wait for others to expire",
					"server", server.Name, "peer", peer.Name, "addresses", MaxLearned)
				entry.full = true
			}
			continue
		}
		entry.until[address] = until
		added = append(added, network.Learned{Peer: key, Address: address})
		texts = append(texts, address.String())
	}
	if len(added) == 0 {
		return
	}
	s.log.Info("a peer can reach the addresses of a name", "server", server.Name, "peer", peer.Name, "name", asked,
		"addresses", strings.Join(texts, ", "))
	if err := s.net.AddLearned(server.Interface, added...); err != nil {
		s.log.Error("can't open the addresses of a name for a peer, applying the whole configuration", "peer", peer.Name,
			"name", asked, "error", err)
		s.applyLocked()
	}
}

// learnedLocked are the addresses a peer learned and that are still open, sorted
func (s *Service) learnedLocked(id int64) []netip.Addr {
	entry := s.learned[id]
	if entry == nil {
		return nil
	}
	now := s.now()
	list := make([]netip.Addr, 0, len(entry.until))
	for address, until := range entry.until {
		if now.Before(until) {
			list = append(list, address)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Less(list[j]) })
	return list
}

// pruneLearnedLocked closes the learned addresses whose time is up, at each Tick
func (s *Service) pruneLearnedLocked(now time.Time) {
	for id, entry := range s.learned {
		var gone []network.Learned
		for address, until := range entry.until {
			if now.Before(until) {
				continue
			}
			delete(entry.until, address)
			key := entry.peer4
			if address.Is6() {
				key = entry.peer6
			}
			gone = append(gone, network.Learned{Peer: key, Address: address})
		}
		if len(entry.until) < MaxLearned {
			entry.full = false
		}
		if len(entry.until) == 0 {
			delete(s.learned, id)
		}
		if len(gone) > 0 {
			if err := s.net.RemoveLearned(entry.iface, gone...); err != nil {
				s.log.Error("can't close the expired addresses of names, applying the whole configuration", "error", err)
				s.applyLocked()
			}
		}
	}
}

// forgetLearnedLocked forgets what a peer with names learned, and closes the connections it opened to those addresses:
// its rules, or the networks of its server, changed. The callers apply the configuration next, which takes the
// addresses out of the firewall.
func (s *Service) forgetLearnedLocked(server *store.Server, peer *store.Peer) {
	delete(s.learned, peer.ID)
	if !hasNames(peer.Access) {
		return
	}
	addresses := addressesOf(server, peer.Address)
	if len(addresses) == 0 {
		return
	}
	if err := s.net.ForgetLearned(addresses...); err != nil {
		s.log.Warn("can't close the connections of a peer to the addresses of its names", "peer", peer.Name, "error", err)
	}
}

// forgetServerLearnedLocked does it for every peer with names of a server
func (s *Service) forgetServerLearnedLocked(server *store.Server) {
	peers, err := s.db.Q().Peers(server.ID)
	if err != nil {
		return
	}
	for index := range peers {
		if hasNames(peers[index].Access) || s.learned[peers[index].ID] != nil {
			s.forgetLearnedLocked(server, &peers[index])
		}
	}
}

// the DNS servers of the container, read again at most every minute: Docker writes them in /etc/resolv.conf
var resolvConf struct {
	sync.Mutex
	read    time.Time
	servers []netip.AddrPort
}

func systemResolvers() []netip.AddrPort {
	resolvConf.Lock()
	defer resolvConf.Unlock()
	if time.Since(resolvConf.read) < time.Minute {
		return resolvConf.servers
	}
	resolvConf.read = time.Now()
	resolvConf.servers = nil
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if address, err := netip.ParseAddr(fields[1]); err == nil && address.Zone() == "" {
				resolvConf.servers = append(resolvConf.servers, netip.AddrPortFrom(address.Unmap(), 53))
			}
		}
	}
	return resolvConf.servers
}
