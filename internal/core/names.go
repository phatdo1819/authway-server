package core

import (
	"bufio"
	"encoding/binary"
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
//
// A name on the internet, app.example.com, goes through the server too. Its configuration file can't route addresses
// that aren't known in advance, so the answer gives the device stand-in addresses instead, from a network that the
// file routes through the tunnel (Options.StandIns): each IPv4 internet address of the name gets one, learned like
// the addresses inside the networks, and the firewall sends the connections to it on to the internet address, with
// the address of the server. The IPv6 internet addresses go from the answer: the device takes the IPv4 ones.
//
// Authway Server also looks up the exact names itself (lookups.go), and a restart keeps what the peers learned
// (namessaved.go).

const (
	DefaultResolverPort = 8154
	// the stand-in addresses of the internet addresses of names, unless the options say otherwise: 198.18.0.0/15 is
	// for tests of networks, never on the internet
	DefaultStandIns = "198.18.0.0/16"
	// a learned address stays open this much longer than the answer holds: the devices keep their answers a little
	// longer than they should
	LearnedMargin = 10 * time.Minute
	// and a day at most
	LearnedMax = 24 * time.Hour
	// the addresses a peer can have learned at once: past it, the new ones wait for others to expire
	MaxLearned = 1024
	// a stand-in address keeps its internet address this long after the last peer that could use it: a device that
	// keeps an answer longer than it should still reaches the same site, not another one
	StandInGrace = 24 * time.Hour
)

// standIn is the internet address that a stand-in address leads to, and until when a peer may use it
type standIn struct {
	real  netip.Addr
	until time.Time
}

// notInternet are the IPv4 networks that aren't on the internet, besides the private and local ones: "this network",
// the shared one of carrier-grade NAT, the IETF protocol assignments, the one for tests of networks (the stand-in
// addresses by default), and the reserved ones
var notInternet = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
}

// onInternet tells whether an address of an answer is on the internet
func onInternet(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.Is4In6() {
		return false
	}
	for _, network := range notInternet {
		if network.Contains(address) {
			return false
		}
	}
	return true
}

// validStandIns tells whether a network can hold the stand-in addresses: IPv4, from /8 to /24
func validStandIns(network netip.Prefix) bool {
	return network.IsValid() && network.Addr().Is4() && network.Bits() >= 8 && network.Bits() <= 24
}

// standInsOn tells whether the peers with names of a server reach the internet addresses of their names through
// stand-in addresses: not when its networks overlap them, which New warns of.
func (s *Service) standInsOn(server *store.Server) bool {
	standIns := s.opts.StandIns
	if !validStandIns(standIns) {
		return false
	}
	if tunnel, err := netip.ParsePrefix(server.Network); err == nil && tunnel.Overlaps(standIns) {
		return false
	}
	for _, network := range parsePrefixes(server.Networks) {
		if network.Overlaps(standIns) {
			return false
		}
	}
	return true
}

// standInLocked is the stand-in address of an internet address, a new one when it has none: true for new, false when
// they're all taken. It comes from a hash of the internet address, so after a restart it's the same one, unless
// another took it first.
func (s *Service) standInLocked(real netip.Addr) (address netip.Addr, created, ok bool) {
	if address, ok := s.standInOf[real]; ok {
		return address, false, true
	}
	network := s.opts.StandIns.Masked()
	size := uint32(1) << (32 - network.Bits())
	base := network.Addr().As4()
	first := binary.BigEndian.Uint32(base[:])
	// FNV-1a
	hash := uint32(2166136261)
	for _, b := range real.AsSlice() {
		hash = (hash ^ uint32(b)) * 16777619
	}
	start := hash % size
	for step := uint32(0); step < size; step++ {
		var candidate [4]byte
		binary.BigEndian.PutUint32(candidate[:], first+(start+step)%size)
		// not the first and the last address of each 256, which some systems take for a network or a broadcast
		if candidate[3] == 0 || candidate[3] == 255 {
			continue
		}
		address := netip.AddrFrom4(candidate)
		if _, taken := s.standIns[address]; taken {
			continue
		}
		s.standIns[address] = &standIn{real: real}
		s.standInOf[real] = address
		s.namesChanged = true
		return address, true, true
	}
	if !s.standInsFull {
		s.log.Warn("all the stand-in addresses of internet names are taken: the new internet addresses go to the devices as they are",
			"network", network)
		s.standInsFull = true
	}
	return netip.Addr{}, false, false
}

// standInListLocked are the stand-in addresses and where they lead, sorted
func (s *Service) standInListLocked() []network.StandIn {
	list := make([]network.StandIn, 0, len(s.standIns))
	for address, record := range s.standIns {
		list = append(list, network.StandIn{Address: address, Real: record.real})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Address.Less(list[j].Address) })
	return list
}

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
	upstreams := upstreamsOf(server, s.opts.UpstreamPort)
	return upstreams, len(upstreams) > 0
}

// upstreamsOf are the DNS servers asked for the peers with names of a server: its own, or the ones of the container
// when it has none
func upstreamsOf(server *store.Server, port int) []netip.AddrPort {
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
			upstreams = append(upstreams, netip.AddrPortFrom(address, uint16(port)))
		}
	}
	if len(upstreams) == 0 {
		upstreams = systemResolvers()
	}
	return upstreams
}

// Learn reads the answer to a DNS query of a peer, and returns the answer for its device. When it's for a name of its
// access rules, the addresses it gives inside the networks of its server open for that peer at once, before the
// answer goes back. On a server with stand-in addresses, an IPv4 internet address of the name becomes its stand-in
// address in the answer, open for the peer the same way, and an IPv6 one goes. With routes, the Authway app asked:
// it routes the internet addresses itself, so they stay as they are, open for the peer, and the answer lists them
// for the app (IPv6 ones only when the tunnel carries IPv6). The HTTPS and SVCB records of the name go too: their
// hints would give the device addresses that skip all this. Any other answer stays as it was.
func (s *Service) Learn(address netip.Addr, reply []byte, routes bool) []byte {
	asked, answers, ok := names.Answer(reply)
	if !ok {
		return reply
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	server, peer, rules, ok := s.namePeerLocked(address)
	if !ok || !names.Match(rules, asked) {
		return reply
	}
	mode := learnAnswer
	if routes {
		mode = learnRoutes
	}
	change, routeList, ok := s.learnLocked(server, peer, asked, answers, mode)
	if !ok {
		return reply
	}
	if rewritten, ok := names.Rewrite(reply, change, routeList); ok {
		return rewritten
	}
	return reply
}

// learnMode is who asked for the addresses of a name, which tells what becomes of its internet addresses
type learnMode int

const (
	// the device, with the answer of Authway Server: their stand-in addresses, on a server that has them
	learnAnswer learnMode = iota
	// the Authway app, which routes them itself: as they are
	learnRoutes
	// Authway Server itself (see lookups.go): none, a device reaches them only through the answer it gets
	learnLookup
)

// learnLocked opens for a peer the addresses that an answer gives for one of its names, as Learn says, and returns
// what changes in the answer for its device: the addresses to replace or take out, and the routes for the Authway
// app. false when the peer or its server can't be read.
func (s *Service) learnLocked(server *store.Server, peer *store.Peer, asked string, answers []names.Address,
	mode learnMode) (map[netip.Addr]netip.Addr, []names.Address, bool) {
	tunnel, err := netip.ParsePrefix(server.Network)
	if err != nil {
		return nil, nil, false
	}
	tunnel6 := tunnel6Of(server)
	peer4, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return nil, nil, false
	}
	peer6, _ := address6(tunnel.Masked(), tunnel6, peer4)
	networks := parsePrefixes(server.Networks)
	// a peer that sends all its traffic through the tunnel reaches the internet addresses as they are
	standIns := !peer.RouteAll && mode == learnAnswer && s.standInsOn(server)
	routed := !peer.RouteAll && mode == learnRoutes
	internet := standIns || routed
	entry := s.learned[peer.ID]
	if entry == nil || entry.iface != server.Interface || entry.peer4 != peer4 || entry.peer6 != peer6 {
		entry = &learnedPeer{iface: server.Interface, peer4: peer4, peer6: peer6, until: map[netip.Addr]time.Time{}}
		s.learned[peer.ID] = entry
	}
	now := s.now()
	change := map[netip.Addr]netip.Addr{}
	var added []network.Learned
	var created []network.StandIn
	var routeList []names.Address
	var texts []string
	for _, answer := range answers {
		address := answer.Addr
		// what the peer reaches: the address, or its stand-in address
		learn, key := address, peer4
		if address.Is6() {
			key = peer6
		}
		switch {
		case insideAny(netip.PrefixFrom(address, address.BitLen()), networks):
			// of a version its tunnel carries
			if !key.IsValid() {
				continue
			}
		case internet && onInternet(address) && !s.opts.StandIns.Contains(address):
			if routed {
				// the app routes it through the tunnel: of a version the tunnel carries
				if !key.IsValid() {
					change[address] = netip.Addr{}
					continue
				}
				break
			}
			if address.Is6() {
				change[address] = netip.Addr{}
				continue
			}
			standIn, fresh, ok := s.standInLocked(address)
			if !ok {
				continue
			}
			if fresh {
				created = append(created, network.StandIn{Address: standIn, Real: address})
			}
			learn = standIn
		default:
			// a private address outside the networks: nothing a name of the rules may open
			continue
		}
		until := now.Add(min(answer.TTL+LearnedMargin, LearnedMax))
		if before, known := entry.until[learn]; known {
			if until.After(before) {
				entry.until[learn] = until
				s.namesChanged = true
			}
		} else if len(entry.until) >= MaxLearned {
			if !entry.full {
				s.log.Warn("a peer learned too many addresses from its names: the new ones wait for others to expire",
					"server", server.Name, "peer", peer.Name, "addresses", MaxLearned)
				entry.full = true
			}
			continue
		} else {
			entry.until[learn] = until
			s.namesChanged = true
			added = append(added, network.Learned{Peer: key, Address: learn})
			switch {
			case learn != address:
				texts = append(texts, address.String()+" as "+learn.String())
			case routed && !insideAny(netip.PrefixFrom(address, address.BitLen()), networks):
				texts = append(texts, address.String()+" routed by the app")
			default:
				texts = append(texts, address.String())
			}
		}
		if routed && !insideAny(netip.PrefixFrom(address, address.BitLen()), networks) {
			// for as long as the firewall lets it through
			routeList = append(routeList, names.Address{Addr: address, TTL: entry.until[learn].Sub(now)})
		}
		if learn != address {
			// the stand-in address leads to the internet one as long as a peer may use it
			if record := s.standIns[learn]; entry.until[learn].After(record.until) {
				record.until = entry.until[learn]
			}
			change[address] = learn
		}
	}
	applied := false
	if len(created) > 0 {
		if err := s.net.AddStandIns(created...); err != nil {
			s.log.Error("can't set the stand-in addresses of a name, applying the whole configuration", "name", asked, "error", err)
			s.applyLocked()
			applied = true
		}
	}
	if len(added) > 0 {
		message := "a peer can reach the addresses of a name"
		if mode == learnLookup {
			message = "a peer can reach the addresses of a name, looked up by Authway Server"
		}
		s.log.Info(message, "server", server.Name, "peer", peer.Name, "name", asked, "addresses", strings.Join(texts, ", "))
		if !applied {
			if err := s.net.AddLearned(server.Interface, added...); err != nil {
				s.log.Error("can't open the addresses of a name for a peer, applying the whole configuration", "peer", peer.Name,
					"name", asked, "error", err)
				s.applyLocked()
			}
		}
	}
	return change, routeList, true
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
			s.namesChanged = true
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
			s.dropLearnedLocked(id)
		}
		if len(gone) > 0 {
			if err := s.net.RemoveLearned(entry.iface, gone...); err != nil {
				s.log.Error("can't close the expired addresses of names, applying the whole configuration", "error", err)
				s.applyLocked()
			}
		}
	}
	// the stand-in addresses that no peer may use any more, StandInGrace later
	var gone []network.StandIn
	for address, record := range s.standIns {
		if now.Before(record.until.Add(StandInGrace)) {
			continue
		}
		delete(s.standIns, address)
		delete(s.standInOf, record.real)
		gone = append(gone, network.StandIn{Address: address, Real: record.real})
	}
	if len(gone) > 0 {
		s.standInsFull = false
		s.namesChanged = true
		if err := s.net.RemoveStandIns(gone...); err != nil {
			s.log.Error("can't remove the stand-in addresses no longer used, applying the whole configuration", "error", err)
			s.applyLocked()
		}
	}
}

// forgetStandInsLocked forgets every stand-in address: a restore, whose Apply takes them out of the firewall
func (s *Service) forgetStandInsLocked() {
	s.standIns = map[netip.Addr]*standIn{}
	s.standInOf = map[netip.Addr]netip.Addr{}
	s.standInsFull = false
	s.namesChanged = true
}

// dropLearnedLocked forgets in memory what a peer learned: the addresses saved for a restart lose it too, at the next
// writing (see namessaved.go)
func (s *Service) dropLearnedLocked(id int64) {
	if _, ok := s.learned[id]; ok {
		delete(s.learned, id)
		s.namesChanged = true
	}
}

// forgetLearnedLocked forgets what a peer with names learned, and closes the connections it opened to those addresses:
// its rules, or the networks of its server, changed. The callers apply the configuration next, which takes the
// addresses out of the firewall.
func (s *Service) forgetLearnedLocked(server *store.Server, peer *store.Peer) {
	s.dropLearnedLocked(peer.ID)
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
