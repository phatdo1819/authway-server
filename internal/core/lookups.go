package core

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/store"
)

// Authway Server also looks up the exact names of the access rules itself, files.corp.lan but not *.corp.lan, whose
// names it can't list, for the peers that its DNS server answers (see namePeerLocked), with the DNS servers it asks
// for them. Their addresses inside the networks of the server open for those peers as if their devices had asked: a
// device that kept an answer from before its login, an app that keeps an address for hours, or a browser that asks
// DNS over HTTPS still reaches them. Each name is looked up again when its answer runs out, LookupMin to LookupMax
// later, and at once when a peer logs in or the configuration changes. Not its internet addresses: a device reaches
// them only through the answer it gets, with their stand-in addresses or the routes of the Authway app.

const (
	// how often the names are looked at
	LookupInterval = 30 * time.Second
	// the shortest and the longest time between two lookups of a name, whatever the time to live of its answer
	LookupMin = 30 * time.Second
	LookupMax = time.Hour
	// a lookup that failed, or found no address, is tried again this much later
	LookupRetry = time.Minute
	// the lookups at once
	maxLookups = 8
	// the failures in a row before a warning
	lookupWarning = 3
)

// lookupKey is a name looked up for the peers of a server: each server has its DNS servers
type lookupKey struct {
	server int64
	name   string
}

// lookup is the latest answer to a name looked up: its addresses, whose times to live count from at, and when to look
// it up again
type lookup struct {
	addresses []names.Address
	at        time.Time
	next      time.Time
	failures  int
}

// lookupPeer is a peer to open the addresses of a name for
type lookupPeer struct {
	server *store.Server
	peer   *store.Peer
}

// lookupTask is a name to look up, with the DNS servers to ask
type lookupTask struct {
	key        lookupKey
	serverName string
	upstreams  []netip.AddrPort
	ipv6       bool
}

// runLookups looks up the names until ctx ends
func (s *Service) runLookups(ctx context.Context) {
	if s.opts.Lookup == nil {
		return
	}
	ticker := time.NewTicker(LookupInterval)
	defer ticker.Stop()
	for {
		s.LookUpNames(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.lookupWake:
		}
	}
}

// wakeLookups asks for a round of lookups at once
func (s *Service) wakeLookups() {
	select {
	case s.lookupWake <- struct{}{}:
	default:
	}
}

// forgetLookupsLocked forgets the names looked up for the peers of a server, of all with 0: they're looked up again at
// the next round, and the lookups under way keep nothing
func (s *Service) forgetLookupsLocked(server int64) {
	for key := range s.lookups {
		if server == 0 || key.server == server {
			delete(s.lookups, key)
		}
	}
	s.lookupsReset++
	s.wakeLookups()
}

// LookUpNames is a round: it looks up the names due, then opens the addresses of every name from its latest answer
// for the peers that have it.
func (s *Service) LookUpNames(ctx context.Context) {
	if s.opts.Lookup == nil {
		return
	}
	s.mu.Lock()
	now := s.now()
	reset := s.lookupsReset
	var tasks []lookupTask
	for key, peers := range s.lookupPeersLocked() {
		if entry := s.lookups[key]; entry != nil && now.Before(entry.next) {
			continue
		}
		server := peers[0].server
		// the IPv6 addresses only for a tunnel and networks of IPv6: the others aren't opened
		ipv6 := false
		if tunnel6Of(server).IsValid() {
			for _, network := range parsePrefixes(server.Networks) {
				ipv6 = ipv6 || network.Addr().Is6()
			}
		}
		tasks = append(tasks, lookupTask{key: key, serverName: server.Name, upstreams: upstreamsOf(server, s.opts.UpstreamPort),
			ipv6: ipv6})
	}
	s.mu.Unlock()

	type outcome struct {
		addresses []names.Address
		ok        bool
	}
	outcomes := make([]outcome, len(tasks))
	slots := make(chan struct{}, maxLookups)
	var wait sync.WaitGroup
	for index, task := range tasks {
		slots <- struct{}{}
		wait.Add(1)
		go func() {
			defer func() {
				<-slots
				wait.Done()
			}()
			outcomes[index].addresses, outcomes[index].ok = s.lookUpName(ctx, task)
		}()
	}
	wait.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	now = s.now()
	if s.lookupsReset == reset {
		for index, task := range tasks {
			s.lookedUpLocked(task, outcomes[index].addresses, outcomes[index].ok, now)
		}
	}
	// the peers of now: some may have logged out, or changed their rules, during the lookups
	work := s.lookupPeersLocked()
	for key := range s.lookups {
		if _, ok := work[key]; !ok {
			delete(s.lookups, key)
		}
	}
	for key, peers := range work {
		entry := s.lookups[key]
		if entry == nil {
			continue
		}
		var answers []names.Address
		for _, address := range entry.addresses {
			if left := address.TTL - now.Sub(entry.at); left >= 0 {
				answers = append(answers, names.Address{Addr: address.Addr, TTL: left})
			}
		}
		if len(answers) == 0 {
			continue
		}
		for _, target := range peers {
			s.learnLocked(target.server, target.peer, key.name, answers, learnLookup)
		}
	}
}

// lookupPeersLocked are the exact names of the rules of the peers that the DNS server of Authway Server answers, each
// with those peers: logged in on a server with a login, enabled, not blocked, on an enabled server
func (s *Service) lookupPeersLocked() map[lookupKey][]lookupPeer {
	work := map[lookupKey][]lookupPeer{}
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return work
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return work
	}
	open := map[int64]bool{}
	for _, session := range sessions {
		if session.PausedAt == 0 {
			open[session.PeerID] = true
		}
	}
	for index := range servers {
		server := &servers[index]
		if !server.Enabled {
			continue
		}
		peers, err := q.Peers(server.ID)
		if err != nil {
			continue
		}
		for each := range peers {
			peer := &peers[each]
			if !peer.Enabled || peer.Blocked || (server.Gated() && !open[peer.ID]) {
				continue
			}
			for _, rule := range names.Rules(peer.Access) {
				if !rule.Wildcard {
					key := lookupKey{server: server.ID, name: rule.Name}
					work[key] = append(work[key], lookupPeer{server: server, peer: peer})
				}
			}
		}
	}
	return work
}

// lookUpName asks the DNS servers of a task in turn for the addresses of its name, IPv4 and, when the server has IPv6
// networks, IPv6: false when none answered for IPv4. Some DNS servers answer for IPv4 and never for IPv6: the IPv4
// addresses still open.
func (s *Service) lookUpName(ctx context.Context, task lookupTask) ([]names.Address, bool) {
	versions := []bool{false}
	if task.ipv6 {
		versions = append(versions, true)
	}
	var all []names.Address
	for _, ipv6 := range versions {
		query, err := names.Query(uint16(rand.Uint32()), task.key.name, ipv6)
		if err != nil {
			return nil, false
		}
		answered := false
		for _, upstream := range task.upstreams {
			reply, err := s.opts.Lookup(ctx, upstream, query)
			if err != nil {
				continue
			}
			if addresses, ok := names.Looked(reply, task.key.name); ok {
				all = append(all, addresses...)
				answered = true
				break
			}
		}
		if !answered && ipv6 {
			s.log.Debug("no answer for the IPv6 addresses of a name of the access rules", "server", task.serverName,
				"name", task.key.name)
			break
		}
		if !answered {
			return nil, false
		}
	}
	return all, true
}

// lookedUpLocked keeps the outcome of a lookup. After a failure, the answer before stays until its times to live run
// out.
func (s *Service) lookedUpLocked(task lookupTask, addresses []names.Address, ok bool, now time.Time) {
	entry := s.lookups[task.key]
	if entry == nil {
		entry = &lookup{}
		s.lookups[task.key] = entry
	}
	if !ok {
		entry.failures++
		entry.next = now.Add(LookupRetry)
		if entry.failures == lookupWarning {
			s.log.Warn("can't look up a name of the access rules: its DNS servers don't answer", "server", task.serverName,
				"name", task.key.name)
		}
		return
	}
	if entry.failures >= lookupWarning {
		s.log.Info("a name of the access rules can be looked up again", "server", task.serverName, "name", task.key.name)
	}
	entry.failures = 0
	entry.addresses, entry.at = addresses, now
	wait := LookupRetry
	if len(addresses) > 0 {
		wait = LookupMax
		for _, address := range addresses {
			wait = min(wait, address.TTL)
		}
		wait = max(wait, LookupMin)
	}
	entry.next = now.Add(wait)
}
