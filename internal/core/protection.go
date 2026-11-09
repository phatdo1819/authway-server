package core

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The protections against a copied configuration: the lock of a session to the public IP of its login, the
// detection of two devices using the same key, the lockout after failed logins.

// loginFailures counts the failed logins of each peer by public IP. Someone using a copy of the configuration from
// another network can't lock out the real user; a peer failing PeerFailureFactor times more from many IPs is locked
// out from all of them but the IP of its latest login.
type loginFailures struct {
	byPeer  map[int64][]failure
	trusted map[int64]string
}

type failure struct {
	at time.Time
	ip string
}

func newLoginFailures() *loginFailures {
	return &loginFailures{byPeer: map[int64][]failure{}, trusted: map[int64]string{}}
}

func (l *loginFailures) recent(peer int64, now time.Time) []failure {
	var kept []failure
	for _, f := range l.byPeer[peer] {
		if now.Sub(f.at) < LockoutTime {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		delete(l.byPeer, peer)
	} else {
		l.byPeer[peer] = kept
	}
	return kept
}

// lockedUntil tells whether a peer can try to log in from an IP, and until when it can't. The IPs count by
// clientKey: an IPv6 address by its /64, so the many addresses of one network don't multiply the attempts.
func (l *loginFailures) lockedUntil(peer int64, ip string, now time.Time) (time.Time, bool) {
	ip = clientKey(ip)
	recent := l.recent(peer, now)
	var own []failure
	for _, f := range recent {
		if f.ip == ip {
			own = append(own, f)
		}
	}
	var until time.Time
	switch {
	case len(own) >= MaxFailures:
		until = own[len(own)-1].at.Add(LockoutTime)
	case ip != l.trusted[peer] && len(recent) >= MaxFailures*PeerFailureFactor:
		until = recent[len(recent)-1].at.Add(LockoutTime)
	default:
		return time.Time{}, false
	}
	return until, now.Before(until)
}

// add counts a failure and returns the IPs it locks out, none when it locks out nothing new.
func (l *loginFailures) add(peer int64, ip string, now time.Time) []string {
	ip = clientKey(ip)
	recent := append(l.recent(peer, now), failure{at: now, ip: ip})
	l.byPeer[peer] = recent
	own := 0
	ips := map[string]bool{}
	for _, f := range recent {
		ips[f.ip] = true
		if f.ip == ip {
			own++
		}
	}
	if own == MaxFailures {
		return []string{ip}
	}
	if len(recent) == MaxFailures*PeerFailureFactor {
		return sortedKeys(ips)
	}
	return nil
}

// success forgets the failures from the IP of a login, and trusts that IP.
func (l *loginFailures) success(peer int64, ip string) {
	ip = clientKey(ip)
	var kept []failure
	for _, f := range l.byPeer[peer] {
		if f.ip != ip {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		delete(l.byPeer, peer)
	} else {
		l.byPeer[peer] = kept
	}
	l.trusted[peer] = ip
}

// forget drops what is known of a peer: its failures and the IP of its latest login.
func (l *loginFailures) forget(peer int64) {
	delete(l.byPeer, peer)
	delete(l.trusted, peer)
}

// forgetPeerLocked drops the state in memory of a peer: for a new peer, which can get the id of a deleted one, a peer
// with new keys or another user. Its failures, its trusted IP and its endpoints were about another device or user.
func (s *Service) forgetPeerLocked(id int64) {
	s.failures.forget(id)
	delete(s.copies, id)
	delete(s.mismatches, id)
	delete(s.counters, id)
}

func (l *loginFailures) prune(now time.Time) {
	for peer := range l.byPeer {
		l.recent(peer, now)
	}
}

// copyTrack follows the endpoint of a peer. WireGuard answers to the public IP of the latest packet, so while two
// devices with the same key are on, the endpoint keeps switching between their IPs; a device that changes network
// switches once, or to new IPs.
type copyTrack struct {
	last    string
	changes []endpointChange
	seen    time.Time
}

type endpointChange struct {
	at       time.Time
	from, to string
}

// observe records the current IP and returns the IPs seen when they look like two devices.
func (c *copyTrack) observe(ip string, now time.Time) []string {
	c.seen = now
	previous := c.last
	c.last = ip
	if previous == "" || previous == ip {
		return nil
	}
	var kept []endpointChange
	for _, change := range c.changes {
		if now.Sub(change.at) < CopyWindow {
			kept = append(kept, change)
		}
	}
	kept = append(kept, endpointChange{at: now, from: previous, to: ip})
	c.changes = kept
	ips := map[string]bool{kept[0].from: true}
	for _, change := range kept {
		ips[change.to] = true
	}
	// back to an IP already seen: with only new IPs, it's a device moving
	if len(kept) >= CopyChanges && len(ips) <= len(kept) {
		c.changes = nil
		return sortedKeys(ips)
	}
	return nil
}

func sortedKeys(set map[string]bool) []string {
	list := make([]string, 0, len(set))
	for key := range set {
		if key != "" {
			list = append(list, key)
		}
	}
	sort.Strings(list)
	return list
}

func endpointIP(stats network.PeerStats) string {
	if !stats.Endpoint.IsValid() {
		return ""
	}
	return stats.Endpoint.Addr().String()
}

func keyOf(publicKey string) wgtypes.Key {
	key, _ := wgtypes.ParseKey(publicKey)
	return key
}

// followLocked locks the open sessions to the public IP of their login, as their server says: with the strict
// lock a session pauses while its peer sends from another IP (another device has its key, or the device moved) and
// resumes when the peer sends from the IP of the login again; with roaming the session follows the peer. onlyPeer,
// when not 0, limits it to one peer.
func (s *Service) followLocked(stats map[wgtypes.Key]network.PeerStats, onlyPeer int64) {
	q := s.db.Q()
	sessions, err := q.OpenSessions()
	if err != nil {
		s.log.Error("can't read the sessions", "error", err)
		return
	}
	for _, session := range sessions {
		if onlyPeer != 0 && session.PeerID != onlyPeer {
			continue
		}
		server, err := q.Server(session.ServerID)
		if err != nil {
			continue
		}
		peer, err := q.Peer(session.PeerID)
		if err != nil {
			continue
		}
		current := endpointIP(peerStatsOf(stats, peer))
		paused := session.PausedAt != 0
		switch server.LockEndpoint {
		case store.LockRoaming:
			if paused {
				s.resumeLocked(session, server)
			}
			if current != "" && current != session.Endpoint {
				if err := q.SetSessionEndpoint(session.ID, current); err == nil {
					s.log.Info("session follows its peer", "user", session.Username, "peer", session.PeerName, "from", current)
				}
			}
		case store.LockOff:
			if paused {
				s.resumeLocked(session, server)
			}
		default:
			// unknown right after a restart of the interface, until the peer sends again
			if current == "" {
				continue
			}
			// a login while WireGuard couldn't be read has no IP yet: the session is locked to the first one seen
			if session.Endpoint == "" {
				if err := q.SetSessionEndpoint(session.ID, current); err == nil {
					s.log.Info("session locked to the public IP of its peer", "user", session.Username, "peer", session.PeerName, "from", current)
				}
				continue
			}
			// an IPv6 address by its /64: a device changes its address in its network over the day
			same := sameClient(current, session.Endpoint)
			if !same && !paused {
				s.pauseLocked(session, server, current)
			} else if same && paused {
				s.resumeLocked(session, server)
			}
		}
	}
}

func (s *Service) pauseLocked(session store.Session, server *store.Server, current string) {
	if err := s.db.Q().PauseSession(session.ID, s.now().Unix()); err != nil {
		s.log.Error("can't pause a session", "error", err)
		return
	}
	if addresses := addressesOf(server, session.Address); len(addresses) > 0 {
		if err := s.net.RemoveSession(server.Interface, addresses...); err != nil {
			s.log.Error("can't close the gate of a paused session, applying the whole configuration", "error", err)
			s.applyLocked()
		}
	}
	s.log.Warn("session paused: the peer sends from another public IP than at login", "user", session.Username,
		"peer", session.PeerName, "from", current, "login_from", session.Endpoint)
	s.eventLocked(store.Event{Kind: "session_paused", ServerName: session.ServerName, PeerName: session.PeerName,
		Username: session.Username, Source: current, Detail: "logged in from " + session.Endpoint})
}

func (s *Service) resumeLocked(session store.Session, server *store.Server) {
	if s.now().Unix() >= session.ExpiresAt {
		// the next check ends it
		return
	}
	if err := s.db.Q().PauseSession(session.ID, 0); err != nil {
		s.log.Error("can't resume a session", "error", err)
		return
	}
	if addresses := addressesOf(server, session.Address); len(addresses) > 0 {
		if err := s.net.AddSession(server.Interface, addresses...); err != nil {
			s.log.Error("can't open the gate of a resumed session, applying the whole configuration", "error", err)
			s.applyLocked()
		}
	}
	s.log.Info("session resumed", "user", session.Username, "peer", session.PeerName, "from", session.Endpoint)
	s.eventLocked(store.Event{Kind: "session_resumed", ServerName: session.ServerName, PeerName: session.PeerName,
		Username: session.Username, Source: session.Endpoint})
}

// detectCopiesLocked watches the endpoints of the peers of the servers that ask for it.
func (s *Service) detectCopiesLocked(stats map[wgtypes.Key]network.PeerStats, now time.Time) {
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return
	}
	watched := map[int64]bool{}
	for index := range servers {
		server := &servers[index]
		if !server.Enabled || !server.Gated() || !server.DetectCopies {
			continue
		}
		peers, err := q.Peers(server.ID)
		if err != nil {
			continue
		}
		for index := range peers {
			peer := &peers[index]
			ip := endpointIP(peerStatsOf(stats, peer))
			if !peer.Enabled || ip == "" {
				continue
			}
			watched[peer.ID] = true
			track := s.copies[peer.ID]
			if track == nil {
				track = &copyTrack{}
				s.copies[peer.ID] = track
			}
			// by network, as the lock: the IPv6 addresses of one device change, and two devices in one network
			// can't be told apart, as behind one IPv4 NAT
			if ips := track.observe(clientKey(ip), now); ips != nil {
				s.reportCopyLocked(server, peer, ips, now)
			}
		}
	}
	for peer := range s.copies {
		if !watched[peer] {
			delete(s.copies, peer)
		}
	}
}

// reportCopyLocked ends the session of a peer whose key looks used by two devices, records the alert at most once
// an hour, and blocks the peer when its server says so.
func (s *Service) reportCopyLocked(server *store.Server, peer *store.Peer, ips []string, now time.Time) {
	q := s.db.Q()
	recent := false
	if alerts, err := q.Alerts(peer.ID, 50); err == nil {
		for _, alert := range alerts {
			if alert.Kind == "copy" && now.Sub(time.Unix(alert.At, 0)) < CopyReportInterval {
				recent = true
			}
		}
	}
	username := s.usernameLocked(peer.UserID)
	block := server.BlockCopies && !peer.Blocked
	if !recent || block {
		s.log.Warn("the configuration of a peer looks used by two devices at once", "server", server.Name,
			"peer", peer.Name, "user", username, "from", strings.Join(ips, ", "), "blocked", server.BlockCopies)
		if err := q.AddAlert(&store.Alert{PeerID: peer.ID, At: now.Unix(), Kind: "copy", Username: username, Addresses: ips}); err != nil {
			s.log.Error("can't save an alert", "error", err)
		}
		s.eventLocked(store.Event{Kind: "copy_suspected", ServerName: server.Name, PeerName: peer.Name,
			Username: username, Source: strings.Join(ips, ", ")})
	}
	if block {
		if err := q.SetPeerBlocked(peer.ID, true, now.Unix()); err != nil {
			s.log.Error("can't block a peer", "error", err)
		}
		peer.Blocked = true
	}
	s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == peer.ID }, EndCopySuspected)
}

// lockoutLocked records the alert of a lockout.
func (s *Service) lockoutLocked(server *store.Server, peer *store.Peer, ips []string) {
	username := s.usernameLocked(peer.UserID)
	s.log.Warn("too many failed logins, locked out", "server", server.Name, "peer", peer.Name, "user", username,
		"from", strings.Join(ips, ", "), "minutes", int(LockoutTime.Minutes()))
	if err := s.db.Q().AddAlert(&store.Alert{PeerID: peer.ID, At: s.now().Unix(), Kind: "lockout", Username: username, Addresses: ips}); err != nil {
		s.log.Error("can't save an alert", "error", err)
	}
	s.eventLocked(store.Event{Kind: "locked_out", ServerName: server.Name, PeerName: peer.Name, Username: username,
		Source: strings.Join(ips, ", ")})
}

func (s *Service) usernameLocked(userID int64) string {
	if userID == 0 {
		return ""
	}
	if user, err := s.db.Q().User(userID); err == nil {
		return user.Username
	}
	return ""
}

// ClearPeerAlerts deletes the alerts of a peer and unblocks it.
func (s *Service) ClearPeerAlerts(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	peer, server, err := s.peerAndServerLocked(id)
	if err != nil {
		return err
	}
	if err := q.ClearAlerts(id); err != nil {
		return err
	}
	if peer.Blocked {
		if err := q.SetPeerBlocked(id, false, s.now().Unix()); err != nil {
			return err
		}
		s.log.Info("peer unblocked", "peer", peer.Name)
	}
	delete(s.copies, id)
	detail := ""
	if peer.Blocked {
		detail = "unblocked"
	}
	s.changeLocked(by, store.Event{Kind: "alerts_cleared", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID), Detail: detail})
	return nil
}

// RedirectTarget is the server a redirected request or DNS query of a peer goes to, for the servers that lead their
// peers to the login page: its IPv4 address, and its IPv6 one, invalid when it has none. The peer can ask from
// either of its addresses.
func (s *Service) RedirectTarget(address netip.Addr) (netip.Addr, netip.Addr, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	server, peer4, ok := inTunnel(servers, address)
	if !ok || !peer4.IsValid() || !server.Enabled || !server.Gated() || !server.Redirect {
		return netip.Addr{}, netip.Addr{}, false
	}
	peers, err := q.Peers(server.ID)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	for _, peer := range peers {
		if peer.Enabled && peer.Address == peer4.String() {
			tunnel, _ := netip.ParsePrefix(server.Network)
			var own6 netip.Addr
			if tunnel6 := tunnel6Of(server); tunnel6.IsValid() {
				own6 = serverAddress(tunnel6)
			}
			return serverAddress(tunnel), own6, true
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

// inTunnel finds the server whose tunnel has an address of a peer, and the IPv4 address of that peer: the address
// itself, or the one an IPv6 address stands for. The IPv4 address is invalid when an IPv6 address of the tunnel
// isn't the one of an IPv4 address: no peer has it.
func inTunnel(servers []store.Server, address netip.Addr) (*store.Server, netip.Addr, bool) {
	address = address.Unmap()
	for index := range servers {
		server := &servers[index]
		tunnel, err := netip.ParsePrefix(server.Network)
		if err != nil {
			continue
		}
		tunnel = tunnel.Masked()
		if address.Is4() && tunnel.Contains(address) {
			return server, address, true
		}
		if tunnel6 := tunnel6Of(server); address.Is6() && tunnel6.IsValid() && tunnel6.Contains(address) {
			peer4, _ := address4(tunnel, tunnel6, address)
			return server, peer4, true
		}
	}
	return nil, netip.Addr{}, false
}
