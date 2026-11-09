package core

import (
	"net/netip"
	"strings"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/peerconf"
	"github.com/phatdo1819/authway-server/internal/store"
)

const maxPeerName = 64

// PeerInput is what the web UI sends to add or edit a peer. The address is chosen by the server when empty, and
// can't change later: the configuration file of the peer has it.
type PeerInput struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UserID   int64  `json:"user_id"`
	RouteAll bool   `json:"route_all"`
	Address  string `json:"address"`
}

func (s *Service) CreatePeer(by Actor, serverID int64, input PeerInput) (*PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	server, err := q.Server(serverID)
	if err != nil {
		return nil, notFound(err)
	}
	peers, err := q.Peers(serverID)
	if err != nil {
		return nil, err
	}
	peer := &store.Peer{ServerID: serverID}
	if err := s.checkPeer(input, server, peer, peers); err != nil {
		return nil, err
	}
	tunnel, _ := netip.ParsePrefix(server.Network)
	address := strings.TrimSpace(input.Address)
	if address == "" {
		free, ok := freeAddress(tunnel, peers)
		if !ok {
			return nil, &ValidationError{Fields: map[string]string{"address": "network_full"}}
		}
		peer.Address = free.String()
	} else {
		parsed, err := netip.ParseAddr(address)
		switch {
		case err != nil || !peerAddress(tunnel, parsed):
			return nil, &ValidationError{Fields: map[string]string{"address": "invalid"}}
		case addressTaken(parsed.String(), peers):
			return nil, &ValidationError{Fields: map[string]string{"address": "taken"}}
		}
		peer.Address = parsed.String()
	}
	if err := setNewKeys(peer); err != nil {
		return nil, err
	}
	now := s.now().Unix()
	peer.CreatedAt, peer.UpdatedAt = now, now
	if err := q.CreatePeer(peer); err != nil {
		return nil, takenOr(err, "name")
	}
	s.forgetPeerLocked(peer.ID)
	s.log.Info("peer added", "server", server.Name, "peer", peer.Name, "address", peer.Address)
	detail := peer.Address
	if peer.RouteAll {
		detail += ", all the traffic"
	}
	if !peer.Enabled {
		detail += ", disabled"
	}
	s.changeLocked(by, store.Event{Kind: "peer_added", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID), Detail: detail})
	s.applyLocked()
	return s.peerViewLocked(peer)
}

func (s *Service) UpdatePeer(by Actor, id int64, input PeerInput) (*PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	peer, err := q.Peer(id)
	if err != nil {
		return nil, notFound(err)
	}
	server, err := q.Server(peer.ServerID)
	if err != nil {
		return nil, notFound(err)
	}
	peers, err := q.Peers(peer.ServerID)
	if err != nil {
		return nil, err
	}
	before := *peer
	if err := s.checkPeer(input, server, peer, peers); err != nil {
		return nil, err
	}
	peer.UpdatedAt = s.now().Unix()
	if err := q.UpdatePeer(peer); err != nil {
		return nil, takenOr(err, "name")
	}
	s.log.Info("peer changed", "server", server.Name, "peer", peer.Name)
	var c changes
	c.text("name", before.Name, peer.Name)
	if before.Enabled != peer.Enabled {
		c = append(c, map[bool]string{true: "enabled", false: "disabled"}[peer.Enabled])
	}
	c.text("user", s.usernameLocked(before.UserID), s.usernameLocked(peer.UserID))
	c.toggle("all the traffic through the tunnel", before.RouteAll, peer.RouteAll)
	if len(c) > 0 {
		s.changeLocked(by, store.Event{Kind: "peer_changed", ServerName: server.Name, PeerName: peer.Name,
			Username: s.usernameLocked(peer.UserID), Detail: c.String()})
	}
	if !peer.Enabled || peer.UserID != before.UserID {
		s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == id }, EndPeerChanged)
	}
	if peer.UserID != before.UserID {
		s.forgetPeerLocked(id)
		// the device of another user: the new user enrolls a device of their own
		s.resetDeviceLocked(server, id)
	}
	s.applyLocked()
	return s.peerViewLocked(peer)
}

func (s *Service) DeletePeer(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := s.db.Q().Peer(id)
	if err != nil {
		return notFound(err)
	}
	serverName := ""
	if server, err := s.db.Q().Server(peer.ServerID); err == nil {
		serverName = server.Name
	}
	username := s.usernameLocked(peer.UserID)
	s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == id }, EndPeerChanged)
	// a new peer can get its id: the history must not go on with it
	if err := s.db.Q().EndConnectionsOf(peer.ServerID, id); err != nil {
		s.log.Error("can't end the connections of a peer", "error", err)
	}
	if err := s.db.Q().DeletePeer(id); err != nil {
		return notFound(err)
	}
	delete(s.counters, id)
	s.log.Info("peer deleted", "peer", peer.Name, "address", peer.Address)
	s.changeLocked(by, store.Event{Kind: "peer_deleted", ServerName: serverName, PeerName: peer.Name, Username: username,
		Detail: peer.Address})
	s.applyLocked()
	return nil
}

// RegeneratePeerKeys gives a peer new keys: its configuration file, and every copy of it, stops working. A blocked
// peer is unblocked, and its alerts, about the old keys, go.
func (s *Service) RegeneratePeerKeys(by Actor, id int64) (*PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	peer, err := q.Peer(id)
	if err != nil {
		return nil, notFound(err)
	}
	server, err := q.Server(peer.ServerID)
	if err != nil {
		return nil, notFound(err)
	}
	if err := setNewKeys(peer); err != nil {
		return nil, err
	}
	detail := "the old configuration file stops working"
	if peer.Blocked {
		detail += ", unblocked"
	}
	peer.Blocked = false
	peer.UpdatedAt = s.now().Unix()
	if err := q.UpdatePeer(peer); err != nil {
		return nil, err
	}
	if err := q.ClearAlerts(id); err != nil {
		s.log.Error("can't clear the alerts of a peer", "error", err)
	}
	s.forgetPeerLocked(id)
	// the device and the WireGuard key it gave belonged to the old keys: a device enrolls with the new file
	s.resetDeviceLocked(server, id)
	peer.DeviceKey, peer.DeviceKeyAt = "", 0
	s.log.Info("new keys for a peer", "peer", peer.Name)
	s.changeLocked(by, store.Event{Kind: "peer_keys", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID), Detail: detail})
	s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == id }, EndPeerChanged)
	s.applyLocked()
	return s.peerViewLocked(peer)
}

// LogoutPeer ends the session of a peer: it must log in again.
func (s *Service) LogoutPeer(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, server, err := s.peerAndServerLocked(id)
	if err != nil {
		return err
	}
	if s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == id }, EndByAdmin) > 0 {
		s.changeLocked(by, store.Event{Kind: "session_ended", ServerName: server.Name, PeerName: peer.Name,
			Username: s.usernameLocked(peer.UserID)})
	}
	return nil
}

// PeerConfig returns the name and the content of the configuration file of a peer. It has the private key of the
// peer: each time is an event.
func (s *Service) PeerConfig(by Actor, id int64) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	peer, err := q.Peer(id)
	if err != nil {
		return "", "", notFound(err)
	}
	server, err := q.Server(peer.ServerID)
	if err != nil {
		return "", "", notFound(err)
	}
	serverKey, err := wgtypes.ParseKey(server.PrivateKey)
	if err != nil {
		return "", "", err
	}
	tunnel, err := netip.ParsePrefix(server.Network)
	if err != nil {
		return "", "", err
	}
	address, err := netip.ParseAddr(peer.Address)
	if err != nil {
		return "", "", err
	}
	tunnel6 := tunnel6Of(server)
	// invalid without an IPv6 network
	other, _ := address6(tunnel.Masked(), tunnel6, address)
	networks := append(append([]string{}, server.Networks...), s.linkedNetworksLocked(server)...)
	config := peerconf.Config{
		PeerName:        peer.Name,
		ServerName:      server.Name,
		PrivateKey:      peer.PrivateKey,
		Address:         address,
		Address6:        other,
		DNS:             server.DNS,
		MTU:             server.MTU,
		ServerPublicKey: serverKey.PublicKey().String(),
		PresharedKey:    peer.PresharedKey,
		AllowedIPs:      peerconf.AllowedIPs(peer.RouteAll, tunnel, tunnel6, networks),
		Endpoint:        peerconf.Endpoint(server.PublicHost, server.EndpointPort()),
		Fallbacks:       server.FallbackEndpoints,
		Keepalive:       server.Keepalive,
	}
	if server.Gated() {
		config.Login = peerconf.LoginURL(serverAddress(tunnel), s.opts.LoginPort)
	}
	s.changeLocked(by, store.Event{Kind: "peer_config", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID)})
	return peerconf.FileName(server.Name), config.String(), nil
}

// linkedNetworksLocked are the tunnel networks of the servers linked to a server: the ones its peers reach, and the
// ones whose peers reach them. A peer that doesn't send all its traffic through the tunnel routes them there: the
// answers too must come back through the tunnel.
func (s *Service) linkedNetworksLocked(server *store.Server) []string {
	servers, err := s.db.Q().Servers()
	if err != nil {
		return nil
	}
	var list []string
	for _, other := range servers {
		if other.ID == server.ID {
			continue
		}
		if containsID(server.ReachableServers, other.ID) || containsID(other.ReachableServers, server.ID) {
			if tunnel, err := netip.ParsePrefix(other.Network); err == nil && !containsText(list, tunnel.Masked().String()) {
				list = append(list, tunnel.Masked().String())
			}
			// over IPv6 when both tunnels have it: the peers of a server without it have no IPv6 address
			if tunnel6 := tunnel6Of(&other); tunnel6.IsValid() && tunnel6Of(server).IsValid() && !containsText(list, tunnel6.String()) {
				list = append(list, tunnel6.String())
			}
		}
	}
	return list
}

func containsText(list []string, text string) bool {
	for _, value := range list {
		if value == text {
			return true
		}
	}
	return false
}

func (s *Service) checkPeer(input PeerInput, server *store.Server, peer *store.Peer, peers []store.Peer) error {
	var c checks
	name := strings.TrimSpace(input.Name)
	switch {
	case name == "":
		c.fail("name", "required")
	case len([]rune(name)) > maxPeerName || strings.IndexFunc(name, unicode.IsControl) >= 0:
		c.fail("name", "invalid")
	}
	if input.UserID != 0 {
		user, err := s.db.Q().User(input.UserID)
		switch {
		case err != nil || user == nil:
			c.fail("user_id", "invalid")
		default:
			// one peer for each user on a server: the login of the user opens the gate for that peer only
			for _, other := range peers {
				if other.ID != peer.ID && other.UserID == input.UserID {
					c.fail("user_id", "has_peer")
				}
			}
		}
	} else if server.Gated() {
		c.fail("user_id", "required")
	}
	for _, other := range peers {
		if other.ID != peer.ID && strings.EqualFold(other.Name, name) {
			c.fail("name", "taken")
		}
	}
	if err := c.err(); err != nil {
		return err
	}
	peer.Name = name
	peer.Enabled = input.Enabled
	peer.UserID = input.UserID
	peer.RouteAll = input.RouteAll
	return nil
}

func setNewKeys(peer *store.Peer) error {
	private, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	preshared, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	peer.PrivateKey = private.String()
	peer.PublicKey = private.PublicKey().String()
	peer.PresharedKey = preshared.String()
	return nil
}

func freeAddress(tunnel netip.Prefix, peers []store.Peer) (netip.Addr, bool) {
	used := map[string]bool{}
	for _, peer := range peers {
		used[peer.Address] = true
	}
	for address := serverAddress(tunnel).Next(); tunnel.Contains(address); address = address.Next() {
		if peerAddress(tunnel, address) && !used[address.String()] {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func addressTaken(address string, peers []store.Peer) bool {
	for _, peer := range peers {
		if peer.Address == address {
			return true
		}
	}
	return false
}
