package core

import (
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The connection history: who was connected, from which public IP, when, for how long and how many bytes, on every
// server, with a login or not. WireGuard has no connections and no hooks when a peer comes or goes: a peer is there
// while its handshakes keep coming, at least every 2 minutes while it sends anything, its keepalive too. So the
// history follows the handshakes and the byte counters of the peers.

// RecordInterval is the time between two passes of the history: its times are precise to it.
const RecordInterval = time.Minute

// what the history knows of a peer at the latest pass
type peerCounters struct {
	key      wgtypes.Key
	received int64
	sent     int64
}

type ConnectionView struct {
	ID         int64  `json:"id"`
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	PeerID     int64  `json:"peer_id"`
	PeerName   string `json:"peer_name"`
	Username   string `json:"username"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
	StartedAt  int64  `json:"started_at"`
	LastSeen   int64  `json:"last_seen"`
	EndedAt    int64  `json:"ended_at"`
	Received   int64  `json:"received"`
	Sent       int64  `json:"sent"`
	Connected  bool   `json:"connected"`
}

// Connections returns the latest connections, the open ones first.
func (s *Service) Connections(limit int) ([]ConnectionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	connections, err := s.db.Q().Connections(limit)
	if err != nil {
		return nil, err
	}
	views := make([]ConnectionView, 0, len(connections))
	for _, c := range connections {
		views = append(views, connectionView(c))
	}
	return views, nil
}

func connectionView(c store.Connection) ConnectionView {
	return ConnectionView{
		ID: c.ID, ServerID: c.ServerID, ServerName: c.ServerName, PeerID: c.PeerID, PeerName: c.PeerName,
		Username: c.Username, Address: c.Address, Endpoint: c.Endpoint, StartedAt: c.StartedAt, LastSeen: c.LastSeen,
		EndedAt: c.EndedAt, Received: c.Received, Sent: c.Sent, Connected: c.EndedAt == 0,
	}
}

// recordConnectionsLocked follows the peers of the enabled servers. A connection starts with a handshake younger
// than ConnectedWindow, from the time of that handshake, follows the byte counters of the peer, and ends at the
// latest change of its counters when:
//   - the latest handshake is older than ConnectedWindow: the peer left
//   - the peer sends from another public IP: it moved, a new connection starts
//   - its counters are lower than at the latest pass: the interface started again, a new connection starts
//   - the peer, its server or its interface is gone, or disabled
func (s *Service) recordConnectionsLocked(stats map[wgtypes.Key]network.PeerStats, now time.Time) {
	q := s.db.Q()
	open, err := q.OpenConnections()
	if err != nil {
		s.log.Error("can't read the connections", "error", err)
		return
	}
	byPeer := map[int64]*store.Connection{}
	for index := range open {
		byPeer[open[index].PeerID] = &open[index]
	}
	servers, err := q.Servers()
	if err != nil {
		return
	}
	users, err := q.Users()
	if err != nil {
		return
	}
	usernames := map[int64]string{}
	for _, user := range users {
		usernames[user.ID] = user.Username
	}
	seen := map[int64]bool{}
	for index := range servers {
		server := &servers[index]
		if !server.Enabled {
			continue
		}
		peers, err := q.Peers(server.ID)
		if err != nil {
			continue
		}
		for index := range peers {
			peer := &peers[index]
			if !peer.Enabled {
				continue
			}
			key, entry, ok := liveStatsOf(stats, peer)
			if !ok {
				continue
			}
			seen[peer.ID] = true
			s.recordPeerLocked(server, peer, usernames[peer.UserID], key, entry, byPeer[peer.ID], now)
		}
	}
	for peerID, connection := range byPeer {
		if !seen[peerID] {
			s.endConnectionLocked(connection)
		}
	}
	for peerID := range s.counters {
		if !seen[peerID] {
			// back as a new peer of the interface: its counters start from zero
			delete(s.counters, peerID)
		}
	}
}

// liveStatsOf is peerStatsOf with the key WireGuard reports the peer with: false when the interface hasn't it
func liveStatsOf(stats map[wgtypes.Key]network.PeerStats, peer *store.Peer) (wgtypes.Key, network.PeerStats, bool) {
	if peer.DeviceKey != "" {
		if entry, ok := stats[keyOf(peer.DeviceKey)]; ok {
			return keyOf(peer.DeviceKey), entry, true
		}
	}
	key := keyOf(peer.PublicKey)
	entry, ok := stats[key]
	return key, entry, ok
}

func (s *Service) recordPeerLocked(server *store.Server, peer *store.Peer, username string, key wgtypes.Key,
	entry network.PeerStats, open *store.Connection, now time.Time) {
	previous, known := s.counters[peer.ID]
	s.counters[peer.ID] = peerCounters{key: key, received: entry.Received, sent: entry.Sent}
	recent := !entry.LastHandshake.IsZero() && now.Sub(entry.LastHandshake) < ConnectedWindow
	ip := endpointIP(entry)
	// the same peer on the interface: its counters go on
	sameKey := known && previous.key == key
	reset := sameKey && (entry.Received < previous.received || entry.Sent < previous.sent)
	changed := !known || entry.Received != previous.received || entry.Sent != previous.sent
	start := entry.LastHandshake.Unix()
	if open != nil {
		// another network: an IPv6 address that changes in its /64 is the same device
		moved := ip != "" && open.Endpoint != "" && !sameClient(ip, open.Endpoint)
		if !recent || moved || reset {
			s.endConnectionLocked(open)
			// the new one starts after the old one, even when the peer moved without a new handshake
			if open.LastSeen > start {
				start = open.LastSeen
			}
			open = nil
		}
	}
	if open != nil {
		if known && !sameKey {
			// the device gave the peer its own key, or the configuration file connects again: another peer for
			// WireGuard, whose counters start from zero, the same connection for the history. Its bytes add to the
			// ones counted until the latest pass
			open.RxStart, open.TxStart = -open.Received, -open.Sent
			changed = true
		}
		if !changed && open.PeerName == peer.Name && open.ServerName == server.Name && open.Username == username {
			return
		}
		if changed {
			open.LastSeen = now.Unix()
		}
		open.Received, open.Sent = entry.Received-open.RxStart, entry.Sent-open.TxStart
		open.ServerName, open.PeerName, open.Username = server.Name, peer.Name, username
		if err := s.db.Q().UpdateConnection(open); err != nil {
			s.log.Error("can't save a connection", "peer", peer.Name, "error", err)
		}
		return
	}
	if !recent {
		return
	}
	// the counters since the latest pass belong to this connection: before, it wasn't there
	rxStart, txStart := int64(0), int64(0)
	if sameKey && !reset {
		rxStart, txStart = previous.received, previous.sent
	}
	lastSeen := start
	if changed {
		lastSeen = now.Unix()
	}
	connection := &store.Connection{
		ServerID: server.ID, PeerID: peer.ID, ServerName: server.Name, PeerName: peer.Name, Username: username,
		Address: peer.Address, Endpoint: ip, StartedAt: start, LastSeen: lastSeen,
		Received: entry.Received - rxStart, Sent: entry.Sent - txStart, RxStart: rxStart, TxStart: txStart,
	}
	if err := s.db.Q().CreateConnection(connection); err != nil {
		s.log.Error("can't save a connection", "peer", peer.Name, "error", err)
	}
}

func (s *Service) endConnectionLocked(connection *store.Connection) {
	if err := s.db.Q().EndConnection(connection.ID); err != nil {
		s.log.Error("can't end a connection", "peer", connection.PeerName, "error", err)
	}
}
