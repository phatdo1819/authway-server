package core

import (
	"net/netip"
	"sort"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The views are what the web UI gets. They never carry a private key: only the configuration file of a peer has
// its own.

type ServerView struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Interface  string `json:"interface"`
	Enabled    bool   `json:"enabled"`
	PublicHost string `json:"public_host"`
	ListenPort int    `json:"listen_port"`
	PublicPort int    `json:"public_port"`
	Network    string `json:"network"`
	Address    string `json:"address"`
	// "" without an IPv6 network
	Network6       string   `json:"network6"`
	Address6       string   `json:"address6"`
	Networks       []string `json:"networks"`
	DNS            []string `json:"dns"`
	MTU            int      `json:"mtu"`
	Keepalive      int      `json:"keepalive"`
	AuthMode       string   `json:"auth_mode"`
	SessionTimeout int      `json:"session_timeout"`
	LockEndpoint   string   `json:"lock_endpoint"`
	DetectCopies   bool     `json:"detect_copies"`
	BlockCopies    bool     `json:"block_copies"`
	Redirect       bool     `json:"redirect"`
	Fallbacks      []string `json:"fallback_endpoints"`
	DeviceBinding  bool     `json:"device_binding"`
	MachineID      bool     `json:"machine_id"`
	ClientToClient bool     `json:"client_to_client"`
	Reachable      []int64  `json:"reachable_servers"`
	Routed         bool     `json:"routed"`
	Inbound        bool     `json:"inbound"`
	// routed: what the router of its networks needs
	Routes    []RouteView `json:"routes,omitempty"`
	PublicKey string      `json:"public_key"`
	LoginURL  string      `json:"login_url,omitempty"`
	Peers     int         `json:"peers"`
	// the peers with no user: with a login they can't log in, until they get one
	PeersWithoutUser int   `json:"peers_without_user"`
	Connected        int   `json:"connected"`
	Sessions         int   `json:"sessions"`
	CreatedAt        int64 `json:"created_at"`
	UpdatedAt        int64 `json:"updated_at"`
}

// DeviceView is the device of a peer of a server with device binding.
type DeviceView struct {
	// enrolled, waiting (a device can enroll until EnrollmentUntil) or closed
	State           string `json:"state"`
	EnrollmentUntil int64  `json:"enrollment_until"`
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	// a machine ID is recorded
	MachineID  bool   `json:"machine_id"`
	EnrolledAt int64  `json:"enrolled_at"`
	LastUsedAt int64  `json:"last_used_at"`
	LastFrom   string `json:"last_from"`
	// configuration or device: the key the peer connects with
	WireGuardKey   string `json:"wireguard_key"`
	WireGuardKeyAt int64  `json:"wireguard_key_at"`
}

type PeerView struct {
	ID       int64  `json:"id"`
	ServerID int64  `json:"server_id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Address  string `json:"address"`
	// "" when the server has no IPv6 network
	Address6      string       `json:"address6"`
	PublicKey     string       `json:"public_key"`
	RouteAll      bool         `json:"route_all"`
	Blocked       bool         `json:"blocked"`
	Alerts        int          `json:"alerts"`
	Connected     bool         `json:"connected"`
	LastHandshake int64        `json:"last_handshake"`
	Endpoint      string       `json:"endpoint"`
	Received      int64        `json:"received"`
	Sent          int64        `json:"sent"`
	Session       *SessionView `json:"session"`
	// only on a server with device binding
	Device    *DeviceView `json:"device"`
	CreatedAt int64       `json:"created_at"`
	UpdatedAt int64       `json:"updated_at"`
}

type SessionView struct {
	ID         int64  `json:"id"`
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	PeerID     int64  `json:"peer_id"`
	PeerName   string `json:"peer_name"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
	StartedAt  int64  `json:"started_at"`
	ExpiresAt  int64  `json:"expires_at"`
	EndedAt    int64  `json:"ended_at"`
	EndReason  string `json:"end_reason"`
	PausedAt   int64  `json:"paused_at"`
}

type AlertView struct {
	ID         int64    `json:"id"`
	PeerID     int64    `json:"peer_id"`
	PeerName   string   `json:"peer_name"`
	ServerID   int64    `json:"server_id"`
	ServerName string   `json:"server_name"`
	Blocked    bool     `json:"blocked"`
	At         int64    `json:"at"`
	Kind       string   `json:"kind"`
	Username   string   `json:"username"`
	Addresses  []string `json:"addresses"`
}

type UserView struct {
	ID        int64    `json:"id"`
	Username  string   `json:"username"`
	FullName  string   `json:"full_name"`
	Disabled  bool     `json:"disabled"`
	TOTP      bool     `json:"totp"`
	Peers     []string `json:"peers"`
	Sessions  int      `json:"sessions"`
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}

type EventView struct {
	ID         int64  `json:"id"`
	At         int64  `json:"at"`
	Kind       string `json:"kind"`
	ServerName string `json:"server_name"`
	PeerName   string `json:"peer_name"`
	Username   string `json:"username"`
	Source     string `json:"source"`
	Detail     string `json:"detail"`
	// the administrator who made the change, for the events of the web UI
	By string `json:"by"`
}

func eventView(event store.Event) EventView {
	return EventView{
		ID: event.ID, At: event.At, Kind: event.Kind, ServerName: event.ServerName, PeerName: event.PeerName,
		Username: event.Username, Source: event.Source, Detail: event.Detail, By: event.Actor,
	}
}

// Status is the state of the whole server, for the top of the web UI.
type Status struct {
	ApplyError string `json:"apply_error"`
	Servers    int    `json:"servers"`
	Peers      int    `json:"peers"`
	Connected  int    `json:"connected"`
	Sessions   int    `json:"sessions"`
	LoginPort  int    `json:"login_port"`
	// the version of Authway Server, at the bottom of the menu
	Version string `json:"version"`
	// the routes to change on the routers: the address of the Docker host changed
	HostChanges []HostAddressChange `json:"host_changes"`
}

func sessionView(session store.Session) *SessionView {
	return &SessionView{
		ID: session.ID, ServerID: session.ServerID, ServerName: session.ServerName, PeerID: session.PeerID,
		PeerName: session.PeerName, UserID: session.UserID, Username: session.Username, Address: session.Address,
		Endpoint: session.Endpoint, StartedAt: session.StartedAt, ExpiresAt: session.ExpiresAt,
		EndedAt: session.EndedAt, EndReason: session.EndReason, PausedAt: session.PausedAt,
	}
}

func (s *Service) connectedLocked(stats network.PeerStats) bool {
	return !stats.LastHandshake.IsZero() && s.now().Sub(stats.LastHandshake) < ConnectedWindow
}

func (s *Service) serverViewLocked(server *store.Server) (*ServerView, error) {
	q := s.db.Q()
	view := &ServerView{
		ID: server.ID, Name: server.Name, Interface: server.Interface, Enabled: server.Enabled,
		PublicHost: server.PublicHost, ListenPort: server.ListenPort, PublicPort: server.PublicPort,
		Network: server.Network, Network6: server.Network6, Networks: server.Networks, DNS: server.DNS, MTU: server.MTU,
		Keepalive: server.Keepalive, AuthMode: server.AuthMode, SessionTimeout: server.SessionTimeout,
		LockEndpoint: server.LockEndpoint, DetectCopies: server.DetectCopies, BlockCopies: server.BlockCopies,
		Redirect: server.Redirect, Fallbacks: server.FallbackEndpoints, DeviceBinding: server.DeviceBinding,
		MachineID: server.MachineID, ClientToClient: server.ClientToClient, Reachable: server.ReachableServers,
		Routed: server.Routed, Inbound: server.Inbound, Routes: routeViews(s.routesOf(server)),
		CreatedAt: server.CreatedAt, UpdatedAt: server.UpdatedAt,
	}
	if key, err := wgtypes.ParseKey(server.PrivateKey); err == nil {
		view.PublicKey = key.PublicKey().String()
	}
	if tunnel, err := netip.ParsePrefix(server.Network); err == nil {
		view.Address = serverAddress(tunnel).String()
		if server.Gated() {
			view.LoginURL = "http://" + view.Address + ":" + strconv.Itoa(s.opts.LoginPort) + "/"
		}
	}
	if tunnel6 := tunnel6Of(server); tunnel6.IsValid() {
		view.Address6 = serverAddress(tunnel6).String()
	}
	peers, err := q.Peers(server.ID)
	if err != nil {
		return nil, err
	}
	view.Peers = len(peers)
	for _, peer := range peers {
		if peer.UserID == 0 {
			view.PeersWithoutUser++
		}
		if s.connectedLocked(peerStatsOf(s.stats, &peer)) {
			view.Connected++
		}
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if session.ServerID == server.ID {
			view.Sessions++
		}
	}
	return view, nil
}

func (s *Service) peerViewLocked(peer *store.Peer) (*PeerView, error) {
	views, err := s.peerViewsLocked([]store.Peer{*peer})
	if err != nil {
		return nil, err
	}
	return &views[0], nil
}

func (s *Service) peerViewsLocked(peers []store.Peer) ([]PeerView, error) {
	q := s.db.Q()
	users, err := q.Users()
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	for _, user := range users {
		names[user.ID] = user.Username
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return nil, err
	}
	byPeer := map[int64]store.Session{}
	for _, session := range sessions {
		byPeer[session.PeerID] = session
	}
	alerts, err := q.AlertCounts()
	if err != nil {
		return nil, err
	}
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	bound := map[int64]bool{}
	byID := map[int64]*store.Server{}
	for index, server := range servers {
		bound[server.ID] = server.DeviceBinding
		byID[server.ID] = &servers[index]
	}
	devices, err := q.Devices()
	if err != nil {
		return nil, err
	}
	now := s.now()
	views := make([]PeerView, 0, len(peers))
	for _, peer := range peers {
		stats := peerStatsOf(s.stats, &peer)
		view := PeerView{
			ID: peer.ID, ServerID: peer.ServerID, Name: peer.Name, Enabled: peer.Enabled, UserID: peer.UserID,
			Username: names[peer.UserID], Address: peer.Address, PublicKey: peer.PublicKey, RouteAll: peer.RouteAll,
			Blocked: peer.Blocked, Alerts: alerts[peer.ID],
			Connected: s.connectedLocked(stats), Received: stats.Received, Sent: stats.Sent,
			CreatedAt: peer.CreatedAt, UpdatedAt: peer.UpdatedAt,
		}
		if server, ok := byID[peer.ServerID]; ok {
			view.Address6 = peerAddress6(server, peer.Address)
		}
		if !stats.LastHandshake.IsZero() {
			view.LastHandshake = stats.LastHandshake.Unix()
		}
		if stats.Endpoint.IsValid() {
			view.Endpoint = stats.Endpoint.String()
		}
		if session, ok := byPeer[peer.ID]; ok {
			view.Session = sessionView(session)
		}
		if bound[peer.ServerID] {
			var device *store.Device
			if entry, ok := devices[peer.ID]; ok {
				device = &entry
			}
			view.Device = deviceView(device, now)
		}
		views = append(views, view)
	}
	return views, nil
}

func deviceView(device *store.Device, now time.Time) *DeviceView {
	view := &DeviceView{State: deviceState(device, now)}
	switch view.State {
	case DeviceWaiting:
		view.EnrollmentUntil = device.WindowUntil
	case DeviceEnrolled:
		view.Name, view.Kind, view.MachineID = device.Name, device.Kind, device.MachineID != ""
		view.EnrolledAt, view.LastUsedAt, view.LastFrom = device.EnrolledAt, device.LastUsedAt, device.LastFrom
		view.WireGuardKey = KeyOfConfiguration
		if device.WireGuardKey != "" {
			view.WireGuardKey, view.WireGuardKeyAt = KeyOfDevice, device.WireGuardKeyAt
		}
	}
	return view
}

func (s *Service) userViewLocked(user *store.User) (*UserView, error) {
	views, err := s.userViewsLocked([]store.User{*user})
	if err != nil {
		return nil, err
	}
	return &views[0], nil
}

func (s *Service) userViewsLocked(users []store.User) ([]UserView, error) {
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	serverNames := map[int64]string{}
	for _, server := range servers {
		serverNames[server.ID] = server.Name
	}
	peers, err := q.Peers(0)
	if err != nil {
		return nil, err
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return nil, err
	}
	views := make([]UserView, 0, len(users))
	for _, user := range users {
		view := UserView{
			ID: user.ID, Username: user.Username, FullName: user.FullName, Disabled: user.Disabled,
			TOTP: user.TOTPSecret != "", Peers: []string{}, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
		}
		for _, peer := range peers {
			if peer.UserID == user.ID {
				view.Peers = append(view.Peers, serverNames[peer.ServerID]+" / "+peer.Name)
			}
		}
		for _, session := range sessions {
			if session.UserID == user.ID {
				view.Sessions++
			}
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Service) Servers() ([]ServerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, err := s.db.Q().Servers()
	if err != nil {
		return nil, err
	}
	views := make([]ServerView, 0, len(servers))
	for index := range servers {
		view, err := s.serverViewLocked(&servers[index])
		if err != nil {
			return nil, err
		}
		views = append(views, *view)
	}
	return views, nil
}

func (s *Service) Server(id int64) (*ServerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, err := s.db.Q().Server(id)
	if err != nil {
		return nil, notFound(err)
	}
	return s.serverViewLocked(server)
}

func (s *Service) Peers(serverID int64) ([]PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Q().Server(serverID); err != nil {
		return nil, notFound(err)
	}
	peers, err := s.db.Q().Peers(serverID)
	if err != nil {
		return nil, err
	}
	return s.peerViewsLocked(peers)
}

func (s *Service) Users() ([]UserView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.db.Q().Users()
	if err != nil {
		return nil, err
	}
	return s.userViewsLocked(users)
}

// OpenSessions are the sessions of now for Activity: the latest login first, as in the other lists.
func (s *Service) OpenSessions() ([]SessionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessions, err := s.db.Q().OpenSessions()
	if err != nil {
		return nil, err
	}
	views := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		views = append(views, *sessionView(session))
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].StartedAt != views[j].StartedAt {
			return views[i].StartedAt > views[j].StartedAt
		}
		return views[i].ID > views[j].ID
	})
	return views, nil
}

// EndSession ends a session from the web UI.
func (s *Service) EndSession(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessions, err := s.db.Q().OpenSessions()
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.ID == id {
			s.endSessionLocked(session, EndByAdmin, true)
			s.changeLocked(by, store.Event{Kind: "session_ended", ServerName: session.ServerName, PeerName: session.PeerName,
				Username: session.Username})
			return nil
		}
	}
	return ErrNotFound
}

func (s *Service) History(limit int) ([]SessionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessions, err := s.db.Q().EndedSessions(limit)
	if err != nil {
		return nil, err
	}
	views := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		views = append(views, *sessionView(session))
	}
	return views, nil
}

func (s *Service) Events(limit int) ([]EventView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events, err := s.db.Q().Events(limit)
	if err != nil {
		return nil, err
	}
	views := make([]EventView, 0, len(events))
	for _, event := range events {
		views = append(views, eventView(event))
	}
	return views, nil
}

// Alerts returns the latest alerts of a peer, or of all the peers when peerID is 0.
func (s *Service) Alerts(peerID int64, limit int) ([]AlertView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	if peerID != 0 {
		if _, err := q.Peer(peerID); err != nil {
			return nil, notFound(err)
		}
	}
	alerts, err := q.Alerts(peerID, limit)
	if err != nil {
		return nil, err
	}
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	serverNames := map[int64]string{}
	for _, server := range servers {
		serverNames[server.ID] = server.Name
	}
	peers, err := q.Peers(0)
	if err != nil {
		return nil, err
	}
	byID := map[int64]store.Peer{}
	for _, peer := range peers {
		byID[peer.ID] = peer
	}
	views := make([]AlertView, 0, len(alerts))
	for _, alert := range alerts {
		peer := byID[alert.PeerID]
		views = append(views, AlertView{
			ID: alert.ID, PeerID: alert.PeerID, PeerName: peer.Name, ServerID: peer.ServerID,
			ServerName: serverNames[peer.ServerID], Blocked: peer.Blocked, At: alert.At, Kind: alert.Kind,
			Username: alert.Username, Addresses: alert.Addresses,
		})
	}
	return views, nil
}

func (s *Service) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	status := Status{ApplyError: s.applyError, LoginPort: s.opts.LoginPort, Version: s.opts.Version,
		HostChanges: s.hostChangesLocked()}
	servers, err := q.Servers()
	if err != nil {
		return status, err
	}
	status.Servers = len(servers)
	peers, err := q.Peers(0)
	if err != nil {
		return status, err
	}
	status.Peers = len(peers)
	for _, peer := range peers {
		if s.connectedLocked(peerStatsOf(s.stats, &peer)) {
			status.Connected++
		}
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return status, err
	}
	status.Sessions = len(sessions)
	return status, nil
}
