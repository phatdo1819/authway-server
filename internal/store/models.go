package store

import (
	"database/sql"
)

// The roles of the administrators of the web UI.
const (
	RoleAdmin    = "admin"    // everything, the administrators and the settings too
	RoleOperator = "operator" // the users, the peers and the sessions: not the servers, the administrators or the settings
	RoleViewer   = "viewer"   // sees everything but the private keys, changes nothing
)

type Admin struct {
	ID           int64
	Username     string
	FullName     string
	PasswordHash string
	Role         string
	// the secret of the authenticator app, "" when the administrator has none
	TOTPSecret string
	Disabled   bool
	// set when another administrator or the command line chose the password: changed at the next login
	MustChangePassword bool
	LastLoginAt        int64
	LastLoginFrom      string
	CreatedAt          int64
	UpdatedAt          int64
}

type User struct {
	ID           int64
	Username     string
	FullName     string
	PasswordHash string
	TOTPSecret   string
	Disabled     bool
	CreatedAt    int64
	UpdatedAt    int64
}

// AuthMode says what the peers of a server do before their traffic passes.
const (
	AuthKey         = "key"          // nothing: the WireGuard key is enough
	AuthPassword    = "password"     // the password of the user of the peer
	AuthPasswordOTP = "password_otp" // the password and a code of an authenticator app
)

type Server struct {
	ID         int64
	Name       string
	Interface  string
	Enabled    bool
	ListenPort int
	PublicHost string
	PublicPort int // 0: the listen port
	PrivateKey string
	Network    string
	// the IPv6 network of the tunnel, "" when it has none: its peers have the address of their IPv4 one in it
	Network6       string
	Networks       []string
	DNS            []string
	MTU            int // 0: the default of WireGuard
	Keepalive      int
	AuthMode       string
	SessionTimeout int // seconds
	// what a session does when its peer sends from another public IP than at login: LockStrict, LockRoaming, LockOff
	LockEndpoint string
	// watch the endpoints for two devices using the same key, and block the peer when it happens
	DetectCopies bool
	BlockCopies  bool
	// before the login, DNS and web requests of the peers lead to the login page
	Redirect bool
	// other host:port of this server, tried by Authway when the endpoint doesn't answer
	FallbackEndpoints []string
	// the peers log in only from the device enrolled for them, which signs every login; with MachineID it also
	// sends a hash of the hardware ID of its machine. Only with a login
	DeviceBinding bool
	MachineID     bool
	// the peers of the server reach each other, and the peers of the servers listed, by id: one way, the answers
	// pass back
	ClientToClient   bool
	ReachableServers []int64
	// the networks of the server see the addresses of the peers, not the one of the container: their router sends
	// the tunnel networks back through it. With Inbound, the networks also start connections to the peers
	Routed    bool
	Inbound   bool
	CreatedAt int64
	UpdatedAt int64
}

const (
	LockStrict  = "strict"  // the session pauses, and ends after a while, until the peer sends from its login IP
	LockRoaming = "roaming" // the session follows the peer to its new IP
	LockOff     = "off"     // the IP is ignored
)

// Gated tells whether the peers must log in.
func (s *Server) Gated() bool {
	return s.AuthMode == AuthPassword || s.AuthMode == AuthPasswordOTP
}

// EndpointPort is the port the peers send to: the one published by Docker can differ from the one inside.
func (s *Server) EndpointPort() int {
	if s.PublicPort != 0 {
		return s.PublicPort
	}
	return s.ListenPort
}

type Peer struct {
	ID           int64
	ServerID     int64
	Name         string
	Enabled      bool
	UserID       int64 // 0: none
	Address      string
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	RouteAll     bool
	// blocked after a copy of its configuration, until an administrator clears its alerts or gives it new keys
	Blocked   bool
	CreatedAt int64
	UpdatedAt int64
	// read only, from its device: the WireGuard public key the enrolled device gave the peer, and when; "" when the
	// peer connects with the key of its configuration file
	DeviceKey   string
	DeviceKeyAt int64
}

// Device is the device of a peer of a server with device binding: the one enrolled, or the enrollment that waits.
type Device struct {
	PeerID int64
	// a device can enroll until then; 0: closed
	WindowUntil int64
	// the public key of the device, DER SubjectPublicKeyInfo in base64; "": none enrolled
	Key  string
	Kind string
	Name string
	// the hash of the hardware ID of its machine, "" when the server didn't ask for it yet
	MachineID  string
	EnrolledAt int64
	LastUsedAt int64
	// the public IP of its latest login
	LastFrom string
	// the WireGuard public key the device gave its peer, "": the one of the configuration file
	WireGuardKey   string
	WireGuardKeyAt int64
}

// Enrolled tells whether a device is enrolled.
func (d *Device) Enrolled() bool {
	return d != nil && d.Key != ""
}

// Connection is a run of handshakes of a peer, from one public IP: WireGuard has no connections.
type Connection struct {
	ID         int64
	ServerID   int64
	PeerID     int64
	ServerName string
	PeerName   string
	Username   string
	Address    string
	Endpoint   string
	StartedAt  int64
	// the latest change of its counters
	LastSeen int64
	EndedAt  int64 // 0: still connected
	Received int64
	Sent     int64
	// the counters of WireGuard when the row started: they count from the time the interface came up
	RxStart int64
	TxStart int64
}

type Session struct {
	ID         int64
	ServerID   int64
	PeerID     int64
	UserID     int64
	ServerName string
	PeerName   string
	Username   string
	Address    string
	Endpoint   string
	StartedAt  int64
	ExpiresAt  int64
	EndedAt    int64 // 0: still open
	EndReason  string
	// when the session was paused, its peer sending from another public IP; 0: not paused
	PausedAt int64
}

// Alert is something an administrator should look at, on a peer: a copy of its configuration, a lockout.
type Alert struct {
	ID        int64
	PeerID    int64
	At        int64
	Kind      string
	Username  string
	Addresses []string
}

type Event struct {
	ID         int64
	At         int64
	Kind       string
	ServerName string
	PeerName   string
	Username   string
	Source     string
	Detail     string
	// the administrator who made the change, for the events of the web UI; the address is in Source
	Actor string
}

// Admins

const adminColumns = "id, username, full_name, password_hash, role, totp_secret, disabled, must_change_password, last_login_at, last_login_from, created_at, updated_at"

func scanAdmin(row interface{ Scan(...any) error }) (*Admin, error) {
	var a Admin
	var disabled, mustChange int
	err := row.Scan(&a.ID, &a.Username, &a.FullName, &a.PasswordHash, &a.Role, &a.TOTPSecret, &disabled, &mustChange,
		&a.LastLoginAt, &a.LastLoginFrom, &a.CreatedAt, &a.UpdatedAt)
	a.Disabled, a.MustChangePassword = disabled != 0, mustChange != 0
	return &a, err
}

func (t *Tx) CountAdmins() (int, error) {
	var count int
	err := t.q.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	return count, err
}

// CountActiveAdmins counts the administrators with the role admin who can log in: one always stays.
func (t *Tx) CountActiveAdmins() (int, error) {
	var count int
	err := t.q.QueryRow("SELECT COUNT(*) FROM admins WHERE role = ? AND disabled = 0", RoleAdmin).Scan(&count)
	return count, err
}

func (t *Tx) AdminByName(username string) (*Admin, error) {
	a, err := scanAdmin(t.q.QueryRow("SELECT "+adminColumns+" FROM admins WHERE username = ?", username))
	return a, notFound(err)
}

func (t *Tx) Admin(id int64) (*Admin, error) {
	a, err := scanAdmin(t.q.QueryRow("SELECT "+adminColumns+" FROM admins WHERE id = ?", id))
	return a, notFound(err)
}

// Admins returns the administrators, the oldest first.
func (t *Tx) Admins() ([]Admin, error) {
	rows, err := t.q.Query("SELECT " + adminColumns + " FROM admins ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *a)
	}
	return list, rows.Err()
}

func (t *Tx) CreateAdmin(a *Admin) error {
	if a.Role == "" {
		a.Role = RoleAdmin
	}
	if a.UpdatedAt == 0 {
		a.UpdatedAt = a.CreatedAt
	}
	// an id of 0 is chosen by SQLite; a restore gives the ones of the backup
	result, err := t.q.Exec(`INSERT INTO admins (id, username, full_name, password_hash, role, totp_secret, disabled,
		must_change_password, last_login_at, last_login_from, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullID(a.ID), a.Username, a.FullName, a.PasswordHash, a.Role, a.TOTPSecret, boolInt(a.Disabled),
		boolInt(a.MustChangePassword), a.LastLoginAt, a.LastLoginFrom, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return conflict(err)
	}
	a.ID, err = result.LastInsertId()
	return err
}

// UpdateAdmin saves the name, the role and the state of an administrator; the password and the authenticator have
// methods of their own.
func (t *Tx) UpdateAdmin(a *Admin) error {
	return changed(t.q.Exec("UPDATE admins SET full_name = ?, role = ?, disabled = ?, updated_at = ? WHERE id = ?",
		a.FullName, a.Role, boolInt(a.Disabled), a.UpdatedAt, a.ID))
}

// SetAdminPassword sets the password of an administrator, and whether it must be changed at the next login.
func (t *Tx) SetAdminPassword(id int64, hash string, mustChange bool, at int64) error {
	return changed(t.q.Exec("UPDATE admins SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?",
		hash, boolInt(mustChange), at, id))
}

// SetAdminTOTP sets the secret of the authenticator of an administrator, "" to remove it.
func (t *Tx) SetAdminTOTP(id int64, secret string, at int64) error {
	return changed(t.q.Exec("UPDATE admins SET totp_secret = ?, updated_at = ? WHERE id = ?", secret, at, id))
}

func (t *Tx) SetAdminLogin(id, at int64, from string) error {
	return changed(t.q.Exec("UPDATE admins SET last_login_at = ?, last_login_from = ? WHERE id = ?", at, from, id))
}

func (t *Tx) DeleteAdmin(id int64) error {
	return changed(t.q.Exec("DELETE FROM admins WHERE id = ?", id))
}

// Users

const userColumns = "id, username, full_name, password_hash, totp_secret, disabled, created_at, updated_at"

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var disabled int
	err := row.Scan(&u.ID, &u.Username, &u.FullName, &u.PasswordHash, &u.TOTPSecret, &disabled, &u.CreatedAt, &u.UpdatedAt)
	u.Disabled = disabled != 0
	return &u, err
}

func (t *Tx) Users() ([]User, error) {
	rows, err := t.q.Query("SELECT " + userColumns + " FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *u)
	}
	return list, rows.Err()
}

func (t *Tx) User(id int64) (*User, error) {
	u, err := scanUser(t.q.QueryRow("SELECT "+userColumns+" FROM users WHERE id = ?", id))
	return u, notFound(err)
}

func (t *Tx) UserByName(username string) (*User, error) {
	u, err := scanUser(t.q.QueryRow("SELECT "+userColumns+" FROM users WHERE username = ?", username))
	return u, notFound(err)
}

func (t *Tx) CreateUser(u *User) error {
	result, err := t.q.Exec("INSERT INTO users (id, username, full_name, password_hash, totp_secret, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		nullID(u.ID), u.Username, u.FullName, u.PasswordHash, u.TOTPSecret, boolInt(u.Disabled), u.CreatedAt, u.UpdatedAt)
	if err != nil {
		return conflict(err)
	}
	u.ID, err = result.LastInsertId()
	return err
}

func (t *Tx) UpdateUser(u *User) error {
	return changed(t.q.Exec("UPDATE users SET username = ?, full_name = ?, password_hash = ?, totp_secret = ?, disabled = ?, updated_at = ? WHERE id = ?",
		u.Username, u.FullName, u.PasswordHash, u.TOTPSecret, boolInt(u.Disabled), u.UpdatedAt, u.ID))
}

func (t *Tx) DeleteUser(id int64) error {
	return changed(t.q.Exec("DELETE FROM users WHERE id = ?", id))
}

// Servers

const serverColumns = "id, name, interface, enabled, listen_port, public_host, public_port, private_key, network, network6, networks, dns, mtu, keepalive, auth_mode, session_timeout, lock_endpoint, detect_copies, block_copies, redirect, fallback_endpoints, device_binding, machine_id, client_to_client, reachable_servers, routed, inbound, created_at, updated_at"

func scanServer(row interface{ Scan(...any) error }) (*Server, error) {
	var s Server
	var enabled, detect, block, redirect, binding, machineID, clientToClient, routed, inbound int
	var networks, dns, fallbacks, reachable string
	err := row.Scan(&s.ID, &s.Name, &s.Interface, &enabled, &s.ListenPort, &s.PublicHost, &s.PublicPort, &s.PrivateKey,
		&s.Network, &s.Network6, &networks, &dns, &s.MTU, &s.Keepalive, &s.AuthMode, &s.SessionTimeout, &s.LockEndpoint, &detect,
		&block, &redirect, &fallbacks, &binding, &machineID, &clientToClient, &reachable, &routed, &inbound, &s.CreatedAt,
		&s.UpdatedAt)
	s.Routed = routed != 0
	s.Inbound = inbound != 0
	s.Enabled = enabled != 0
	s.DetectCopies = detect != 0
	s.BlockCopies = block != 0
	s.Redirect = redirect != 0
	s.DeviceBinding = binding != 0
	s.MachineID = machineID != 0
	s.ClientToClient = clientToClient != 0
	s.Networks = fromJSON(networks)
	s.DNS = fromJSON(dns)
	s.FallbackEndpoints = fromJSON(fallbacks)
	s.ReachableServers = idsFromJSON(reachable)
	return &s, err
}

func (t *Tx) Servers() ([]Server, error) {
	rows, err := t.q.Query("SELECT " + serverColumns + " FROM servers ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *s)
	}
	return list, rows.Err()
}

func (t *Tx) Server(id int64) (*Server, error) {
	s, err := scanServer(t.q.QueryRow("SELECT "+serverColumns+" FROM servers WHERE id = ?", id))
	return s, notFound(err)
}

func (t *Tx) CreateServer(s *Server) error {
	result, err := t.q.Exec("INSERT INTO servers (id, name, interface, enabled, listen_port, public_host, public_port, private_key, network, network6, networks, dns, mtu, keepalive, auth_mode, session_timeout, lock_endpoint, detect_copies, block_copies, redirect, fallback_endpoints, device_binding, machine_id, client_to_client, reachable_servers, routed, inbound, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		nullID(s.ID), s.Name, s.Interface, boolInt(s.Enabled), s.ListenPort, s.PublicHost, s.PublicPort, s.PrivateKey, s.Network, s.Network6,
		toJSON(s.Networks), toJSON(s.DNS), s.MTU, s.Keepalive, s.AuthMode, s.SessionTimeout, s.LockEndpoint,
		boolInt(s.DetectCopies), boolInt(s.BlockCopies), boolInt(s.Redirect), toJSON(s.FallbackEndpoints),
		boolInt(s.DeviceBinding), boolInt(s.MachineID), boolInt(s.ClientToClient), idsToJSON(s.ReachableServers),
		boolInt(s.Routed), boolInt(s.Inbound), s.CreatedAt, s.UpdatedAt)
	if err != nil {
		return conflict(err)
	}
	s.ID, err = result.LastInsertId()
	return err
}

func (t *Tx) UpdateServer(s *Server) error {
	return changed(t.q.Exec("UPDATE servers SET name = ?, enabled = ?, listen_port = ?, public_host = ?, public_port = ?, private_key = ?, network = ?, network6 = ?, networks = ?, dns = ?, mtu = ?, keepalive = ?, auth_mode = ?, session_timeout = ?, lock_endpoint = ?, detect_copies = ?, block_copies = ?, redirect = ?, fallback_endpoints = ?, device_binding = ?, machine_id = ?, client_to_client = ?, reachable_servers = ?, routed = ?, inbound = ?, updated_at = ? WHERE id = ?",
		s.Name, boolInt(s.Enabled), s.ListenPort, s.PublicHost, s.PublicPort, s.PrivateKey, s.Network, s.Network6, toJSON(s.Networks),
		toJSON(s.DNS), s.MTU, s.Keepalive, s.AuthMode, s.SessionTimeout, s.LockEndpoint, boolInt(s.DetectCopies),
		boolInt(s.BlockCopies), boolInt(s.Redirect), toJSON(s.FallbackEndpoints), boolInt(s.DeviceBinding),
		boolInt(s.MachineID), boolInt(s.ClientToClient), idsToJSON(s.ReachableServers), boolInt(s.Routed),
		boolInt(s.Inbound), s.UpdatedAt, s.ID))
}

func (t *Tx) DeleteServer(id int64) error {
	return changed(t.q.Exec("DELETE FROM servers WHERE id = ?", id))
}

// Peers

// the key the device gave the peer comes from its device: a peer has one device at most
const peerColumns = "id, server_id, name, enabled, user_id, address, private_key, public_key, preshared_key, route_all, blocked, created_at, updated_at, " +
	"COALESCE((SELECT wireguard_key FROM devices WHERE devices.peer_id = peers.id), ''), " +
	"COALESCE((SELECT wireguard_key_at FROM devices WHERE devices.peer_id = peers.id), 0)"

func scanPeer(row interface{ Scan(...any) error }) (*Peer, error) {
	var p Peer
	var enabled, routeAll, blocked int
	var userID sql.NullInt64
	err := row.Scan(&p.ID, &p.ServerID, &p.Name, &enabled, &userID, &p.Address, &p.PrivateKey, &p.PublicKey,
		&p.PresharedKey, &routeAll, &blocked, &p.CreatedAt, &p.UpdatedAt, &p.DeviceKey, &p.DeviceKeyAt)
	p.Enabled = enabled != 0
	p.RouteAll = routeAll != 0
	p.Blocked = blocked != 0
	p.UserID = userID.Int64
	return &p, err
}

func (t *Tx) queryPeers(where string, args ...any) ([]Peer, error) {
	rows, err := t.q.Query("SELECT "+peerColumns+" FROM peers "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *p)
	}
	return list, rows.Err()
}

// Peers returns the peers of a server, or of all the servers when serverID is 0.
func (t *Tx) Peers(serverID int64) ([]Peer, error) {
	if serverID == 0 {
		return t.queryPeers("ORDER BY server_id, name")
	}
	return t.queryPeers("WHERE server_id = ? ORDER BY name", serverID)
}

func (t *Tx) PeersOfUser(userID int64) ([]Peer, error) {
	return t.queryPeers("WHERE user_id = ? ORDER BY server_id, name", userID)
}

func (t *Tx) Peer(id int64) (*Peer, error) {
	p, err := scanPeer(t.q.QueryRow("SELECT "+peerColumns+" FROM peers WHERE id = ?", id))
	return p, notFound(err)
}

func (t *Tx) CreatePeer(p *Peer) error {
	result, err := t.q.Exec("INSERT INTO peers (id, server_id, name, enabled, user_id, address, private_key, public_key, preshared_key, route_all, blocked, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		nullID(p.ID), p.ServerID, p.Name, boolInt(p.Enabled), nullID(p.UserID), p.Address, p.PrivateKey, p.PublicKey, p.PresharedKey,
		boolInt(p.RouteAll), boolInt(p.Blocked), p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return conflict(err)
	}
	p.ID, err = result.LastInsertId()
	return err
}

func (t *Tx) UpdatePeer(p *Peer) error {
	return changed(t.q.Exec("UPDATE peers SET name = ?, enabled = ?, user_id = ?, address = ?, private_key = ?, public_key = ?, preshared_key = ?, route_all = ?, blocked = ?, updated_at = ? WHERE id = ?",
		p.Name, boolInt(p.Enabled), nullID(p.UserID), p.Address, p.PrivateKey, p.PublicKey, p.PresharedKey,
		boolInt(p.RouteAll), boolInt(p.Blocked), p.UpdatedAt, p.ID))
}

func (t *Tx) DeletePeer(id int64) error {
	return changed(t.q.Exec("DELETE FROM peers WHERE id = ?", id))
}

// Sessions

const sessionColumns = "id, server_id, peer_id, user_id, server_name, peer_name, username, address, endpoint, started_at, expires_at, ended_at, end_reason, paused_at"

func (t *Tx) querySessions(query string, args ...any) ([]Session, error) {
	rows, err := t.q.Query("SELECT "+sessionColumns+" FROM sessions "+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.ServerID, &s.PeerID, &s.UserID, &s.ServerName, &s.PeerName, &s.Username,
			&s.Address, &s.Endpoint, &s.StartedAt, &s.ExpiresAt, &s.EndedAt, &s.EndReason, &s.PausedAt); err != nil {
			return nil, err
		}
		list = append(list, s)
	}
	return list, rows.Err()
}

// OpenSessions returns the sessions that haven't ended.
func (t *Tx) OpenSessions() ([]Session, error) {
	return t.querySessions("WHERE ended_at = 0 ORDER BY started_at")
}

// EndedSessions returns the latest sessions that ended, the newest first.
func (t *Tx) EndedSessions(limit int) ([]Session, error) {
	return t.querySessions("WHERE ended_at != 0 ORDER BY ended_at DESC LIMIT ?", limit)
}

func (t *Tx) CreateSession(s *Session) error {
	result, err := t.q.Exec("INSERT INTO sessions (server_id, peer_id, user_id, server_name, peer_name, username, address, endpoint, started_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		s.ServerID, s.PeerID, s.UserID, s.ServerName, s.PeerName, s.Username, s.Address, s.Endpoint, s.StartedAt, s.ExpiresAt)
	if err != nil {
		return err
	}
	s.ID, err = result.LastInsertId()
	return err
}

// RenewSession moves the end of an open session: the user logged in again, maybe from another public IP. A paused
// session goes on.
func (t *Tx) RenewSession(id, expiresAt int64, endpoint string) error {
	return changed(t.q.Exec("UPDATE sessions SET expires_at = ?, endpoint = ?, paused_at = 0 WHERE id = ? AND ended_at = 0", expiresAt, endpoint, id))
}

// PauseSession pauses an open session at a time, or resumes it with 0.
func (t *Tx) PauseSession(id, at int64) error {
	return changed(t.q.Exec("UPDATE sessions SET paused_at = ? WHERE id = ? AND ended_at = 0", at, id))
}

// SetSessionEndpoint follows a peer that roams to another public IP.
func (t *Tx) SetSessionEndpoint(id int64, endpoint string) error {
	return changed(t.q.Exec("UPDATE sessions SET endpoint = ? WHERE id = ? AND ended_at = 0", endpoint, id))
}

func (t *Tx) EndSession(id, at int64, reason string) error {
	return changed(t.q.Exec("UPDATE sessions SET ended_at = ?, end_reason = ? WHERE id = ? AND ended_at = 0", at, reason, id))
}

// EndOpenSessions ends every open session, for a reason: it returns how many.
func (t *Tx) EndOpenSessions(at int64, reason string) (int64, error) {
	result, err := t.q.Exec("UPDATE sessions SET ended_at = ?, end_reason = ? WHERE ended_at = 0", at, reason)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClearConfig deletes the configuration: the peers with their alerts and devices, the servers, the users and the
// administrators. The history of the sessions and of the connections and the events stay.
func (t *Tx) ClearConfig() error {
	for _, table := range []string{"alerts", "devices", "peers", "servers", "users", "admins"} {
		if _, err := t.q.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

// PruneSessions deletes the sessions that ended before a time, to keep the history small.
func (t *Tx) PruneSessions(before int64) error {
	_, err := t.q.Exec("DELETE FROM sessions WHERE ended_at != 0 AND ended_at < ?", before)
	return err
}

// Events

func (t *Tx) AddEvent(e *Event) error {
	_, err := t.q.Exec("INSERT INTO events (at, kind, server_name, peer_name, username, source, detail, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		e.At, e.Kind, e.ServerName, e.PeerName, e.Username, e.Source, e.Detail, e.Actor)
	return err
}

// Events returns the latest events, the newest first.
func (t *Tx) Events(limit int) ([]Event, error) {
	return t.queryEvents("ORDER BY at DESC, id DESC LIMIT ?", limit)
}

func (t *Tx) queryEvents(query string, args ...any) ([]Event, error) {
	rows, err := t.q.Query("SELECT id, at, kind, server_name, peer_name, username, source, detail, actor FROM events "+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.At, &e.Kind, &e.ServerName, &e.PeerName, &e.Username, &e.Source, &e.Detail, &e.Actor); err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

func (t *Tx) PruneEvents(before int64) error {
	_, err := t.q.Exec("DELETE FROM events WHERE at < ?", before)
	return err
}

// SetPeerBlocked blocks a peer, or unblocks it.
func (t *Tx) SetPeerBlocked(id int64, blocked bool, at int64) error {
	return changed(t.q.Exec("UPDATE peers SET blocked = ?, updated_at = ? WHERE id = ?", boolInt(blocked), at, id))
}

// Alerts

func (t *Tx) AddAlert(a *Alert) error {
	result, err := t.q.Exec("INSERT INTO alerts (peer_id, at, kind, username, addresses) VALUES (?, ?, ?, ?, ?)",
		a.PeerID, a.At, a.Kind, a.Username, toJSON(a.Addresses))
	if err != nil {
		return err
	}
	a.ID, err = result.LastInsertId()
	return err
}

func (t *Tx) queryAlerts(where string, args ...any) ([]Alert, error) {
	rows, err := t.q.Query("SELECT id, peer_id, at, kind, username, addresses FROM alerts "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Alert
	for rows.Next() {
		var a Alert
		var addresses string
		if err := rows.Scan(&a.ID, &a.PeerID, &a.At, &a.Kind, &a.Username, &addresses); err != nil {
			return nil, err
		}
		a.Addresses = fromJSON(addresses)
		list = append(list, a)
	}
	return list, rows.Err()
}

// Alerts returns the latest alerts of a peer, or of all the peers when peerID is 0, the newest first.
func (t *Tx) Alerts(peerID int64, limit int) ([]Alert, error) {
	if peerID == 0 {
		return t.queryAlerts("ORDER BY at DESC, id DESC LIMIT ?", limit)
	}
	return t.queryAlerts("WHERE peer_id = ? ORDER BY at DESC, id DESC LIMIT ?", peerID, limit)
}

// AlertCounts returns the number of alerts of each peer that has some.
func (t *Tx) AlertCounts() (map[int64]int, error) {
	rows, err := t.q.Query("SELECT peer_id, COUNT(*) FROM alerts GROUP BY peer_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[int64]int{}
	for rows.Next() {
		var peer int64
		var count int
		if err := rows.Scan(&peer, &count); err != nil {
			return nil, err
		}
		counts[peer] = count
	}
	return counts, rows.Err()
}

func (t *Tx) ClearAlerts(peerID int64) error {
	_, err := t.q.Exec("DELETE FROM alerts WHERE peer_id = ?", peerID)
	return err
}

func (t *Tx) PruneAlerts(before int64) error {
	_, err := t.q.Exec("DELETE FROM alerts WHERE at < ?", before)
	return err
}

// changed turns an update of no row into ErrNotFound
func changed(result sql.Result, err error) error {
	if err != nil {
		return conflict(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
