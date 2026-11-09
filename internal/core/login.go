package core

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

// The login API answers the browser page and Authway, through the tunnel, with the same JSON as the firewall login
// of NethSecurity (ns-wgauth), so Authway works with both. Each method returns the HTTP status and the JSON body.

type Answer struct {
	Status int
	Body   map[string]any
}

func fail(status int, code string) Answer {
	return Answer{Status: status, Body: map[string]any{"error": code}}
}

func isoTime(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// findPeerLocked returns the gated server and the peer of an address of the tunnels, IPv4 or IPv6. The page must be
// opened with an address of the server: a page of another site whose name resolves to it (DNS rebinding) gets
// nothing.
func (s *Service) findPeerLocked(address netip.Addr, host string) (*store.Server, *store.Peer, bool) {
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		s.log.Error("can't read the servers", "error", err)
		return nil, nil, false
	}
	server, peer4, ok := inTunnel(servers, address)
	if !ok || !peer4.IsValid() || !server.Enabled || !server.Gated() || !s.ownHost(server, host) {
		return nil, nil, false
	}
	peers, err := q.Peers(server.ID)
	if err != nil {
		return nil, nil, false
	}
	for i := range peers {
		if peers[i].Enabled && peers[i].Address == peer4.String() {
			return server, &peers[i], true
		}
	}
	return nil, nil, false
}

// ownHost tells whether the host a page was asked with is an address of the server in its tunnel, with the port of
// the login page or none: 10.8.0.1, 10.8.0.1:8181, [fd12:3456:789a:1::1]:8181. Never a name.
func (s *Service) ownHost(server *store.Server, host string) bool {
	text := host
	if name, port, err := net.SplitHostPort(host); err == nil {
		if port != strconv.Itoa(s.opts.LoginPort) {
			return false
		}
		text = name
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		text = host[1 : len(host)-1]
	} else if strings.Contains(host, ":") {
		// an IPv6 address without its brackets isn't a host
		return false
	}
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" {
		return false
	}
	if tunnel, err := netip.ParsePrefix(server.Network); err == nil && address == serverAddress(tunnel.Masked()) {
		return true
	}
	tunnel6 := tunnel6Of(server)
	return tunnel6.IsValid() && address == serverAddress(tunnel6)
}

func (s *Service) openSessionOfLocked(peerID int64) (*store.Session, bool) {
	sessions, err := s.db.Q().OpenSessions()
	if err != nil {
		return nil, false
	}
	for _, session := range sessions {
		if session.PeerID == peerID {
			return &session, true
		}
	}
	return nil, false
}

// freshStatsLocked reads WireGuard now: the request just came through the tunnel, so the endpoint of the peer is
// the public IP of the device that asks
func (s *Service) freshStatsLocked() {
	if stats, err := s.net.Stats(); err == nil {
		s.stats = stats
		s.statsAt = s.now()
	}
}

// LoginStatus is GET /api/status. With device binding, the app sends deviceKeyID, the ID of its device key for the
// peer, empty when it has none, nil from the browser or an older app: the status tells it whether it's the device
// enrolled, so another device steps back before its handshakes take the session of the enrolled one.
func (s *Service) LoginStatus(address netip.Addr, host string, deviceKeyID *string) Answer {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, peer, ok := s.findPeerLocked(address, host)
	if !ok {
		return fail(403, "forbidden")
	}
	s.freshStatsLocked()
	// at once: a session isn't shared with another device even for the seconds until the next check
	s.followLocked(s.stats, peer.ID)
	body := map[string]any{
		"authenticated": false,
		"otp_required":  server.AuthMode == store.AuthPasswordOTP,
		"server":        server.Name,
		"blocked":       peer.Blocked,
		"no_user":       peer.UserID == 0,
		"no_otp":        false,
	}
	if peer.UserID != 0 && server.AuthMode == store.AuthPasswordOTP {
		if user, err := s.db.Q().User(peer.UserID); err == nil {
			body["no_otp"] = user.TOTPSecret == ""
		}
	}
	if server.DeviceBinding {
		// the request just came through the tunnel: the endpoint is the public IP of the device that asks
		endpoint := endpointIP(peerStatsOf(s.stats, peer))
		body["device"] = s.deviceStatusLocked(server, peer, address, deviceKeyID, endpoint, s.now())
	}
	// a paused session doesn't count: the device that asks isn't the one that logged in, or moved and logs in again
	if session, ok := s.openSessionOfLocked(peer.ID); ok && session.PausedAt == 0 && s.now().Unix() < session.ExpiresAt {
		body["authenticated"] = true
		body["user"] = session.Username
		body["expires"] = isoTime(session.ExpiresAt)
	}
	return Answer{Status: 200, Body: body}
}

// LoginRequest is the body of POST /api/login. Device is the proof of the device, signed by Authway, for the servers
// with device binding.
type LoginRequest struct {
	Username string       `json:"username"`
	Password string       `json:"password"`
	OTP      string       `json:"otp"`
	Device   *DeviceProof `json:"device"`
}

// Login is POST /api/login.
func (s *Service) Login(address netip.Addr, host string, request LoginRequest) Answer {
	s.mu.Lock()
	server, peer, ok := s.findPeerLocked(address, host)
	if !ok {
		s.mu.Unlock()
		return fail(403, "forbidden")
	}
	if peer.Blocked {
		s.mu.Unlock()
		return fail(403, "blocked")
	}
	if peer.UserID == 0 {
		s.mu.Unlock()
		return fail(403, "no_user")
	}
	user, err := s.db.Q().User(peer.UserID)
	if err != nil {
		s.mu.Unlock()
		return fail(403, "no_user")
	}
	withOTP := server.AuthMode == store.AuthPasswordOTP
	if withOTP && user.TOTPSecret == "" {
		s.mu.Unlock()
		return fail(403, "no_otp")
	}
	s.freshStatsLocked()
	endpoint := endpointIP(peerStatsOf(s.stats, peer))
	now := s.now()
	if until, locked := s.failures.lockedUntil(peer.ID, endpoint, now); locked {
		s.mu.Unlock()
		retry := int(until.Sub(now).Seconds())
		if retry < 1 {
			retry = 1
		}
		return Answer{Status: 429, Body: map[string]any{"error": "too_many_attempts", "retry_after": retry}}
	}
	binding := server.DeviceBinding
	var enrolling *store.Device
	if binding {
		// before the password: from another device, the password is never checked
		code, device := s.checkDeviceLocked(server, peer, address, request, now)
		switch code {
		case "":
			enrolling = device
		case "device_mismatch":
			s.reportMismatchLocked(server, peer, endpoint, now, "login from another device")
			s.loginFailedLocked(server, peer, user.Username, address, endpoint, "another device", now)
			s.mu.Unlock()
			return fail(401, code)
		case "challenge_expired":
			s.mu.Unlock()
			return fail(401, code)
		default:
			if code == "device_not_enrolled" {
				s.log.Warn("login refused: the peer has no device and its enrollment is closed", "server", server.Name,
					"peer", peer.Name, "user", user.Username)
			}
			s.mu.Unlock()
			return fail(403, code)
		}
	}
	serverID, peerID, hash, generation := server.ID, peer.ID, user.PasswordHash, s.generation
	s.mu.Unlock()

	// the password check takes a while, out of the lock; the username is the one of the user of the peer
	valid := false
	if strings.EqualFold(strings.TrimSpace(request.Username), user.Username) && !user.Disabled &&
		request.Password != "" && len(request.Password) <= MaxPassword {
		valid = secret.VerifyPassword(request.Password, hash)
	} else {
		secret.SpendCheck(request.Password)
	}
	var counter uint64
	if valid && withOTP {
		counter, valid = totp.Verify(user.TOTPSecret, request.OTP, now)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// the configuration could have changed during the check
	server, peer, ok = s.findPeerLocked(address, host)
	if !ok || server.ID != serverID || peer.ID != peerID || (server.AuthMode == store.AuthPasswordOTP) != withOTP ||
		server.DeviceBinding != binding || s.generation != generation {
		// another server, peer, a login that now asks for a code or a device, or a restored configuration: the
		// checks done no longer apply
		return fail(403, "forbidden")
	}
	if peer.Blocked {
		return fail(403, "blocked")
	}
	current, err := s.db.Q().User(peer.UserID)
	if err != nil || current.ID != user.ID || current.PasswordHash != hash || current.Disabled {
		valid = false
	}
	if valid && withOTP && s.codeUsedLocked(user.ID, counter, now) {
		valid = false
	}
	if !valid {
		// the user of the peer, never what was typed: it can be a password, and the events are read by every role
		detail := ""
		if !strings.EqualFold(strings.TrimSpace(request.Username), user.Username) {
			detail = "another username"
		}
		s.loginFailedLocked(server, peer, user.Username, address, endpoint, detail, now)
		return fail(401, "invalid_credentials")
	}
	if binding && !s.recordDeviceLoginLocked(server, peer, user.Username, enrolling, request.Device, endpoint, now) {
		// another device enrolled meanwhile, the window closed, or an administrator revoked the device
		s.loginFailedLocked(server, peer, user.Username, address, endpoint, "another device", now)
		return fail(401, "device_mismatch")
	}
	s.failures.success(peer.ID, endpoint)
	expires, err := s.openSessionLocked(server, peer, user, endpoint)
	if err != nil {
		s.log.Error("can't open the gate", "peer", peer.Name, "error", err)
		return fail(500, "internal_error")
	}
	if addresses := addressesOf(server, peer.Address); len(addresses) > 0 {
		if err := s.net.FlushRedirected(addresses...); err != nil {
			s.log.Warn("can't forget the redirected connections of a peer", "peer", peer.Name, "error", err)
		}
	}
	s.log.Info("logged in", "user", user.Username, "server", server.Name, "peer", peer.Name, "address", address, "from", endpoint)
	return Answer{Status: 200, Body: map[string]any{"result": "success", "user": user.Username, "expires": isoTime(expires)}}
}

// openSessionLocked opens the gate for a peer, or starts its session again: a login from another public IP moves
// the lock of the session there, and a paused session goes on.
func (s *Service) openSessionLocked(server *store.Server, peer *store.Peer, user *store.User, endpoint string) (int64, error) {
	now := s.now().Unix()
	expires := now + int64(server.SessionTimeout)
	q := s.db.Q()
	if session, ok := s.openSessionOfLocked(peer.ID); ok {
		if err := q.RenewSession(session.ID, expires, endpoint); err != nil {
			return 0, err
		}
	} else {
		session := &store.Session{
			ServerID: server.ID, PeerID: peer.ID, UserID: user.ID,
			ServerName: server.Name, PeerName: peer.Name, Username: user.Username,
			Address: peer.Address, Endpoint: endpoint, StartedAt: now, ExpiresAt: expires,
		}
		if err := q.CreateSession(session); err != nil {
			return 0, err
		}
	}
	addresses := addressesOf(server, peer.Address)
	if len(addresses) == 0 {
		return 0, fmt.Errorf("the address of the peer %s isn't valid", peer.Name)
	}
	// both addresses at once: the gate opens for IPv4 and IPv6 together
	if err := s.net.AddSession(server.Interface, addresses...); err != nil {
		// the rule of the peer alone failed: the whole configuration has the session
		s.applyLocked()
		if s.applyError != "" {
			if session, ok := s.openSessionOfLocked(peer.ID); ok {
				q.EndSession(session.ID, now, EndServerChanged)
			}
			return 0, err
		}
	}
	return expires, nil
}

// Logout is POST /api/logout.
func (s *Service) Logout(address netip.Addr, host string) Answer {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, peer, ok := s.findPeerLocked(address, host)
	if !ok {
		return fail(403, "forbidden")
	}
	if session, ok := s.openSessionOfLocked(peer.ID); ok {
		s.endSessionLocked(*session, EndLogout, true)
	}
	return Answer{Status: 200, Body: map[string]any{"result": "success"}}
}

// loginFailedLocked counts a failed login of a peer from its public IP, and locks the IP out after too many.
func (s *Service) loginFailedLocked(server *store.Server, peer *store.Peer, username string, address netip.Addr,
	endpoint, detail string, now time.Time) {
	s.log.Warn("login failed", "user", username, "server", server.Name, "peer", peer.Name, "address", address,
		"from", endpoint, "detail", detail)
	s.eventLocked(store.Event{Kind: "login_failed", ServerName: server.Name, PeerName: peer.Name, Username: username,
		Source: endpoint, Detail: detail})
	if locked := s.failures.add(peer.ID, endpoint, now); locked != nil {
		s.lockoutLocked(server, peer, locked)
	}
}

// codeUsedLocked tells whether an authenticator code was already used, and marks it used
func (s *Service) codeUsedLocked(userID int64, counter uint64, now time.Time) bool {
	codes := s.usedCodes[userID]
	if codes == nil {
		codes = map[uint64]time.Time{}
		s.usedCodes[userID] = codes
	}
	if _, used := codes[counter]; used {
		return true
	}
	codes[counter] = now
	return false
}

// DevHost is the host the login page of a peer address is opened with: for the fake network only, where the page is
// opened from this computer.
func (s *Service) DevHost(address netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, err := s.db.Q().Servers()
	if err != nil {
		return ""
	}
	for _, server := range servers {
		if tunnel, err := netip.ParsePrefix(server.Network); err == nil && tunnel.Contains(address) {
			return serverAddress(tunnel).String()
		}
	}
	return ""
}
