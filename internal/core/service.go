// Package core is the logic of Authway Server: the configuration, its checks, the logins and the sessions.
//
// Every change is applied at once: there is no saved configuration waiting to be applied, so what the gate does is
// always what the database says.
package core

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/hostroute"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

const (
	// a session ends after this long without a handshake: WireGuard makes a new one every 2 minutes while packets
	// flow, and the keepalive of the peers keeps them flowing
	IdleTimeout = 5 * time.Minute
	// WireGuard counts a peer as connected while its last handshake is younger than this
	ConnectedWindow = 3 * time.Minute
	// failed logins: after MaxFailures in LockoutTime from the same public IP, that IP waits LockoutTime. A peer
	// failing PeerFailureFactor times more from any IPs is locked out from all of them, but the IP of its latest
	// login: many IPs don't multiply the attempts
	MaxFailures       = 5
	LockoutTime       = 15 * time.Minute
	PeerFailureFactor = 4
	// two devices using the same key: the endpoint of the peer changes CopyChanges times in CopyWindow, going back
	// to an IP it already had. A device that moves goes only to new IPs
	CopyWindow  = 5 * time.Minute
	CopyChanges = 3
	// while both devices stay on, the copy is seen again and again: one alert an hour is enough
	CopyReportInterval = time.Hour
	// with the strict lock, a session paused this long, its peer sending from another IP than at login, ends: the
	// device that logged in isn't coming back
	PauseLimit = 5 * time.Minute
	// how long the ended sessions, the connections, the events and the alerts stay in the history, by default: a
	// setting, from a day to ten years
	DefaultHistoryDays = 90
	MaxHistoryDays     = 3650
)

// the reasons a session ends, kept in the history
const (
	EndLogout        = "logout"
	EndExpired       = "expired"
	EndIdle          = "idle"
	EndByAdmin       = "ended_by_admin"
	EndPeerChanged   = "peer_changed"
	EndUserChanged   = "user_changed"
	EndServerChanged = "server_changed"
	// the peer sent from another public IP than at login for PauseLimit
	EndEndpointChanged = "endpoint_changed"
	EndCopySuspected   = "copy_suspected"
	EndBlocked         = "blocked"
	// a backup replaced the configuration
	EndRestored = "restored"
	// an administrator revoked the device of the peer or allowed a new one
	EndDeviceChanged = "device_changed"
)

var ErrNotFound = errors.New("not_found")

// ValidationError tells which fields are wrong, with a code for each: required, invalid, taken, in_use...
type ValidationError struct {
	Fields map[string]string
	// what's wrong, in words, when a code isn't enough: the content of a backup
	Detail string
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for field, code := range e.Fields {
		parts = append(parts, field+": "+code)
	}
	sort.Strings(parts)
	text := "invalid: " + strings.Join(parts, ", ")
	if e.Detail != "" {
		text += " (" + e.Detail + ")"
	}
	return text
}

type checks struct {
	fields map[string]string
}

func (c *checks) fail(field, code string) {
	if c.fields == nil {
		c.fields = map[string]string{}
	}
	if _, ok := c.fields[field]; !ok {
		c.fields[field] = code
	}
}

func (c *checks) err() error {
	if len(c.fields) == 0 {
		return nil
	}
	return &ValidationError{Fields: c.fields}
}

type Options struct {
	// the TCP port of the login page on the address of each server
	LoginPort int
	// where the web requests and the DNS queries of the peers that aren't logged in are redirected
	RedirectPort int
	DNSPort      int
	// the public name or address of this server, the default for new WireGuard servers
	PublicHost string
	// the version of Authway Server, written in the backups
	Version string
	Log     *slog.Logger
	// the resources of the host and the latest lines of the log, for the System page: nil, no page
	System *system.Monitor
	// the folder shared with the helper of the Docker host, for the routed servers on a Docker bridge: "", no helper
	HostRoutes string
	Now        func() time.Time
	// After runs f once d has passed, time.AfterFunc by default: the tests run it at once
	After func(d time.Duration, f func())
}

type Service struct {
	mu      sync.Mutex
	db      *store.Store
	net     network.Network
	log     *slog.Logger
	now     func() time.Time
	opts    Options
	started time.Time

	applyError string
	stats      map[wgtypes.Key]network.PeerStats
	statsAt    time.Time
	// why the latest reading of the tunnels failed, for the System page
	statsError string
	pruned     time.Time
	// the latest pass of Tick, for the health check
	ticked time.Time

	failures *loginFailures
	// the endpoints of the peers watched for copies, by peer
	copies map[int64]*copyTrack
	// the periods of the authenticator codes already used, by user: a code works only once
	usedCodes map[int64]map[uint64]time.Time
	// the same for the administrators, and the authenticators they are setting up
	usedAdminCodes map[int64]map[uint64]time.Time
	pendingTOTP    map[int64]pendingSecret
	// counts the restores: a login checked before one doesn't open a session after it
	generation uint64
	// the challenges given to the devices, and the latest alert of each peer for another device
	challenges challenges
	mismatches map[int64]time.Time
	after      func(time.Duration, func())
	// the connection history: the counters of each peer at the latest pass, and when it was
	counters map[int64]peerCounters
	recorded time.Time
	// the helper of the Docker host: its report, and the latest routes asked of it
	hostReader     *hostroute.Reader
	hostWanted     *hostroute.Wanted
	hostWriteError string
	// the addresses of the Docker host for the routers, by tunnel network: written with mu held, read without it
	// by the System page, so hostMu guards them too. Nil until read from the database
	hostMu        sync.Mutex
	hostAddresses map[string]hostAddress
}

// New ends the sessions that can't go on and applies the configuration.
func New(db *store.Store, net network.Network, opts Options) (*Service, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LoginPort == 0 {
		opts.LoginPort = 8181
	}
	if opts.RedirectPort == 0 {
		opts.RedirectPort = 8180
	}
	if opts.DNSPort == 0 {
		opts.DNSPort = 8153
	}
	if opts.After == nil {
		opts.After = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	}
	s := &Service{
		db:             db,
		net:            net,
		log:            opts.Log,
		now:            opts.Now,
		opts:           opts,
		started:        opts.Now(),
		stats:          map[wgtypes.Key]network.PeerStats{},
		failures:       newLoginFailures(),
		copies:         map[int64]*copyTrack{},
		usedCodes:      map[int64]map[uint64]time.Time{},
		usedAdminCodes: map[int64]map[uint64]time.Time{},
		pendingTOTP:    map[int64]pendingSecret{},
		challenges:     challenges{},
		mismatches:     map[int64]time.Time{},
		after:          opts.After,
		counters:       map[int64]peerCounters{},
	}
	if opts.HostRoutes != "" {
		s.hostReader = hostroute.NewReader(opts.HostRoutes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkSessionsLocked(EndServerChanged); err != nil {
		return nil, err
	}
	// the interfaces are new: their counters start again, the connections of before ended
	if err := db.Q().EndOpenConnections(); err != nil {
		return nil, err
	}
	s.applyLocked()
	return s, nil
}

// LoginPort is the port of the login page.
func (s *Service) LoginPort() int {
	return s.opts.LoginPort
}

// applyLocked puts the configuration of the database on the system. A failure is kept for the web UI: the rest of
// the configuration still works, and the next change tries again.
func (s *Service) applyLocked() {
	s.syncDevicesLocked()
	defer s.syncHostRoutesLocked()
	state, err := s.stateLocked()
	if err == nil {
		err = s.net.Apply(state)
	}
	if err != nil {
		if s.applyError != err.Error() {
			s.log.Error("can't apply the configuration", "error", err)
		}
		s.applyError = err.Error()
		return
	}
	if s.applyError != "" {
		s.log.Info("the configuration is applied again")
	}
	s.applyError = ""
}

func (s *Service) stateLocked() (network.State, error) {
	q := s.db.Q()
	state := network.State{LoginPort: s.opts.LoginPort, RedirectPort: s.opts.RedirectPort, DNSPort: s.opts.DNSPort}
	servers, err := q.Servers()
	if err != nil {
		return state, err
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		return state, err
	}
	interfaces := map[int64]string{}
	for _, server := range servers {
		if server.Enabled {
			interfaces[server.ID] = server.Interface
		}
	}
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		key, err := wgtypes.ParseKey(server.PrivateKey)
		if err != nil {
			return state, fmt.Errorf("server %s: %w", server.Name, err)
		}
		tunnel, err := netip.ParsePrefix(server.Network)
		if err != nil {
			return state, fmt.Errorf("server %s: %w", server.Name, err)
		}
		entry := network.Server{
			Interface:      server.Interface,
			ListenPort:     server.ListenPort,
			PrivateKey:     key,
			Address:        netip.PrefixFrom(serverAddress(tunnel), tunnel.Bits()),
			MTU:            server.MTU,
			Gated:          server.Gated(),
			Redirect:       server.Gated() && server.Redirect,
			ClientToClient: server.ClientToClient,
			Routed:         server.Routed,
			Inbound:        server.Routed && server.Inbound,
		}
		tunnel6 := tunnel6Of(&server)
		if tunnel6.IsValid() {
			entry.Address6 = netip.PrefixFrom(serverAddress(tunnel6), tunnel6.Bits())
		}
		// a disabled or deleted target has no interface: nothing to reach
		for _, id := range server.ReachableServers {
			if name, ok := interfaces[id]; ok && id != server.ID {
				entry.Reaches = append(entry.Reaches, name)
			}
		}
		for _, text := range server.Networks {
			if prefix, err := netip.ParsePrefix(text); err == nil {
				entry.Networks = append(entry.Networks, prefix)
			}
		}
		peers, err := q.Peers(server.ID)
		if err != nil {
			return state, err
		}
		for _, peer := range peers {
			if !peer.Enabled {
				continue
			}
			// once its device gave it a key of its own, only that key connects: not the configuration file
			key := peer.PublicKey
			if server.DeviceBinding && peer.DeviceKey != "" {
				key = peer.DeviceKey
			}
			public, err1 := wgtypes.ParseKey(key)
			preshared, err2 := wgtypes.ParseKey(peer.PresharedKey)
			address, err3 := netip.ParseAddr(peer.Address)
			if err := errors.Join(err1, err2, err3); err != nil {
				return state, fmt.Errorf("peer %s of %s: %w", peer.Name, server.Name, err)
			}
			// invalid without an IPv6 network
			other, _ := address6(tunnel.Masked(), tunnel6, address)
			entry.Peers = append(entry.Peers, network.Peer{
				PublicKey: public, PresharedKey: preshared, Address: address, Address6: other, RouteAll: peer.RouteAll,
			})
		}
		for _, session := range sessions {
			// a paused session keeps its peer out until it resumes
			if session.ServerID == server.ID && session.PausedAt == 0 {
				entry.Sessions = append(entry.Sessions, addressesOf(&server, session.Address)...)
			}
		}
		state.Servers = append(state.Servers, entry)
	}
	return state, nil
}

// checkSessionsLocked ends the open sessions that no longer match the configuration: the server, the peer or the
// user changed or are gone. It doesn't apply: the callers do.
func (s *Service) checkSessionsLocked(reason string) error {
	q := s.db.Q()
	sessions, err := q.OpenSessions()
	if err != nil {
		return err
	}
	now := s.now()
	for _, session := range sessions {
		why := ""
		server, err := q.Server(session.ServerID)
		peer, err2 := q.Peer(session.PeerID)
		user, err3 := q.User(session.UserID)
		switch {
		case now.Unix() >= session.ExpiresAt:
			why = EndExpired
		case err != nil || !server.Enabled || !server.Gated():
			why = EndServerChanged
		case err2 != nil || !peer.Enabled || peer.ServerID != server.ID || peer.Address != session.Address || peer.UserID != session.UserID:
			why = EndPeerChanged
		case peer.Blocked:
			why = EndBlocked
		case err3 != nil || user.Disabled:
			why = EndUserChanged
		}
		if why != "" {
			if reason != "" && why != EndExpired {
				why = reason
			}
			s.endSessionLocked(session, why, false)
		}
	}
	return nil
}

// endSessionLocked closes a session in the database and in the gate. When the gate can't drop the peer alone,
// applyOnError applies the whole configuration; the callers that apply it next anyway pass false.
func (s *Service) endSessionLocked(session store.Session, reason string, applyOnError bool) {
	if err := s.db.Q().EndSession(session.ID, s.now().Unix(), reason); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("can't end a session", "user", session.Username, "error", err)
	}
	s.log.Info("session ended", "user", session.Username, "server", session.ServerName, "peer", session.PeerName,
		"address", session.Address, "reason", reason)
	server, err := s.db.Q().Server(session.ServerID)
	if err != nil {
		// a server deleted: the next apply drops its whole set
		return
	}
	addresses := addressesOf(server, session.Address)
	if len(addresses) == 0 {
		return
	}
	if err := s.net.RemoveSession(server.Interface, addresses...); err != nil {
		s.log.Error("can't close the gate of a peer, applying the whole configuration", "address", session.Address, "error", err)
		if applyOnError {
			s.applyLocked()
		}
	}
}

// endSessionsLocked ends the open sessions that match, and says how many
func (s *Service) endSessionsLocked(match func(store.Session) bool, reason string) int {
	sessions, err := s.db.Q().OpenSessions()
	if err != nil {
		s.log.Error("can't read the sessions", "error", err)
		return 0
	}
	ended := 0
	for _, session := range sessions {
		if match(session) {
			s.endSessionLocked(session, reason, true)
			ended++
		}
	}
	return ended
}

func (s *Service) eventLocked(event store.Event) {
	event.At = s.now().Unix()
	if err := s.db.Q().AddEvent(&event); err != nil {
		s.log.Error("can't save an event", "kind", event.Kind, "error", err)
	}
}

// serverAddress is the address of the server in its tunnel network: the first one.
func serverAddress(tunnel netip.Prefix) netip.Addr {
	return tunnel.Masked().Addr().Next()
}

// lastAddress is the broadcast address of an IPv4 network.
func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	value |= uint32(1)<<(32-prefix.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// peerAddress tells whether an address can go to a peer of the network: not the network, the broadcast or the
// address of the server.
func peerAddress(tunnel netip.Prefix, address netip.Addr) bool {
	tunnel = tunnel.Masked()
	return address.Is4() && tunnel.Contains(address) && address != tunnel.Addr() && address != lastAddress(tunnel) &&
		address != serverAddress(tunnel)
}
