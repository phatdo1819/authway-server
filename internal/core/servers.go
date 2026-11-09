package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/peerconf"
	"github.com/phatdo1819/authway-server/internal/store"
)

const (
	FirstPort        = 51820
	DefaultKeepalive = 25
	DefaultTimeout   = 8 * 3600
	MinTimeout       = 15 * 60
	MaxTimeout       = 7 * 24 * 3600
	MaxNetworks      = 32
	MaxDNS           = 4
	maxServers       = 100
)

var (
	serverNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$`)
	hostLabel         = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// ServerInput is what the web UI sends to add or edit a server.
type ServerInput struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	PublicHost string `json:"public_host"`
	ListenPort int    `json:"listen_port"`
	PublicPort int    `json:"public_port"`
	Network    string `json:"network"`
	// "" for IPv4 only
	Network6       string   `json:"network6"`
	Networks       []string `json:"networks"`
	DNS            []string `json:"dns"`
	MTU            int      `json:"mtu"`
	Keepalive      int      `json:"keepalive"`
	AuthMode       string   `json:"auth_mode"`
	SessionTimeout int      `json:"session_timeout"`
	// "" counts as strict
	LockEndpoint      string   `json:"lock_endpoint"`
	DetectCopies      bool     `json:"detect_copies"`
	BlockCopies       bool     `json:"block_copies"`
	Redirect          bool     `json:"redirect"`
	FallbackEndpoints []string `json:"fallback_endpoints"`
	// only with a login: the peers log in from their enrolled device, and with MachineID from its machine
	DeviceBinding bool `json:"device_binding"`
	MachineID     bool `json:"machine_id"`
	// the peers reach each other, and start connections to the peers of the servers listed, by id
	ClientToClient   bool    `json:"client_to_client"`
	ReachableServers []int64 `json:"reachable_servers"`
	// the networks see the addresses of the peers, not the one of the container; with Inbound they also start
	// connections to the peers
	Routed  bool `json:"routed"`
	Inbound bool `json:"inbound"`
}

const MaxFallbacks = 4

// ServerSuggestion is what the web UI proposes for a server: free values. IPv6Off says why the tunnels can't
// carry IPv6, and then Network6 is empty.
type ServerSuggestion struct {
	ServerInput
	IPv6Off string `json:"ipv6_off,omitempty"`
}

// ServerDefaults proposes the values of a new server, or with forID those an existing one can take: its own IPv4
// network, and an IPv6 network for it.
func (s *Service) ServerDefaults(forID int64) (ServerSuggestion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, err := s.db.Q().Servers()
	if err != nil {
		return ServerSuggestion{}, err
	}
	var own *store.Server
	if forID != 0 {
		for index := range servers {
			if servers[index].ID == forID {
				own = &servers[index]
			}
		}
		if own == nil {
			return ServerSuggestion{}, ErrNotFound
		}
	}
	host, err := s.publicHostLocked()
	if err != nil {
		return ServerSuggestion{}, err
	}
	input := ServerInput{
		Enabled:           true,
		PublicHost:        host,
		ListenPort:        FirstPort,
		Networks:          []string{},
		DNS:               []string{},
		Keepalive:         DefaultKeepalive,
		AuthMode:          store.AuthPassword,
		SessionTimeout:    DefaultTimeout,
		LockEndpoint:      store.LockStrict,
		DetectCopies:      true,
		Redirect:          true,
		FallbackEndpoints: []string{},
		ReachableServers:  []int64{},
	}
	usedPorts := map[int]bool{}
	var tunnels, tunnels6 []netip.Prefix
	for index, server := range servers {
		if own != nil && server.ID == own.ID {
			continue
		}
		usedPorts[server.ListenPort] = true
		if prefix, err := netip.ParsePrefix(server.Network); err == nil {
			tunnels = append(tunnels, prefix)
		}
		if prefix := tunnel6Of(&servers[index]); prefix.IsValid() {
			tunnels6 = append(tunnels6, prefix)
		}
	}
	for usedPorts[input.ListenPort] {
		input.ListenPort++
	}
	if own != nil {
		input.Network = own.Network
	} else {
		for third := 0; third < 256; third++ {
			candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 8, byte(third), 0}), 24)
			if !overlapsAny(candidate, tunnels) {
				input.Network = candidate.String()
				break
			}
		}
	}
	defaults := ServerSuggestion{ServerInput: input}
	if err := s.net.IPv6(); err != nil {
		defaults.IPv6Off = err.Error()
		return defaults, nil
	}
	ula, err := s.ula48Locked(servers)
	if err != nil {
		return ServerSuggestion{}, err
	}
	tunnel, _ := netip.ParsePrefix(input.Network)
	if suggestion := suggestNetwork6(ula, tunnel, tunnels6); suggestion.IsValid() {
		defaults.Network6 = suggestion.String()
	}
	return defaults, nil
}

func (s *Service) CreateServer(by Actor, input ServerInput) (*ServerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	if len(servers) >= maxServers {
		return nil, &ValidationError{Fields: map[string]string{"name": "too_many"}}
	}
	server := &store.Server{}
	if err := s.checkServer(input, server, servers); err != nil {
		return nil, err
	}
	if err := s.checkIPv6Locked(server, ""); err != nil {
		return nil, err
	}
	server.Interface = freeInterface(servers)
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	server.PrivateKey = key.String()
	now := s.now().Unix()
	server.CreatedAt, server.UpdatedAt = now, now
	if err := q.CreateServer(server); err != nil {
		return nil, takenOr(err, "name")
	}
	s.log.Info("server added", "name", server.Name, "interface", server.Interface)
	networks := server.Network
	if server.Network6 != "" {
		networks += " and " + server.Network6
	}
	s.changeLocked(by, store.Event{Kind: "server_added", ServerName: server.Name, Detail: fmt.Sprintf("%s, UDP port %d, %s, login: %s",
		server.Interface, server.ListenPort, networks, authModeNames[server.AuthMode])})
	s.applyLocked()
	return s.serverViewLocked(server)
}

func (s *Service) UpdateServer(by Actor, id int64, input ServerInput) (*ServerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	server, err := q.Server(id)
	if err != nil {
		return nil, notFound(err)
	}
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	before := *server
	if err := s.checkServer(input, server, servers); err != nil {
		return nil, err
	}
	if err := s.checkIPv6Locked(server, before.Network6); err != nil {
		return nil, err
	}
	// the IPv6 network can come, go or change with peers: their addresses follow, and their files of before keep
	// working on IPv4
	if server.Network != before.Network {
		peers, err := q.Peers(id)
		if err != nil {
			return nil, err
		}
		if len(peers) > 0 {
			return nil, &ValidationError{Fields: map[string]string{"network": "has_peers"}}
		}
	}
	server.UpdatedAt = s.now().Unix()
	if err := q.UpdateServer(server); err != nil {
		return nil, takenOr(err, "name")
	}
	s.log.Info("server changed", "name", server.Name, "interface", server.Interface)
	if c := serverChanges(&before, server, serverNames(servers)); len(c) > 0 {
		s.changeLocked(by, store.Event{Kind: "server_changed", ServerName: server.Name, Detail: c.String()})
	}
	bound := server.DeviceBinding && !before.DeviceBinding
	if !server.Enabled || server.AuthMode != before.AuthMode || bound {
		// the peers log in again under the new rules: with device binding, from their device
		s.endSessionsLocked(func(session store.Session) bool { return session.ServerID == id }, EndServerChanged)
	}
	if bound {
		s.openEnrollmentsLocked(server)
	}
	s.applyLocked()
	return s.serverViewLocked(server)
}

// openEnrollmentsLocked opens the enrollment of the peers of a server whose binding was just turned on: the devices
// enrolled before stay, the other peers enroll at their next login.
func (s *Service) openEnrollmentsLocked(server *store.Server) {
	q := s.db.Q()
	peers, err := q.Peers(server.ID)
	if err != nil {
		return
	}
	devices, err := q.Devices()
	if err != nil {
		s.log.Error("can't read the devices", "error", err)
		return
	}
	for _, peer := range peers {
		if device, ok := devices[peer.ID]; ok && device.Enrolled() {
			continue
		}
		if err := s.openEnrollmentLocked(peer.ID, s.enrollWindowLocked()); err != nil {
			s.log.Error("can't open the enrollment of a peer", "peer", peer.Name, "error", err)
		}
	}
	s.log.Info("device binding on: the peers without a device enroll one at their next login", "server", server.Name,
		"hours", s.enrollHoursLocked())
}

func (s *Service) DeleteServer(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, err := s.db.Q().Server(id)
	if err != nil {
		return notFound(err)
	}
	peers, err := s.db.Q().Peers(id)
	if err != nil {
		return err
	}
	s.endSessionsLocked(func(session store.Session) bool { return session.ServerID == id }, EndServerChanged)
	// new peers can get the ids of its peers: the history must not go on with them
	if err := s.db.Q().EndConnectionsOf(id, 0); err != nil {
		s.log.Error("can't end the connections of a server", "error", err)
	}
	if err := s.db.Q().DeleteServer(id); err != nil {
		return notFound(err)
	}
	// the other servers no longer reach it
	if servers, err := s.db.Q().Servers(); err == nil {
		for index := range servers {
			other := &servers[index]
			kept := withoutID(other.ReachableServers, id)
			if len(kept) != len(other.ReachableServers) {
				other.ReachableServers = kept
				if err := s.db.Q().UpdateServer(other); err != nil {
					s.log.Error("can't update a server", "name", other.Name, "error", err)
				}
			}
		}
	}
	s.log.Info("server deleted", "name", server.Name, "interface", server.Interface)
	detail := ""
	if len(peers) > 0 {
		detail = fmt.Sprintf("with its %d peers", len(peers))
	}
	s.changeLocked(by, store.Event{Kind: "server_deleted", ServerName: server.Name, Detail: detail})
	s.applyLocked()
	return nil
}

func withoutID(list []int64, id int64) []int64 {
	kept := []int64{}
	for _, value := range list {
		if value != id {
			kept = append(kept, value)
		}
	}
	return kept
}

// checkServer checks the input and copies it into server; servers are all the servers, server among them when it
// exists.
func (s *Service) checkServer(input ServerInput, server *store.Server, servers []store.Server) error {
	var c checks
	name := strings.TrimSpace(input.Name)
	switch {
	case name == "":
		c.fail("name", "required")
	case !serverNamePattern.MatchString(name):
		c.fail("name", "invalid")
	}
	host := strings.TrimSpace(input.PublicHost)
	switch {
	case host == "":
		c.fail("public_host", "required")
	case !validHost(host):
		c.fail("public_host", "invalid")
	}
	if input.ListenPort < 1 || input.ListenPort > 65535 {
		c.fail("listen_port", "invalid")
	}
	if input.PublicPort < 0 || input.PublicPort > 65535 {
		c.fail("public_port", "invalid")
	}
	tunnel, err := netip.ParsePrefix(strings.TrimSpace(input.Network))
	switch {
	case strings.TrimSpace(input.Network) == "":
		c.fail("network", "required")
	case err != nil || !tunnel.Addr().Is4():
		c.fail("network", "invalid")
	case tunnel.Bits() < 16 || tunnel.Bits() > 29:
		c.fail("network", "size")
	}
	tunnel = tunnel.Masked()
	text6 := strings.TrimSpace(input.Network6)
	var tunnel6 netip.Prefix
	if text6 != "" {
		parsed, err := netip.ParsePrefix(text6)
		address := parsed.Addr()
		switch {
		// unicast, global or unique local: not link-local, multicast, loopback or an IPv4 address written in IPv6
		case err != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast():
			c.fail("network6", "invalid")
		case parsed.Bits() < MinNetwork6Bits || parsed.Bits() > MaxNetwork6Bits:
			c.fail("network6", "size6")
		case tunnel.IsValid() && 128-parsed.Bits() < 32-tunnel.Bits():
			// each peer has the address of its IPv4 one: the IPv6 network must hold as many
			c.fail("network6", "too_small")
		default:
			tunnel6 = parsed.Masked()
		}
	}

	networks := []netip.Prefix{}
	for _, text := range input.Networks {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			c.fail("networks", "invalid")
			continue
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is6() && text6 == "" {
			// the peers have no IPv6 address to reach it from
			c.fail("networks", "needs_ipv6")
			continue
		}
		if (tunnel.IsValid() && prefix.Overlaps(tunnel)) || (tunnel6.IsValid() && prefix.Overlaps(tunnel6)) {
			c.fail("networks", "overlaps_tunnel")
			continue
		}
		// nftables refuses networks that overlap in the same rule
		if overlapsAny(prefix, networks) {
			c.fail("networks", "overlap")
			continue
		}
		networks = append(networks, prefix)
	}
	if len(networks) > MaxNetworks {
		c.fail("networks", "too_many")
	}
	if _, wrong := c.fields["networks"]; input.Routed && len(networks) == 0 && !wrong {
		// only the networks are routed: the internet of the peers is translated anyway
		c.fail("routed", "no_networks")
	}
	dns := []string{}
	for _, text := range input.DNS {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" {
			c.fail("dns", "invalid")
			continue
		}
		dns = append(dns, address.String())
	}
	if len(dns) > MaxDNS {
		c.fail("dns", "too_many")
	}
	if input.MTU != 0 && (input.MTU < 1280 || input.MTU > 1500) {
		c.fail("mtu", "invalid")
	}
	if input.Keepalive < 0 || input.Keepalive > 300 {
		c.fail("keepalive", "invalid")
	}
	switch input.AuthMode {
	case store.AuthKey, store.AuthPassword, store.AuthPasswordOTP:
	default:
		c.fail("auth_mode", "invalid")
	}
	if input.SessionTimeout < MinTimeout || input.SessionTimeout > MaxTimeout {
		c.fail("session_timeout", "invalid")
	}
	lock := input.LockEndpoint
	switch lock {
	case "":
		lock = store.LockStrict
	case store.LockStrict, store.LockRoaming, store.LockOff:
	default:
		c.fail("lock_endpoint", "invalid")
	}
	port := input.PublicPort
	if port == 0 {
		port = input.ListenPort
	}
	fallbacks, code := checkFallbacks(input.FallbackEndpoints, peerconf.Endpoint(host, port), port)
	if code != "" {
		c.fail("fallback_endpoints", code)
	}
	reachable := []int64{}
	known := map[int64]bool{}
	for _, other := range servers {
		known[other.ID] = true
	}
	for _, id := range input.ReachableServers {
		switch {
		case server.ID != 0 && id == server.ID:
			c.fail("reachable_servers", "same_server")
		case !known[id]:
			c.fail("reachable_servers", "server_not_found")
		case containsID(reachable, id):
			c.fail("reachable_servers", "duplicate_server")
		default:
			reachable = append(reachable, id)
		}
	}
	for _, other := range servers {
		if other.ID == server.ID {
			continue
		}
		if strings.EqualFold(other.Name, name) {
			c.fail("name", "taken")
		}
		if other.ListenPort == input.ListenPort {
			c.fail("listen_port", "taken")
		}
		if prefix, err := netip.ParsePrefix(other.Network); err == nil && tunnel.IsValid() && prefix.Overlaps(tunnel) {
			c.fail("network", "taken")
		}
		if prefix := tunnel6Of(&other); prefix.IsValid() && tunnel6.IsValid() && prefix.Overlaps(tunnel6) {
			c.fail("network6", "taken")
		}
	}
	if err := c.err(); err != nil {
		return err
	}
	server.Name = name
	server.Enabled = input.Enabled
	server.PublicHost = host
	server.ListenPort = input.ListenPort
	server.PublicPort = input.PublicPort
	server.Network = tunnel.String()
	server.Network6 = ""
	if tunnel6.IsValid() {
		server.Network6 = tunnel6.String()
	}
	server.Networks = prefixTexts(networks)
	server.DNS = dns
	server.MTU = input.MTU
	server.Keepalive = input.Keepalive
	server.AuthMode = input.AuthMode
	server.SessionTimeout = input.SessionTimeout
	server.LockEndpoint = lock
	server.DetectCopies = input.DetectCopies
	server.BlockCopies = input.DetectCopies && input.BlockCopies
	server.Redirect = input.Redirect
	server.FallbackEndpoints = fallbacks
	// a device proves itself at the login: without one, nothing to bind
	gated := input.AuthMode == store.AuthPassword || input.AuthMode == store.AuthPasswordOTP
	server.DeviceBinding = gated && input.DeviceBinding
	server.MachineID = server.DeviceBinding && input.MachineID
	server.ClientToClient = input.ClientToClient
	server.ReachableServers = reachable
	// the networks start nothing to the peers of a translated server: they can't tell them apart
	server.Routed = input.Routed
	server.Inbound = input.Routed && input.Inbound
	return nil
}

func containsID(list []int64, id int64) bool {
	for _, value := range list {
		if value == id {
			return true
		}
	}
	return false
}

// checkFallbacks checks the other addresses of a server, host:port or host alone for the port of the endpoint, and
// returns them as WireGuard writes them, or the code of the problem.
func checkFallbacks(list []string, endpoint string, port int) ([]string, string) {
	fallbacks := []string{}
	seen := map[string]bool{strings.ToLower(endpoint): true}
	for _, text := range list {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		host, portText := text, ""
		if h, p, err := net.SplitHostPort(text); err == nil {
			host, portText = h, p
		} else if strings.Count(text, ":") > 1 && !strings.HasPrefix(text, "[") {
			// an IPv6 address alone
			host = text
		} else if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			host = text[1 : len(text)-1]
		} else if strings.Contains(text, ":") {
			return nil, "invalid"
		}
		chosen := port
		if portText != "" {
			value, err := strconv.Atoi(portText)
			if err != nil || value < 1 || value > 65535 {
				return nil, "invalid"
			}
			chosen = value
		}
		if !validHost(host) {
			return nil, "invalid"
		}
		normalized := peerconf.Endpoint(host, chosen)
		if seen[strings.ToLower(normalized)] {
			return nil, "duplicate"
		}
		seen[strings.ToLower(normalized)] = true
		fallbacks = append(fallbacks, normalized)
	}
	if len(fallbacks) > MaxFallbacks {
		return nil, "too_many"
	}
	return fallbacks, ""
}

func validHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == ""
	}
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	// a name made of digits only would be an address written wrong
	last := labels[len(labels)-1]
	return strings.IndexFunc(last, func(r rune) bool { return !unicode.IsDigit(r) }) >= 0
}

func overlapsAny(prefix netip.Prefix, list []netip.Prefix) bool {
	for _, other := range list {
		if prefix.Overlaps(other) {
			return true
		}
	}
	return false
}

func prefixTexts(list []netip.Prefix) []string {
	texts := make([]string, 0, len(list))
	for _, prefix := range list {
		texts = append(texts, prefix.String())
	}
	return texts
}

func freeInterface(servers []store.Server) string {
	used := map[string]bool{}
	for _, server := range servers {
		used[server.Interface] = true
	}
	for index := 0; ; index++ {
		name := fmt.Sprintf("wg%d", index)
		if !used[name] {
			return name
		}
	}
}

// takenOr turns a unique constraint of the database into a validation error of the field
func takenOr(err error, field string) error {
	if errors.Is(err, store.ErrConflict) {
		return &ValidationError{Fields: map[string]string{field: "taken"}}
	}
	return err
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
