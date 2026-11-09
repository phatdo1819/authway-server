package core

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/store"
)

func (f *fixture) serverWith(mode string, change func(*ServerInput)) *ServerView {
	f.t.Helper()
	suggestion, err := f.s.ServerDefaults(0)
	input := suggestion.ServerInput
	if err != nil {
		f.t.Fatal(err)
	}
	input.Name = "Office " + input.Network[5:6]
	input.AuthMode = mode
	change(&input)
	server, err := f.s.CreateServer(testActor, input)
	if err != nil {
		f.t.Fatal(err)
	}
	return server
}

func inputOf(server *ServerView) ServerInput {
	return ServerInput{
		Name: server.Name, Enabled: server.Enabled, PublicHost: server.PublicHost, ListenPort: server.ListenPort,
		PublicPort: server.PublicPort, Network: server.Network, Network6: server.Network6, Networks: server.Networks, DNS: server.DNS,
		MTU: server.MTU, Keepalive: server.Keepalive, AuthMode: server.AuthMode, SessionTimeout: server.SessionTimeout,
		LockEndpoint: server.LockEndpoint, DetectCopies: server.DetectCopies, BlockCopies: server.BlockCopies,
		Redirect: server.Redirect, FallbackEndpoints: server.Fallbacks, DeviceBinding: server.DeviceBinding,
		MachineID: server.MachineID, ClientToClient: server.ClientToClient, ReachableServers: server.Reachable,
		Routed: server.Routed, Inbound: server.Inbound,
	}
}

func (f *fixture) login(peer *PeerView, from string) Answer {
	f.t.Helper()
	f.handshake(peer, from)
	return f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: peer.Username, Password: "Secret,1234"})
}

func (f *fixture) session(peerID int64) *SessionView {
	sessions, _ := f.s.OpenSessions()
	for _, session := range sessions {
		if session.PeerID == peerID {
			return &session
		}
	}
	return nil
}

func (f *fixture) lastEnd() string {
	history, _ := f.s.History(1)
	if len(history) == 0 {
		return ""
	}
	return history[0].EndReason
}

func TestStrictLock(t *testing.T) {
	f := setup(t)
	// no copy detection here: the endpoint changes back and forth on purpose
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DetectCopies = false })
	if server.LockEndpoint != store.LockStrict {
		t.Fatalf("default lock %q", server.LockEndpoint)
	}
	peer := f.peer(server, f.user("alice"))
	address := netip.MustParseAddr(peer.Address)
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}

	// another device sends with the key
	f.handshake(peer, "198.51.100.9")
	f.s.Tick()
	if f.net.Open("wg0", address) || f.session(peer.ID).PausedAt == 0 {
		t.Fatal("not paused by another public IP")
	}
	if a := f.s.LoginStatus(address, "10.8.0.1", nil); a.Body["authenticated"] != false {
		t.Fatalf("a paused session counts: %+v", a)
	}
	// the device of the login comes back
	f.handshake(peer, "203.0.113.7")
	f.s.Tick()
	if !f.net.Open("wg0", address) || f.session(peer.ID).PausedAt != 0 {
		t.Fatal("not resumed")
	}
	// the status follows at once, without waiting for the next check
	f.handshake(peer, "198.51.100.9")
	if a := f.s.LoginStatus(address, "10.8.0.1", nil); a.Body["authenticated"] != false || f.net.Open("wg0", address) {
		t.Fatalf("the status doesn't pause: %+v", a)
	}
	// a restart keeps the gate closed for the paused session
	again, err := New(f.db, f.net, Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log})
	if err != nil {
		t.Fatal(err)
	}
	if f.net.Open("wg0", address) {
		t.Fatal("a restart opened a paused session")
	}
	f.s = again
	// away too long
	f.clock.advance(PauseLimit + time.Second)
	f.handshake(peer, "198.51.100.9")
	f.s.Tick()
	if f.session(peer.ID) != nil || f.lastEnd() != EndEndpointChanged {
		t.Fatalf("still open after the pause limit, end %q", f.lastEnd())
	}
	// moving to another network: a new login there moves the lock
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	f.handshake(peer, "192.0.2.50")
	f.s.Tick()
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 200 {
		t.Fatalf("login from the new network: %+v", a)
	}
	f.s.Tick()
	if !f.net.Open("wg0", address) || f.session(peer.ID).Endpoint != "192.0.2.50" {
		t.Fatalf("the new login doesn't move the lock: %+v", f.session(peer.ID))
	}
	events, _ := f.s.Events(50)
	kinds := map[string]int{}
	for _, event := range events {
		kinds[event.Kind]++
	}
	if kinds["session_paused"] < 2 || kinds["session_resumed"] < 1 {
		t.Errorf("events: %v", kinds)
	}
}

func TestRoaming(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.LockEndpoint = store.LockRoaming
		input.DetectCopies = false
	})
	peer := f.peer(server, f.user("alice"))
	f.login(peer, "203.0.113.7")
	f.handshake(peer, "198.51.100.9")
	f.s.Tick()
	session := f.session(peer.ID)
	if session == nil || session.PausedAt != 0 || session.Endpoint != "198.51.100.9" || !f.net.Open("wg0", netip.MustParseAddr(peer.Address)) {
		t.Fatalf("the session doesn't follow: %+v", session)
	}
}

func TestCopies(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	if !server.DetectCopies || server.BlockCopies {
		t.Fatalf("defaults: %+v", server)
	}
	peer := f.peer(server, f.user("alice"))
	address := netip.MustParseAddr(peer.Address)
	twoDevices := func() {
		for _, ip := range []string{"203.0.113.7", "198.51.100.9", "203.0.113.7", "198.51.100.9"} {
			f.clock.advance(10 * time.Second)
			f.handshake(peer, ip)
			f.s.Tick()
		}
	}
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	twoDevices()
	alerts, _ := f.s.Alerts(peer.ID, 10)
	if len(alerts) != 1 || alerts[0].Kind != "copy" || strings.Join(alerts[0].Addresses, ",") != "198.51.100.9,203.0.113.7" {
		t.Fatalf("alerts: %+v", alerts)
	}
	if f.session(peer.ID) != nil || f.lastEnd() != EndCopySuspected {
		t.Fatalf("the session of a copied peer stays, end %q", f.lastEnd())
	}
	// not blocked: the user can log in again
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login after the alert: %+v", a)
	}

	// a device that moves through new networks isn't a copy
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		f.clock.advance(10 * time.Second)
		f.handshake(peer, ip)
		f.s.Tick()
	}
	if alerts, _ := f.s.Alerts(peer.ID, 10); len(alerts) != 1 {
		t.Fatalf("a device moving is a copy: %+v", alerts)
	}

	input := inputOf(server)
	input.BlockCopies = true
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	twoDevices()
	if a := f.s.LoginStatus(address, "10.8.0.1", nil); a.Body["blocked"] != true {
		t.Fatalf("not blocked: %+v", a)
	}
	if a := f.login(peer, "203.0.113.7"); a.Status != 403 || a.Body["error"] != "blocked" {
		t.Fatalf("a blocked peer logs in: %+v", a)
	}
	if peers, _ := f.s.Peers(server.ID); !peers[0].Blocked || peers[0].Alerts != 2 {
		t.Fatalf("peer view: %+v", peers[0])
	}
	if err := f.s.ClearPeerAlerts(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login after the alerts are cleared: %+v", a)
	}
	// new keys unblock too
	twoDevices()
	updated, err := f.s.RegeneratePeerKeys(testActor, peer.ID)
	if err != nil || updated.Blocked || updated.Alerts != 0 {
		t.Fatalf("new keys: %+v %v", updated, err)
	}
}

func TestPeerWideLockout(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.user("alice"))
	address := netip.MustParseAddr(peer.Address)
	// the IP of the real user, trusted after a login
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	f.s.Logout(address, "10.8.0.1")
	for index := range MaxFailures * PeerFailureFactor {
		f.handshake(peer, fmt.Sprintf("198.51.100.%d", index+1))
		f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"})
	}
	f.handshake(peer, "192.0.2.99")
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 429 {
		t.Fatalf("many IPs multiply the attempts: %+v", a)
	}
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("the IP of the latest login is locked out: %+v", a)
	}
	alerts, _ := f.s.Alerts(peer.ID, 10)
	if len(alerts) != 1 || len(alerts[0].Addresses) != MaxFailures*PeerFailureFactor {
		t.Fatalf("alerts: %+v", alerts)
	}
}

func TestFallbacks(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.FallbackEndpoints = []string{" vpn2.example.com ", "203.0.113.10:51821", "[2001:db8::1]:51822", ""}
	})
	if got := strings.Join(server.Fallbacks, ", "); got != "vpn2.example.com:51820, 203.0.113.10:51821, [2001:db8::1]:51822" {
		t.Fatalf("fallbacks: %s", got)
	}
	peer := f.peer(server, f.user("alice"))
	_, text, _ := f.s.PeerConfig(testActor, peer.ID)
	if !strings.Contains(text, "Endpoint = vpn.example.com:51820\n# Fallback = vpn2.example.com:51820, 203.0.113.10:51821, [2001:db8::1]:51822\n") {
		t.Fatalf("config:\n%s", text)
	}
	for list, code := range map[string]string{
		"vpn.example.com:51820":       "duplicate",
		"a.example.com,a.example.com": "duplicate",
		"bad host":                    "invalid",
		"host.example.com:99999":      "invalid",
		"2001:db8::1:51820:x":         "invalid",
		"a.example,b.example,c.example,d.example,e.example": "too_many",
	} {
		input := inputOf(server)
		input.FallbackEndpoints = strings.Split(list, ",")
		if _, err := f.s.UpdateServer(testActor, server.ID, input); fields(t, err)["fallback_endpoints"] != code {
			t.Errorf("%q: %v, want %s", list, err, code)
		}
	}
}

func TestRedirectTarget(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	f.peer(server, f.user("alice"))
	f.server(store.AuthKey)
	if target, target6, ok := f.s.RedirectTarget(netip.MustParseAddr("10.8.0.2")); !ok || target.String() != "10.8.0.1" ||
		target6.String() != server.Address6 {
		t.Fatalf("target %v %v %v", target, target6, ok)
	}
	// from its IPv6 address too
	peers, _ := f.s.Peers(server.ID)
	if target, _, ok := f.s.RedirectTarget(netip.MustParseAddr(peers[0].Address6)); !ok || target.String() != "10.8.0.1" {
		t.Fatalf("from IPv6: %v %v", target, ok)
	}
	tunnel6 := netip.MustParsePrefix(server.Network6)
	// an address of the IPv6 tunnel that no IPv4 one stands for, or no peer has
	stray := tunnel6.Addr().As16()
	stray[8] = 1
	for _, address := range []string{"10.8.0.99", "10.8.1.2", "192.168.1.1", netip.AddrFrom16(stray).String(),
		strings.TrimSuffix(server.Address6, "1") + "63"} {
		if _, _, ok := f.s.RedirectTarget(netip.MustParseAddr(address)); ok {
			t.Errorf("%s is redirected", address)
		}
	}
	if !f.net.State.Servers[0].Redirect || f.net.State.Servers[1].Redirect {
		t.Errorf("redirect applied: %+v", f.net.State.Servers)
	}
	if len(f.net.Flushed) != 0 {
		t.Error("flushed before any login")
	}
	peer, _ := f.s.Peers(server.ID)
	f.login(&peer[0], "203.0.113.7")
	// of both its addresses
	if len(f.net.Flushed) != 2 || f.net.Flushed[0].String() != "10.8.0.2" || f.net.Flushed[1].String() != peer[0].Address6 {
		t.Errorf("the redirected connections stay after the login: %v", f.net.Flushed)
	}
}

// A failed login records the user of the peer, never the username typed: it can be a password.
func TestLoginFailedEvent(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.user("alice"))
	f.handshake(peer, "203.0.113.7")
	address := netip.MustParseAddr(peer.Address)
	f.s.Login(address, "10.8.0.1", LoginRequest{Username: "Secret,1234", Password: "alice"})
	f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"})
	events := f.vpnEvents(10)
	if len(events) != 2 {
		t.Fatalf("events: %+v", events)
	}
	if events[1].Username != "alice" || events[1].Detail != "another username" {
		t.Errorf("another username: %+v", events[1])
	}
	if events[0].Username != "alice" || events[0].Detail != "" {
		t.Errorf("a wrong password: %+v", events[0])
	}
}

// A new peer can get the id of a deleted one: it starts with no failures and no trusted IP.
func TestNewPeerStartsClean(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	f.handshake(peer, "198.51.100.1")
	f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"})
	if err := f.s.DeletePeer(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	again := f.peer(server, f.user("bob"))
	if again.ID != peer.ID {
		t.Skipf("the id %d didn't come back (%d)", peer.ID, again.ID)
	}
	if f.s.failures.trusted[again.ID] != "" || len(f.s.failures.byPeer[again.ID]) != 0 {
		t.Fatalf("the new peer has the state of the old one: %q %v", f.s.failures.trusted[again.ID], f.s.failures.byPeer[again.ID])
	}
	// another user on a peer: the same
	f.handshake(again, "203.0.113.7")
	if a := f.s.Login(netip.MustParseAddr(again.Address), "10.8.0.1", LoginRequest{Username: "bob", Password: "Secret,1234"}); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	if _, err := f.s.UpdatePeer(testActor, again.ID, PeerInput{Name: again.Name, Enabled: true, UserID: alice.ID}); err != nil {
		t.Fatal(err)
	}
	if f.s.failures.trusted[again.ID] != "" {
		t.Fatal("the trusted IP of the old user stays")
	}
}

// A login while WireGuard has no endpoint for the peer: the strict lock takes the first IP seen.
func TestStrictLockWithoutEndpoint(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DetectCopies = false })
	peer := f.peer(server, f.user("alice"))
	address := netip.MustParseAddr(peer.Address)
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	if session := f.session(peer.ID); session == nil || session.Endpoint != "" {
		t.Fatalf("session: %+v", session)
	}
	f.handshake(peer, "203.0.113.7")
	f.s.Tick()
	if session := f.session(peer.ID); session.Endpoint != "203.0.113.7" || session.PausedAt != 0 {
		t.Fatalf("not locked to the first IP: %+v", session)
	}
	f.handshake(peer, "198.51.100.9")
	f.s.Tick()
	if f.net.Open("wg0", address) || f.session(peer.ID).PausedAt == 0 {
		t.Fatal("another IP doesn't pause the session")
	}
}
