package core

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

type fixture struct {
	t     *testing.T
	s     *Service
	net   *network.Fake
	clock *clock
	db    *store.Store
	// what the service runs later: runTimers runs it
	timers *[]func()
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fake := network.NewFake()
	clk := &clock{now: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)}
	timers := &[]func(){}
	s, err := New(db, fake, Options{
		LoginPort: 8181, PublicHost: "vpn.example.com", Now: clk.Now,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		After: func(d time.Duration, f func()) { *timers = append(*timers, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// the IPv6 networks of the servers are fd00:aaaa:bbbb::/64, fd00:aaaa:bbbb:1::/64...: the tests know the addresses
	if err := db.Q().SetMeta(metaIPv6Prefix, "fd00:aaaa:bbbb::/48"); err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, s: s, net: fake, clock: clk, db: db, timers: timers}
}

func (f *fixture) runTimers() {
	pending := *f.timers
	*f.timers = nil
	for _, run := range pending {
		run()
	}
}

func (f *fixture) server(mode string) *ServerView {
	f.t.Helper()
	suggestion, err := f.s.ServerDefaults(0)
	input := suggestion.ServerInput
	if err != nil {
		f.t.Fatal(err)
	}
	input.Name = "Office " + input.Network[5:6]
	input.AuthMode = mode
	input.Networks = []string{"192.168.1.0/24"}
	server, err := f.s.CreateServer(testActor, input)
	if err != nil {
		f.t.Fatal(err)
	}
	return server
}

func (f *fixture) user(name string) *UserView {
	f.t.Helper()
	user, err := f.s.CreateUser(testActor, UserInput{Username: name, Password: "Secret,1234"})
	if err != nil {
		f.t.Fatal(err)
	}
	return user
}

func (f *fixture) peer(server *ServerView, user *UserView) *PeerView {
	f.t.Helper()
	peer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: user.Username + " laptop", Enabled: true, UserID: user.ID})
	if err != nil {
		f.t.Fatal(err)
	}
	return peer
}

// handshake tells the fake WireGuard that the peer is there, from a public IP
func (f *fixture) handshake(peer *PeerView, from string) {
	key, _ := wgtypes.ParseKey(peer.PublicKey)
	f.net.SetPeer(key, network.PeerStats{
		Interface: "wg0", Endpoint: netip.AddrPortFrom(netip.MustParseAddr(from), 40000), LastHandshake: f.clock.now,
	})
}

// vpnEvents are the latest events of the peers, without the changes made in the web UI
func (f *fixture) vpnEvents(limit int) []EventView {
	page, err := f.s.EventsPage(Filter{Limit: limit}, EventsVPN)
	if err != nil {
		panic(err)
	}
	return page.Items
}

// testActor is the administrator of the changes of the tests
var testActor = Actor{ID: 1, Username: "tester", From: "192.0.2.10"}

func fields(t *testing.T, err error) map[string]string {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("not a validation error: %v", err)
	}
	return validation.Fields
}

func TestServers(t *testing.T) {
	f := setup(t)
	first := f.server(store.AuthPassword)
	if first.Interface != "wg0" || first.ListenPort != 51820 || first.Network != "10.8.0.0/24" || first.Address != "10.8.0.1" {
		t.Fatalf("unexpected first server: %+v", first)
	}
	if first.LoginURL != "http://10.8.0.1:8181/" || first.PublicKey == "" {
		t.Fatalf("login URL %q, key %q", first.LoginURL, first.PublicKey)
	}
	second := f.server(store.AuthKey)
	if second.Interface != "wg1" || second.ListenPort != 51821 || second.Network != "10.8.1.0/24" || second.LoginURL != "" {
		t.Fatalf("unexpected second server: %+v", second)
	}
	if len(f.net.State.Servers) != 2 || !f.net.State.Servers[0].Gated || f.net.State.Servers[1].Gated {
		t.Fatalf("not applied: %+v", f.net.State)
	}

	suggestion, _ := f.s.ServerDefaults(0)
	input := suggestion.ServerInput
	input.Name = strings.ToUpper(first.Name)
	input.ListenPort = 51820
	input.Network = "10.8.0.128/25"
	input.Networks = []string{"10.8.2.0/24", "10.8.2.0/25", "10.8.0.0/16"}
	input.PublicHost = "-bad-"
	_, err := f.s.CreateServer(testActor, input)
	got := fields(t, err)
	for field, code := range map[string]string{
		"name": "taken", "listen_port": "taken", "network": "taken", "networks": "overlap", "public_host": "invalid",
	} {
		if got[field] != code {
			t.Errorf("%s: got %q, want %q (%v)", field, got[field], code, got)
		}
	}

	// the network of a server with peers stays
	alice := f.user("alice")
	f.peer(first, alice)
	edit := ServerInput{
		Name: first.Name, Enabled: true, PublicHost: "vpn.example.com", ListenPort: 51820, Network: "10.9.0.0/24",
		AuthMode: store.AuthPassword, SessionTimeout: DefaultTimeout, Keepalive: 25,
	}
	if _, err := f.s.UpdateServer(testActor, first.ID, edit); fields(t, err)["network"] != "has_peers" {
		t.Errorf("the network changed under the peers: %v", err)
	}
}

func TestPeers(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "no user", Enabled: true}); fields(t, err)["user_id"] != "required" {
		t.Errorf("a gated server takes a peer without user: %v", err)
	}
	peer := f.peer(server, alice)
	if peer.Address != "10.8.0.2" || peer.Username != "alice" {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "phone", Enabled: true, UserID: alice.ID}); fields(t, err)["user_id"] != "has_peer" {
		t.Errorf("a second peer for the same user: %v", err)
	}
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "ALICE LAPTOP", Enabled: true, UserID: f.user("bob").ID}); fields(t, err)["name"] != "taken" {
		t.Errorf("a name taken twice: %v", err)
	}
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "x", Enabled: true, UserID: f.user("carol").ID, Address: "10.8.0.1"}); fields(t, err)["address"] != "invalid" {
		t.Errorf("the address of the server given to a peer: %v", err)
	}
	name, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Name = alice laptop", "# Login = http://10.8.0.1:8181/", "Address = 10.8.0.2/32, fd00:aaaa:bbbb::2/128",
		"PublicKey = " + server.PublicKey, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/24", "Endpoint = vpn.example.com:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if name != "Office-0-alice-laptop.conf" {
		t.Errorf("file name %q", name)
	}
	if got := f.net.State.Servers[0].Peers; len(got) != 1 || got[0].Address.String() != "10.8.0.2" {
		t.Errorf("peer not applied: %+v", got)
	}
	// deleting the user deletes its peer
	if err := f.s.DeleteUser(testActor, alice.ID); err != nil {
		t.Fatal(err)
	}
	if peers, _ := f.s.Peers(server.ID); len(peers) != 0 {
		t.Errorf("the peer of a deleted user stays: %+v", peers)
	}
	if len(f.net.State.Servers[0].Peers) != 0 {
		t.Error("the peer of a deleted user stays in WireGuard")
	}
}

// a server without login takes peers without a user; its view counts them, for the warning when the login is
// turned on
func TestPeersWithoutUser(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthKey)
	printer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "printer", Enabled: true})
	if err != nil || printer.UserID != 0 || printer.Address != "10.8.0.2" {
		t.Fatalf("a peer without user on a server without login: %+v, %v", printer, err)
	}
	f.peer(server, f.user("alice"))
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "copy", Enabled: true, Address: printer.Address}); fields(t, err)["address"] != "taken" {
		t.Errorf("the address of another peer: %v", err)
	}
	view, err := f.s.Server(server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Peers != 2 || view.PeersWithoutUser != 1 {
		t.Errorf("peers %d, without user %d", view.Peers, view.PeersWithoutUser)
	}
}

func TestLogin(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	f.handshake(peer, "203.0.113.7")
	address := netip.MustParseAddr("10.8.0.2")

	if a := f.s.LoginStatus(address, "evil.example.com", nil); a.Status != 403 {
		t.Errorf("another host is answered: %+v", a)
	}
	if a := f.s.LoginStatus(netip.MustParseAddr("10.8.0.99"), "10.8.0.1", nil); a.Status != 403 {
		t.Errorf("an unknown address is answered: %+v", a)
	}
	a := f.s.LoginStatus(address, "10.8.0.1:8181", nil)
	if a.Status != 200 || a.Body["authenticated"] != false || a.Body["otp_required"] != false || a.Body["server"] != server.Name {
		t.Fatalf("status before the login: %+v", a)
	}
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"}); a.Status != 401 || a.Body["error"] != "invalid_credentials" {
		t.Fatalf("a wrong password: %+v", a)
	}
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "bob", Password: "Secret,1234"}); a.Status != 401 {
		t.Fatalf("the password with another username: %+v", a)
	}
	if f.net.Open("wg0", address) {
		t.Fatal("the gate opened before the login")
	}
	a = f.s.Login(address, "10.8.0.1", LoginRequest{Username: "ALICE", Password: "Secret,1234"})
	if a.Status != 200 || a.Body["user"] != "alice" || a.Body["expires"] != "2026-11-06T18:00:00Z" {
		t.Fatalf("the login: %+v", a)
	}
	if !f.net.Open("wg0", address) {
		t.Fatal("the gate is closed after the login")
	}
	a = f.s.LoginStatus(address, "10.8.0.1", nil)
	if a.Body["authenticated"] != true || a.Body["user"] != "alice" {
		t.Fatalf("status after the login: %+v", a)
	}
	sessions, _ := f.s.OpenSessions()
	if len(sessions) != 1 || sessions[0].Endpoint != "203.0.113.7" {
		t.Fatalf("sessions: %+v", sessions)
	}
	// a restart keeps the session
	again, err := New(f.db, f.net, Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log})
	if err != nil {
		t.Fatal(err)
	}
	if !f.net.Open("wg0", address) {
		t.Fatal("a restart closed the gate")
	}
	if a := again.Logout(address, "10.8.0.1"); a.Status != 200 {
		t.Fatalf("logout: %+v", a)
	}
	if f.net.Open("wg0", address) {
		t.Fatal("the gate stays open after the logout")
	}
	history, _ := again.History(10)
	if len(history) != 1 || history[0].EndReason != EndLogout {
		t.Fatalf("history: %+v", history)
	}
}

func TestLoginWithCode(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPasswordOTP)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	f.handshake(peer, "203.0.113.7")
	address := netip.MustParseAddr("10.8.0.2")
	if a := f.s.LoginStatus(address, "10.8.0.1", nil); a.Body["no_otp"] != true || a.Body["otp_required"] != true {
		t.Fatalf("status without authenticator: %+v", a)
	}
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 403 || a.Body["error"] != "no_otp" {
		t.Fatalf("login without authenticator: %+v", a)
	}
	setupTOTP, err := f.s.SetupTOTP(testActor, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(setupTOTP.Secret, uint64(f.clock.now.Unix())/totp.Period)
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234", OTP: "000000"}); a.Status != 401 {
		t.Fatalf("a wrong code: %+v", a)
	}
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234", OTP: code}); a.Status != 200 {
		t.Fatalf("the right code: %+v", a)
	}
	f.s.Logout(address, "10.8.0.1")
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234", OTP: code}); a.Status != 401 {
		t.Fatalf("a code used twice: %+v", a)
	}
}

func TestLockout(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.user("alice"))
	address := netip.MustParseAddr("10.8.0.2")
	f.handshake(peer, "198.51.100.1")
	for range MaxFailures {
		f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"})
	}
	a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"})
	if a.Status != 429 || a.Body["retry_after"] != int(LockoutTime.Seconds()) {
		t.Fatalf("after %d failures: %+v", MaxFailures, a)
	}
	if alerts, _ := f.s.Alerts(peer.ID, 10); len(alerts) != 1 || alerts[0].Kind != "lockout" || alerts[0].Addresses[0] != "198.51.100.1" {
		t.Fatalf("alerts: %+v", alerts)
	}
	// the real user, from another network, isn't locked out by a copy of the configuration
	f.handshake(peer, "203.0.113.7")
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 200 {
		t.Fatalf("another IP is locked out: %+v", a)
	}
	f.handshake(peer, "198.51.100.1")
	f.clock.advance(LockoutTime)
	f.s.Logout(address, "10.8.0.1")
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 200 {
		t.Fatalf("still locked out after the wait: %+v", a)
	}
	events := f.vpnEvents(20)
	if len(events) != MaxFailures+1 || events[0].Kind != "locked_out" {
		t.Fatalf("events: %+v", events)
	}
}

func TestSessionsEnd(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	address := netip.MustParseAddr("10.8.0.2")
	login := func() {
		t.Helper()
		f.handshake(peer, "203.0.113.7")
		if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"}); a.Status != 200 {
			t.Fatalf("login: %+v", a)
		}
	}
	reason := func() string {
		t.Helper()
		history, _ := f.s.History(1)
		if len(history) == 0 {
			return ""
		}
		return history[0].EndReason
	}

	login()
	f.clock.advance(4 * time.Minute)
	f.s.Tick()
	if !f.net.Open("wg0", address) {
		t.Fatal("ended before the idle time")
	}
	f.clock.advance(2 * time.Minute)
	f.s.Tick()
	if f.net.Open("wg0", address) || reason() != EndIdle {
		t.Fatalf("no handshake for 6 minutes: still open, reason %q", reason())
	}

	login()
	f.clock.advance(time.Duration(DefaultTimeout) * time.Second)
	f.handshake(peer, "203.0.113.7")
	f.s.Tick()
	if f.net.Open("wg0", address) || reason() != EndExpired {
		t.Fatalf("expired: still open, reason %q", reason())
	}

	login()
	if _, err := f.s.UpdateUser(testActor, alice.ID, UserInput{Username: "alice", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if f.net.Open("wg0", address) || reason() != EndUserChanged {
		t.Fatalf("user disabled: still open, reason %q", reason())
	}
	if _, err := f.s.UpdateUser(testActor, alice.ID, UserInput{Username: "alice"}); err != nil {
		t.Fatal(err)
	}

	login()
	edit := ServerInput{
		Name: server.Name, Enabled: true, PublicHost: server.PublicHost, ListenPort: server.ListenPort,
		Network: server.Network, AuthMode: store.AuthPasswordOTP, SessionTimeout: DefaultTimeout, Keepalive: 25,
	}
	if _, err := f.s.UpdateServer(testActor, server.ID, edit); err != nil {
		t.Fatal(err)
	}
	if f.net.Open("wg0", address) || reason() != EndServerChanged {
		t.Fatalf("login mode changed: still open, reason %q", reason())
	}
}

func TestApplyFailure(t *testing.T) {
	f := setup(t)
	f.net.ApplyError = errors.New("nft: syntax error")
	f.server(store.AuthKey)
	status, _ := f.s.Status()
	if !strings.Contains(status.ApplyError, "syntax error") {
		t.Fatalf("the failure isn't reported: %+v", status)
	}
	f.net.ApplyError = nil
	f.s.Tick()
	status, _ = f.s.Status()
	if status.ApplyError != "" || len(f.net.State.Servers) != 1 {
		t.Fatalf("not applied again: %+v", status)
	}
}

func TestAdmins(t *testing.T) {
	f := setup(t)
	password, err := f.s.EnsureAdmin("admin", "")
	if err != nil || len(password) != 16 {
		t.Fatalf("first admin: %q %v", password, err)
	}
	if again, _ := f.s.EnsureAdmin("admin", ""); again != "" {
		t.Fatal("a second first admin")
	}
	admin, ok := f.s.AdminLogin("admin", password)
	if !ok {
		t.Fatal("the password of the first admin fails")
	}
	if _, ok := f.s.AdminLogin("admin", "wrong"); ok {
		t.Fatal("a wrong password works")
	}
	if err := f.s.ChangeAdminPassword(Actor{ID: admin.ID}, "wrong", "A new long password 1"); fields(t, err)["current"] != "wrong" {
		t.Fatalf("changed without the current password: %v", err)
	}
	if err := f.s.ChangeAdminPassword(Actor{ID: admin.ID}, password, "A new long password 1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.AdminLogin("admin", "A new long password 1"); !ok {
		t.Fatal("the new password fails")
	}
}
