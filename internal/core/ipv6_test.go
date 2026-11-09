package core

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

func TestIPv6Addresses(t *testing.T) {
	prefix, address := netip.MustParsePrefix, netip.MustParseAddr
	tunnel, tunnel6 := prefix("10.8.0.0/24"), prefix("fd00:aaaa:bbbb::/64")
	for four, six := range map[string]string{
		"10.8.0.1": "fd00:aaaa:bbbb::1", "10.8.0.5": "fd00:aaaa:bbbb::5", "10.8.0.254": "fd00:aaaa:bbbb::fe",
	} {
		got, ok := address6(tunnel, tunnel6, address(four))
		if !ok || got.String() != six {
			t.Errorf("%s: %v %v, want %s", four, got, ok, six)
		}
		if back, ok := address4(tunnel, tunnel6, got); !ok || back.String() != four {
			t.Errorf("%s back: %v %v", six, back, ok)
		}
	}
	// a /16 in a /112, a /24 in a /120 that doesn't start at 0: the host part fits
	if got, ok := address6(prefix("10.9.0.0/16"), prefix("fd00:1::/112"), address("10.9.3.7")); !ok || got.String() != "fd00:1::307" {
		t.Errorf("/16: %v %v", got, ok)
	}
	if got, ok := address6(prefix("10.8.4.0/24"), prefix("fd00:1::100/120"), address("10.8.4.9")); !ok || got.String() != "fd00:1::109" {
		t.Errorf("/120: %v %v", got, ok)
	}
	if _, ok := address6(tunnel, tunnel6, address("10.8.1.5")); ok {
		t.Error("an address out of the tunnel has an IPv6 one")
	}
	if _, ok := address6(tunnel, netip.Prefix{}, address("10.8.0.5")); ok {
		t.Error("an IPv6 address without an IPv6 network")
	}
	// the addresses of the IPv6 network that no IPv4 address stands for, and the ones out of it
	for _, text := range []string{"fd00:aaaa:bbbb::100", "fd00:aaaa:bbbb:0:1::5", "fd00:aaaa:bbbc::5", "10.8.0.5", "::ffff:10.8.0.5"} {
		if got, ok := address4(tunnel, tunnel6, address(text)); ok {
			t.Errorf("%s stands for %s", text, got)
		}
	}

	for ip, key := range map[string]string{
		"203.0.113.7": "203.0.113.7", "::ffff:203.0.113.7": "203.0.113.7", "2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64", "": "",
	} {
		if got := clientKey(ip); got != key {
			t.Errorf("clientKey(%q) = %q, want %q", ip, got, key)
		}
	}
	if !sameClient("2001:db8:1:2::10", "2001:db8:1:2:a:b:c:d") || sameClient("2001:db8:1:2::10", "2001:db8:1:3::10") ||
		sameClient("203.0.113.7", "203.0.113.8") {
		t.Error("sameClient")
	}

	ula := prefix("fd00:aaaa:bbbb::/48")
	if got := suggestNetwork6(ula, prefix("10.8.12.0/24"), nil); got.String() != "fd00:aaaa:bbbb:12::/64" {
		t.Errorf("suggestion %v", got)
	}
	if got := suggestNetwork6(ula, prefix("10.8.12.0/24"), []netip.Prefix{prefix("fd00:aaaa:bbbb:12::/64")}); got.String() != "fd00:aaaa:bbbb:13::/64" {
		t.Errorf("next suggestion %v", got)
	}
}

func TestIPv6ServerChecks(t *testing.T) {
	f := setup(t)
	suggestion, err := f.s.ServerDefaults(0)
	if err != nil || suggestion.Network6 != "fd00:aaaa:bbbb::/64" || suggestion.IPv6Off != "" {
		t.Fatalf("defaults: %+v %v", suggestion, err)
	}
	server := f.server(store.AuthPassword)
	if server.Network6 != "fd00:aaaa:bbbb::/64" || server.Address6 != "fd00:aaaa:bbbb::1" {
		t.Fatalf("server: %+v", server)
	}
	if next, _ := f.s.ServerDefaults(0); next.Network != "10.8.1.0/24" || next.Network6 != "fd00:aaaa:bbbb:1::/64" {
		t.Errorf("next defaults: %+v", next)
	}
	// for the server itself: its own networks are free for it
	if own, _ := f.s.ServerDefaults(server.ID); own.Network != "10.8.0.0/24" || own.Network6 != "fd00:aaaa:bbbb::/64" {
		t.Errorf("own defaults: %+v", own)
	}
	if _, err := f.s.ServerDefaults(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("defaults of a server that isn't there: %v", err)
	}

	created := 0
	create := func(change func(*ServerInput)) error {
		suggestion, _ := f.s.ServerDefaults(0)
		input := suggestion.ServerInput
		created++
		input.Name = fmt.Sprintf("Other %d", created)
		change(&input)
		_, err := f.s.CreateServer(testActor, input)
		return err
	}
	for text, code := range map[string]string{
		"10.9.0.0/24": "invalid", "fe80::/64": "invalid", "ff02::/64": "invalid", "::1/128": "invalid",
		"::ffff:10.0.0.0/120": "invalid", "nonsense": "invalid", "fd00:1::/48": "size6", "fd00:1::/124": "size6",
		// overlaps the network of the first server
		"fd00:aaaa:bbbb::/96": "taken",
	} {
		if err := create(func(input *ServerInput) { input.Network6 = text }); fields(t, err)["network6"] != code {
			t.Errorf("%s: %v, want %s", text, err, code)
		}
	}
	// a /16 needs 16 bits of host part
	err = create(func(input *ServerInput) { input.Network, input.Network6 = "10.20.0.0/16", "fd00:9::/120" })
	if fields(t, err)["network6"] != "too_small" {
		t.Errorf("too small: %v", err)
	}
	for _, test := range []struct {
		network6 string
		networks []string
		code     string
	}{
		{"", []string{"2001:db8:5::/64"}, "needs_ipv6"},
		{"fd00:aaaa:bbbb:5::/64", []string{"fd00:aaaa:bbbb:5::/80"}, "overlaps_tunnel"},
		{"fd00:aaaa:bbbb:5::/64", []string{"2001:db8:5::/64", "2001:db8:5::/48"}, "overlap"},
		{"fd00:aaaa:bbbb:5::/64", []string{"::/0"}, "invalid"},
	} {
		err := create(func(input *ServerInput) { input.Network6, input.Networks = test.network6, test.networks })
		if fields(t, err)["networks"] != test.code {
			t.Errorf("%v: %v, want %s", test, err, test.code)
		}
	}
	// IPv6 and IPv4 networks together
	if err := create(func(input *ServerInput) { input.Networks = []string{"192.168.1.0/24", "2001:db8:5::/64"} }); err != nil {
		t.Fatalf("both versions: %v", err)
	}

	// IPv6 off in the container: no new IPv6 network, but the other changes of a server that has one still save
	f.net.IPv6Error = errors.New("IPv6 is off in the container")
	if off, _ := f.s.ServerDefaults(0); off.Network6 != "" || off.IPv6Off == "" {
		t.Errorf("defaults without IPv6: %+v", off)
	}
	input := inputOf(server)
	input.Network6 = "fd00:aaaa:bbbb:9::/64"
	if _, err := f.s.UpdateServer(testActor, server.ID, input); fields(t, err)["network6"] != "ipv6_off" {
		t.Errorf("a new IPv6 network with IPv6 off: %v", err)
	}
	input = inputOf(server)
	input.Name = "Office renamed"
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Errorf("another change with IPv6 off: %v", err)
	}
	if err := create(func(input *ServerInput) { input.Network6 = "" }); err != nil {
		t.Errorf("an IPv4 server with IPv6 off: %v", err)
	}
}

func TestIPv6Peers(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.Network6 = ""
		input.Networks = []string{"192.168.1.0/24"}
	})
	alice := f.user("alice")
	peer := f.peer(server, alice)
	if peer.Address6 != "" || f.net.State.Servers[0].IPv6() || f.net.State.Servers[0].Peers[0].Address6.IsValid() {
		t.Fatalf("IPv6 without an IPv6 network: %+v %+v", peer, f.net.State.Servers[0])
	}
	if rules := network.Ruleset(f.net.State); !strings.Contains(rules, "chain wg0_forward {\n\t\tmeta nfproto ipv6 drop") {
		t.Errorf("a server without IPv6 doesn't drop it:\n%s", rules)
	}
	if _, text, _ := f.s.PeerConfig(testActor, peer.ID); !strings.Contains(text, "Address = 10.8.0.2/32\n") ||
		!strings.Contains(text, "AllowedIPs = 10.8.0.0/24, 192.168.1.0/24\n") {
		t.Errorf("configuration without IPv6:\n%s", text)
	}

	// IPv6 added while the peer is there: its address follows from the IPv4 one
	input := inputOf(server)
	input.Network6 = "fd00:aaaa:bbbb:7::/64"
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	peers, _ := f.s.Peers(server.ID)
	if peers[0].Address6 != "fd00:aaaa:bbbb:7::2" {
		t.Fatalf("address6 %q", peers[0].Address6)
	}
	applied := f.net.State.Servers[0]
	if applied.Address6.String() != "fd00:aaaa:bbbb:7::1/64" || applied.Peers[0].Address6.String() != "fd00:aaaa:bbbb:7::2" {
		t.Fatalf("applied: %+v", applied)
	}
	if e := f.lastEvent("server_changed"); !strings.Contains(e.Detail, "IPv6 network: none → fd00:aaaa:bbbb:7::/64") {
		t.Errorf("event: %+v", e)
	}
	_, text, _ := f.s.PeerConfig(testActor, peer.ID)
	for _, want := range []string{
		"Address = 10.8.0.2/32, fd00:aaaa:bbbb:7::2/128\n", "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb:7::/64, 192.168.1.0/24\n",
		// the login page stays IPv4: the address Authway and the apps already know
		"# Login = http://10.8.0.1:8181/\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}

	// the login page from the IPv6 address of the peer, opened with the IPv6 address of the server
	address4, address6 := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr(peers[0].Address6)
	host6 := "[fd00:aaaa:bbbb:7::1]:8181"
	f.handshake(&peers[0], "2001:db8:1:2::10")
	if status := f.s.LoginStatus(address6, host6, nil); status.Status != 200 {
		t.Fatalf("status over IPv6: %+v", status)
	}
	for _, host := range []string{"vpn.example.com", "fd00:aaaa:bbbb:7::1", "[fd00:aaaa:bbbb:7::1]:80", "[fd00:aaaa:bbbb:7::2]:8181",
		"[fd00:aaaa:bbbb:7::1%wg0]:8181", "evil.example:8181"} {
		if status := f.s.LoginStatus(address6, host, nil); status.Status != 403 {
			t.Errorf("host %q: %+v", host, status)
		}
	}
	// an address of the IPv6 network that no peer has
	if status := f.s.LoginStatus(netip.MustParseAddr("fd00:aaaa:bbbb:7::9"), host6, nil); status.Status != 403 {
		t.Errorf("another address: %+v", status)
	}
	answer := f.s.Login(address6, host6, LoginRequest{Username: "alice", Password: "Secret,1234"})
	if answer.Status != 200 {
		t.Fatalf("login over IPv6: %+v", answer)
	}
	// the gate opens for both addresses, and a new apply keeps both
	if !f.net.Open("wg0", address4) || !f.net.Open("wg0", address6) {
		t.Fatal("the gate isn't open for both addresses")
	}
	f.s.mu.Lock()
	f.s.applyLocked()
	f.s.mu.Unlock()
	if sessions := f.net.State.Servers[0].Sessions; !slices.Contains(sessions, address4) || !slices.Contains(sessions, address6) {
		t.Errorf("applied sessions: %v", sessions)
	}

	// the strict lock holds for the network: another address of the same /64 is the same device
	f.clock.advance(10 * time.Second)
	f.handshake(&peers[0], "2001:db8:1:2:aaaa::7")
	f.s.Tick()
	if session := f.session(peer.ID); session == nil || session.PausedAt != 0 {
		t.Fatalf("paused by a new address in the same /64: %+v", session)
	}
	f.clock.advance(10 * time.Second)
	f.handshake(&peers[0], "2001:db8:9:9::10")
	f.s.Tick()
	if session := f.session(peer.ID); session == nil || session.PausedAt == 0 || f.net.Open("wg0", address4) || f.net.Open("wg0", address6) {
		t.Fatalf("another network: %+v", session)
	}
	f.clock.advance(10 * time.Second)
	f.handshake(&peers[0], "2001:db8:1:2::10")
	f.s.Tick()
	if !f.net.Open("wg0", address4) || !f.net.Open("wg0", address6) {
		t.Fatal("not resumed on both addresses")
	}
	if answer := f.s.Logout(address6, host6); answer.Status != 200 || f.net.Open("wg0", address4) || f.net.Open("wg0", address6) {
		t.Fatalf("logout: %+v", answer)
	}

	// IPv6 taken away: the peer has no IPv6 address any more, the tunnel drops it again
	input.Network6 = ""
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	if peers, _ := f.s.Peers(server.ID); peers[0].Address6 != "" || f.net.State.Servers[0].IPv6() {
		t.Errorf("after IPv6 is taken away: %+v %+v", peers[0], f.net.State.Servers[0])
	}
}

// the devices of one IPv6 network have many addresses of its /64: they count as one, for the failed logins and the
// copies, as the devices behind one IPv4 NAT
func TestIPv6Networks(t *testing.T) {
	l := newLoginFailures()
	now := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	var locked []string
	for index := 1; index <= MaxFailures; index++ {
		locked = l.add(1, fmt.Sprintf("2001:db8:1:2::%x", index), now)
	}
	if strings.Join(locked, ",") != "2001:db8:1:2::/64" {
		t.Errorf("locked out: %v", locked)
	}
	if _, out := l.lockedUntil(1, "2001:db8:1:2:ffff::1", now); !out {
		t.Error("another address of the /64 isn't locked out")
	}
	if _, out := l.lockedUntil(1, "2001:db8:1:3::1", now); out {
		t.Error("another /64 is locked out")
	}

	f := setup(t)
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.user("alice"))
	if a := f.login(peer, "2001:db8:1:2::10"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	// back and forth between two addresses of one network: no copy
	for _, ip := range []string{"2001:db8:1:2::11", "2001:db8:1:2::10", "2001:db8:1:2::11", "2001:db8:1:2::10"} {
		f.clock.advance(10 * time.Second)
		f.handshake(peer, ip)
		f.s.Tick()
	}
	if alerts, _ := f.s.Alerts(peer.ID, 10); len(alerts) != 0 {
		t.Fatalf("one network is a copy: %+v", alerts)
	}
	// between two networks: a copy, the networks in the alert
	for _, ip := range []string{"2001:db8:9:9::1", "2001:db8:1:2::10", "2001:db8:9:9::1", "2001:db8:1:2::10"} {
		f.clock.advance(10 * time.Second)
		f.handshake(peer, ip)
		f.s.Tick()
	}
	alerts, _ := f.s.Alerts(peer.ID, 10)
	if len(alerts) != 1 || strings.Join(alerts[0].Addresses, ",") != "2001:db8:1:2::/64,2001:db8:9:9::/64" {
		t.Fatalf("alerts: %+v", alerts)
	}
}

// a backup has the IPv6 networks, and one of version 2, without them, still restores
func TestIPv6Backup(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	f.peer(office, f.user("alice"))
	before := f.snapshot()
	if before.Servers[0].Network6 != "fd00:aaaa:bbbb::/64" {
		t.Fatalf("server %+v", before.Servers[0])
	}
	data := f.sealed(adminID, func(c *backupContent) {
		if c.Version != BackupVersion || c.Servers[0].Network6 != "fd00:aaaa:bbbb::/64" {
			t.Fatalf("content: %d %+v", c.Version, c.Servers[0])
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if after := f.snapshot(); !reflect.DeepEqual(before.Servers, after.Servers) || !reflect.DeepEqual(before.Peers, after.Peers) {
		t.Fatalf("restored:\n%+v\n%+v", before.Servers, after.Servers)
	}
	older := f.sealed(adminID, func(c *backupContent) {
		c.Version = 2
		for index := range c.Servers {
			c.Servers[index].Network6 = ""
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", older, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if servers, _ := f.db.Q().Servers(); servers[0].Network6 != "" {
		t.Errorf("version 2: %+v", servers[0])
	}
	bad := f.sealed(adminID, func(c *backupContent) { c.Servers[0].Network6 = "fe80::/64" })
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", bad, testPassphrase); err == nil {
		t.Error("a link-local network restores")
	}
}
