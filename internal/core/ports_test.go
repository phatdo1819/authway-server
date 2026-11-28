package core

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// Access rules with ports: checked and kept as network.Ports writes them; in the firewall apart from the rules without
// ports, which they can overlap; not in the configuration file, which routes their addresses all the same. A name with
// ports learns its addresses for that traffic only, each name for the ports of all its rules, and a restart keeps it.
func TestAccessRulesWithPorts(t *testing.T) {
	f := setup(t)
	f.admin()
	addr := netip.MustParseAddr
	office := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24", "10.20.0.0/16", "fd00:5::/64"}
		input.DNS = []string{"192.168.1.1"}
	})
	alice, bob := f.user("alice"), f.user("bob")
	peerInput := PeerInput{Name: "alice laptop", Enabled: true, UserID: alice.ID}
	for _, test := range []struct {
		access []string
		code   string
	}{
		{[]string{"192.168.1.5 tcp/0"}, "invalid_ports"},
		{[]string{"192.168.1.5 http"}, "invalid_ports"},
		{[]string{"192.168.1.5 tcp/80 sctp"}, "invalid_ports"},
		{[]string{"files.corp.lan tcp/x"}, "invalid_ports"},
		{[]string{"192.168.1.5 tcp/90-80"}, "invalid_ports"},
		{[]string{"printer tcp/80"}, "invalid"},
		{[]string{"172.16.0.1 tcp/22"}, "outside"},
		// without ports, still one rule: no overlap
		{[]string{"192.168.1.0/28", "192.168.1.8/29"}, "overlap"},
	} {
		peerInput.Access = &test.access
		if _, err := f.s.CreatePeer(testActor, office.ID, peerInput); fields(t, err)["access"] != test.code {
			t.Errorf("%v: %v, not %s", test.access, err, test.code)
		}
	}
	peerInput.Access = access("192.168.1.0/24 TCP/443,80", " 192.168.1.5  tcp/3389 icmp ", "192.168.1.5 icmp tcp/3389",
		"192.168.1.0/28", "files.corp.lan tcp/445", "*.corp.lan tcp/80", "*.apps.lan udp/53 tcp/443", "fd00:5::5 tcp/22")
	peer, err := f.s.CreatePeer(testActor, office.ID, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"192.168.1.0/24 tcp/80,443", "192.168.1.5/32 tcp/3389 icmp", "192.168.1.0/28", "files.corp.lan tcp/445",
		"*.corp.lan tcp/80", "*.apps.lan tcp/443 udp/53", "fd00:5::5/128 tcp/22"}
	if !slices.Equal(peer.Access, expected) {
		t.Fatalf("kept as %q", peer.Access)
	}
	if e := f.lastEvent("peer_added"); !strings.Contains(e.Detail, "reaches 192.168.1.0/24 tcp/80,443, 192.168.1.5/32 tcp/3389 icmp,") {
		t.Errorf("event: %+v", e)
	}
	state := f.net.State.Servers[0].Peers[0]
	texts := func(list []network.Ports) []string {
		var out []string
		for _, ports := range list {
			out = append(out, ports.String())
		}
		return out
	}
	if !slices.Equal(state.Access, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/28")}) || len(state.AccessPorts) != 3 ||
		state.AccessPorts[1].Prefix != netip.MustParsePrefix("192.168.1.5/32") || state.AccessPorts[1].Ports.String() != "tcp/3389 icmp" ||
		!state.Names || !slices.Equal(texts(state.NamePorts), []string{"tcp/445", "tcp/80", "tcp/443 udp/53"}) {
		t.Fatalf("state: %+v", state)
	}

	// another peer, without names: its file routes the addresses of the rules with ports too
	other, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "bob laptop", Enabled: true, UserID: bob.ID,
		Access: access("192.168.1.5 tcp/3389", "10.20.5.0/24", "10.20.5.7 udp/161")})
	if err != nil {
		t.Fatal(err)
	}
	_, text, err := f.s.PeerConfig(testActor, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.5/32, 10.20.5.0/24, 10.20.5.7/32, 192.168.1.1/32\n") {
		t.Errorf("configuration file:\n%s", text)
	}

	// the names learn for the ports of their rules: files.corp.lan for those of its own rule and of *.corp.lan
	if answer := f.login(peer, "203.0.113.7"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	address := addr(peer.Address)
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.20 600"))
	f.s.learn(address, answer(t, "intra.corp.lan.", "A 192.168.1.21 600"))
	f.s.learn(address, answer(t, "x.apps.lan.", "A 10.20.0.9 600"))
	for _, test := range []struct {
		address, ports string
		reaches        bool
	}{
		{"192.168.1.20", "tcp/445", true},
		{"192.168.1.20", "tcp/80", true},
		{"192.168.1.20", "", false},
		{"192.168.1.21", "tcp/80", true},
		{"192.168.1.21", "tcp/445", false},
		{"10.20.0.9", "tcp/443 udp/53", true},
		{"10.20.0.9", "", false},
	} {
		if f.net.ReachesPorts("wg0", address, addr(test.address), test.ports) != test.reaches {
			t.Errorf("%s for %q: not %v", test.address, test.ports, test.reaches)
		}
	}
	// and the firewall gets them at the next Apply
	f.s.mu.Lock()
	f.s.applyLocked()
	f.s.mu.Unlock()
	learned := f.net.State.Servers[0].Peers[0].LearnedPorts
	if !slices.Equal(learned["tcp/445"], []netip.Addr{addr("192.168.1.20")}) ||
		!slices.Equal(learned["tcp/80"], []netip.Addr{addr("192.168.1.20"), addr("192.168.1.21")}) ||
		len(f.net.State.Servers[0].Peers[0].Learned) != 0 {
		t.Errorf("state: %+v", f.net.State.Servers[0].Peers[0])
	}

	// a rule of the name without ports: all the traffic, the ports of the others no longer matter
	update := PeerInput{Name: peer.Name, Enabled: true, UserID: alice.ID,
		Access: access("files.corp.lan tcp/445", "*.corp.lan"), Version: f.peerView(peer.ID).Version}
	peer, err = f.s.UpdatePeer(testActor, peer.ID, update)
	if err != nil {
		t.Fatal(err)
	}
	if answer := f.login(peer, "203.0.113.7"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.22 600"))
	if !f.net.Reaches("wg0", address, addr("192.168.1.22")) || f.net.ReachesPorts("wg0", address, addr("192.168.1.22"), "tcp/445") {
		t.Errorf("a rule without ports: %+v", f.net.Learned)
	}

	// a restart keeps both kinds
	update.Access = access("files.corp.lan tcp/445", "*.apps.lan")
	update.Version = f.peerView(peer.ID).Version
	if peer, err = f.s.UpdatePeer(testActor, peer.ID, update); err != nil {
		t.Fatal(err)
	}
	if answer := f.login(peer, "203.0.113.7"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.23 600"))
	f.s.learn(address, answer(t, "y.apps.lan.", "A 10.20.0.10 600"))
	f.s.Close()
	if text, _ := f.db.Q().Meta(metaNames); !strings.Contains(text, `"192.168.1.23 tcp/445"`) || !strings.Contains(text, `"10.20.0.10"`) {
		t.Fatalf("saved: %s", text)
	}
	fake := network.NewFake()
	if _, err := New(f.db, fake, Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log}); err != nil {
		t.Fatal(err)
	}
	if !fake.ReachesPorts("wg0", address, addr("192.168.1.23"), "tcp/445") || fake.Reaches("wg0", address, addr("192.168.1.23")) ||
		!fake.Reaches("wg0", address, addr("10.20.0.10")) {
		t.Errorf("after a restart: %+v", fake.Learned)
	}
}

// The settings of a peer for the Authway app: its file without its keys, only once logged in, as it is now, and never
// an event.
func TestPeerSettings(t *testing.T) {
	f := setup(t)
	f.admin()
	office := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24"}
		input.DNS = []string{"192.168.1.1"}
	})
	peer := f.peer(office, f.user("alice"))
	address := netip.MustParseAddr(peer.Address)
	if a := f.s.PeerSettings(address, "10.8.0.1"); a.Status != 401 || a.Body["error"] != "not_authenticated" {
		t.Fatalf("before the login: %+v", a)
	}
	if a := f.s.PeerSettings(address, "files.corp.lan"); a.Status != 403 {
		t.Fatalf("another host: %+v", a)
	}
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	settings := func() string {
		t.Helper()
		a := f.s.PeerSettings(address, "10.8.0.1")
		text, _ := a.Body["config"].(string)
		if a.Status != 200 || text == "" {
			t.Fatalf("settings: %+v", a)
		}
		return text
	}
	text := settings()
	_, file, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	// the file, without the two lines of its keys
	var kept []string
	for _, line := range strings.Split(file, "\n") {
		if !strings.HasPrefix(line, "PrivateKey = ") && !strings.HasPrefix(line, "PresharedKey = ") {
			kept = append(kept, line)
		}
	}
	if text != strings.Join(kept, "\n") || strings.Contains(text, "Key = ") != strings.Contains(text, "PublicKey = ") {
		t.Fatalf("settings:\n%s\nfile:\n%s", text, file)
	}
	events := len(f.eventKinds("peer_config"))
	// new rules: new settings at once
	update := PeerInput{Name: peer.Name, Enabled: true, UserID: peer.UserID, Access: access("192.168.1.5 tcp/3389"),
		Version: f.peerView(peer.ID).Version}
	if _, err := f.s.UpdatePeer(testActor, peer.ID, update); err != nil {
		t.Fatal(err)
	}
	if text := settings(); !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.5/32, 192.168.1.1/32\n") {
		t.Errorf("after the change:\n%s", text)
	}
	if len(f.eventKinds("peer_config")) != events {
		t.Error("the settings are an event")
	}
}
