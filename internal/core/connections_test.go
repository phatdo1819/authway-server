package core

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

func TestConnections(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthKey)
	peer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "phone", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	key := keyOf(peer.PublicKey)
	set := func(key wgtypes.Key, from string, received, sent int64, handshake time.Time) {
		stats := network.PeerStats{Interface: "wg0", LastHandshake: handshake, Received: received, Sent: sent}
		if from != "" {
			stats.Endpoint = netip.MustParseAddrPort(from + ":40000")
		}
		f.net.SetPeer(key, stats)
	}
	pass := func() {
		f.clock.advance(RecordInterval)
		f.s.Tick()
	}
	list := func() []ConnectionView {
		connections, err := f.s.Connections(10)
		if err != nil {
			t.Fatal(err)
		}
		return connections
	}

	// configured, never connected
	set(key, "", 0, 0, time.Time{})
	pass()
	if len(list()) != 0 {
		t.Fatalf("a peer that never connected: %+v", list())
	}
	start := f.clock.now
	set(key, "203.0.113.5", 100, 200, start)
	pass()
	first := list()
	if len(first) != 1 || !first[0].Connected || first[0].StartedAt != start.Unix() || first[0].Received != 100 ||
		first[0].Sent != 200 || first[0].Endpoint != "203.0.113.5" || first[0].PeerName != "phone" || first[0].LastSeen != f.clock.now.Unix() {
		t.Fatalf("connected: %+v", first)
	}
	set(key, "203.0.113.5", 1100, 2200, f.clock.now)
	pass()
	seen := f.clock.now.Unix()
	if c := list()[0]; c.Received != 1100 || c.Sent != 2200 || c.LastSeen != seen {
		t.Fatalf("the counters: %+v", c)
	}
	// nothing new: the latest change stays
	pass()
	if c := list()[0]; c.LastSeen != seen || !c.Connected {
		t.Fatalf("idle: %+v", c)
	}

	// another network: a new connection, the bytes since the latest pass are its own
	set(key, "198.51.100.7", 1500, 2600, f.clock.now)
	pass()
	moved := list()
	if len(moved) != 2 || !moved[0].Connected || moved[0].Endpoint != "198.51.100.7" || moved[0].Received != 400 ||
		moved[0].Sent != 400 || moved[1].Connected || moved[1].EndedAt != seen {
		t.Fatalf("moved: %+v", moved)
	}
	// the interface started again: its counters too
	set(key, "198.51.100.7", 50, 60, f.clock.now)
	pass()
	if again := list(); len(again) != 3 || again[0].Received != 50 || again[0].Sent != 60 || again[1].Connected {
		t.Fatalf("a restart of the interface: %+v", again)
	}

	// the device gives the peer its own key: another peer for WireGuard, the same connection
	private, _ := wgtypes.GeneratePrivateKey()
	device := private.PublicKey()
	if err := f.db.Q().SaveDevice(&store.Device{PeerID: peer.ID, Key: "enrolled", WireGuardKey: device.String()}); err != nil {
		t.Fatal(err)
	}
	delete(f.net.Peers, key)
	set(device, "198.51.100.7", 5, 7, f.clock.now)
	pass()
	if same := list(); len(same) != 3 || !same[0].Connected || same[0].Received != 55 || same[0].Sent != 67 {
		t.Fatalf("the key of the device: %+v", same)
	}

	// gone: no handshake for 3 minutes
	last := f.clock.now.Unix()
	f.clock.advance(ConnectedWindow)
	pass()
	if left := list(); left[0].Connected || left[0].EndedAt != last {
		t.Fatalf("left: %+v", left)
	}

	// a disabled peer ends its connection at once
	set(device, "198.51.100.7", 9, 9, f.clock.now)
	pass()
	if c := list()[0]; !c.Connected {
		t.Fatalf("back: %+v", c)
	}
	if _, err := f.s.UpdatePeer(testActor, peer.ID, PeerInput{Name: "phone", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	pass()
	if c := list()[0]; c.Connected {
		t.Fatalf("disabled: %+v", c)
	}

	// a restart: the interfaces are new, the connections of before ended
	if _, err := f.s.UpdatePeer(testActor, peer.ID, PeerInput{Name: "phone", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	set(device, "198.51.100.7", 20, 20, f.clock.now)
	pass()
	if c := list()[0]; !c.Connected {
		t.Fatalf("enabled again: %+v", c)
	}
	if _, err := New(f.db, f.net, Options{Now: f.clock.Now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	for _, c := range list() {
		if c.Connected {
			t.Fatalf("open after a restart: %+v", c)
		}
	}
}

func TestPeerTraffic(t *testing.T) {
	f := setup(t)
	a := f.server(store.AuthKey)
	b := f.server(store.AuthKey)
	c := f.server(store.AuthKey)
	peers := map[int64]*PeerView{}
	for _, server := range []*ServerView{a, b, c} {
		peer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "laptop", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		peers[server.ID] = peer
	}
	input := inputOf(a)
	input.ClientToClient = true
	input.ReachableServers = []int64{b.ID}
	a, err := f.s.UpdateServer(testActor, a.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ClientToClient || len(a.Reachable) != 1 || a.Reachable[0] != b.ID {
		t.Fatalf("server %+v", a)
	}
	state := f.net.State.Servers
	if !state[0].ClientToClient || strings.Join(state[0].Reaches, ",") != "wg1" || state[1].ClientToClient ||
		len(state[1].Reaches) != 0 {
		t.Fatalf("applied: %+v", state)
	}
	allowed := func(server *ServerView) string {
		_, text, err := f.s.PeerConfig(testActor, peers[server.ID].ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "AllowedIPs = ") {
				return strings.TrimPrefix(line, "AllowedIPs = ")
			}
		}
		return ""
	}
	// the peers of a route the network of b; the ones of b route a for their answers; c is out of it
	if got := allowed(a); got != "10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/24, 10.8.1.0/24, fd00:aaaa:bbbb:1::/64" {
		t.Fatalf("a: %s", got)
	}
	if got := allowed(b); got != "10.8.1.0/24, fd00:aaaa:bbbb:1::/64, 192.168.1.0/24, 10.8.0.0/24, fd00:aaaa:bbbb::/64" {
		t.Fatalf("b: %s", got)
	}
	if got := allowed(c); got != "10.8.2.0/24, fd00:aaaa:bbbb:2::/64, 192.168.1.0/24" {
		t.Fatalf("c: %s", got)
	}

	for _, test := range []struct {
		list []int64
		code string
	}{
		{[]int64{a.ID}, "same_server"},
		{[]int64{999}, "server_not_found"},
		{[]int64{b.ID, b.ID}, "duplicate_server"},
	} {
		input.ReachableServers = test.list
		if _, err := f.s.UpdateServer(testActor, a.ID, input); fields(t, err)["reachable_servers"] != test.code {
			t.Fatalf("%v: %v", test.list, err)
		}
	}

	// a disabled server has no interface to reach
	disabled := inputOf(b)
	disabled.Enabled = false
	if _, err := f.s.UpdateServer(testActor, b.ID, disabled); err != nil {
		t.Fatal(err)
	}
	if len(f.net.State.Servers) != 2 || len(f.net.State.Servers[0].Reaches) != 0 {
		t.Fatalf("b disabled: %+v", f.net.State.Servers)
	}
	if err := f.s.DeleteServer(testActor, b.ID); err != nil {
		t.Fatal(err)
	}
	if after, _ := f.s.Server(a.ID); len(after.Reachable) != 0 || !after.ClientToClient {
		t.Fatalf("b deleted: %+v", after)
	}
	if got := allowed(a); got != "10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/24" {
		t.Fatalf("a after the deletion of b: %s", got)
	}
}

// SQLite gives a new peer the id of the latest one deleted: the history doesn't go on with it
func TestConnectionsReusedID(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthKey)
	old, _ := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "old", Enabled: true})
	connect := func(peer *PeerView) {
		f.net.SetPeer(keyOf(peer.PublicKey), network.PeerStats{Interface: "wg0", Endpoint: netip.MustParseAddrPort("203.0.113.5:40000"),
			LastHandshake: f.clock.now, Received: 100, Sent: 100})
		f.clock.advance(RecordInterval)
		f.s.Tick()
	}
	connect(old)
	if err := f.s.DeletePeer(testActor, old.ID); err != nil {
		t.Fatal(err)
	}
	delete(f.net.Peers, keyOf(old.PublicKey))
	reused, _ := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "new", Enabled: true})
	if reused.ID != old.ID || reused.Address != old.Address {
		t.Skipf("the id or the address isn't reused: %d %s", reused.ID, reused.Address)
	}
	connect(reused)
	list, _ := f.s.Connections(10)
	if len(list) != 2 || list[0].PeerName != "new" || !list[0].Connected || list[1].PeerName != "old" || list[1].Connected {
		t.Fatalf("connections %+v", list)
	}
}
