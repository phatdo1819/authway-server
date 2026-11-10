package core

import (
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// A peer is connected while its handshake is younger than ConnectedWindow and, with the keepalive of its server, while
// it sends something at least every two keepalives: gone, it shows offline within a minute. Without a keepalive an
// idle peer sends nothing, and only the handshake counts.
func TestPeerOffline(t *testing.T) {
	f := setup(t)
	office := f.server(store.AuthKey)
	if office.Keepalive != 25 {
		t.Fatalf("keepalive %d", office.Keepalive)
	}
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "laptop", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := wgtypes.ParseKey(peer.PublicKey)
	handshake := f.clock.now
	sends := func(received int64) {
		f.net.SetPeer(key, network.PeerStats{Interface: office.Interface, Endpoint: netip.MustParseAddrPort("203.0.113.5:40000"),
			LastHandshake: handshake, Received: received})
		f.s.Tick()
	}
	connected := func(at string, want bool) {
		t.Helper()
		if view := f.peerView(peer.ID); view.Connected != want {
			t.Errorf("%s: connected %v", at, view.Connected)
		}
	}

	sends(148)
	connected("the handshake", true)
	f.clock.advance(30 * time.Second)
	sends(180)
	connected("a keepalive", true)
	// one keepalive lost: still there
	f.clock.advance(50 * time.Second)
	sends(180)
	connected("50 seconds without anything", true)
	// gone: offline after two keepalives and a tick, long before the 3 minutes of the handshake
	f.clock.advance(10 * time.Second)
	sends(180)
	connected("a minute without anything", false)
	f.clock.advance(5 * time.Second)
	sends(212)
	connected("back", true)
	// a new handshake is the peer answering too
	f.clock.advance(time.Minute)
	handshake = f.clock.now
	sends(212)
	connected("a new handshake", true)

	// no keepalive: an idle peer sends nothing, only the handshake counts
	input := inputOf(office)
	input.Keepalive = 0
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(2 * time.Minute)
	sends(212)
	connected("idle without a keepalive", true)
	f.clock.advance(time.Minute)
	sends(212)
	connected("the handshake 3 minutes old", false)
}

// WireGuard forgets the handshakes when the container starts again: the view gives the latest time the history saw the
// peer, and from where. A new peer with the id of a deleted one doesn't get its history.
func TestLastSeen(t *testing.T) {
	f := setup(t)
	office := f.server(store.AuthKey)
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "laptop", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := wgtypes.ParseKey(peer.PublicKey)
	f.net.SetPeer(key, network.PeerStats{Interface: office.Interface, Endpoint: netip.MustParseAddrPort("203.0.113.5:40000"),
		LastHandshake: f.clock.now, Received: 148, Sent: 92})
	f.s.Tick()
	seen := f.clock.now.Unix()
	if view := f.peerView(peer.ID); view.LastHandshake != seen || view.LastSeen != 0 {
		t.Fatalf("connected: %+v", view)
	}

	// the container started again: WireGuard has the peer, without a handshake
	f.clock.advance(time.Hour)
	f.net.SetPeer(key, network.PeerStats{Interface: office.Interface})
	f.s.Tick()
	view := f.peerView(peer.ID)
	if view.LastHandshake != 0 || view.LastSeen != seen || view.LastEndpoint != "203.0.113.5" || view.Connected {
		t.Fatalf("after a restart: %+v", view)
	}

	// deleted, and a new peer with its id: never seen
	if err := f.s.DeletePeer(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	again, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "phone", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != peer.ID {
		t.Logf("a new id: %d, not %d", again.ID, peer.ID)
	}
	if view := f.peerView(again.ID); view.LastSeen != 0 || view.LastEndpoint != "" {
		t.Errorf("the history of another peer: %+v", view)
	}
}
