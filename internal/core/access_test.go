package core

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/store"
)

func access(list ...string) *[]string {
	return &list
}

// A peer reaches all the networks of its server, or only those of its access rules, inside them: checked, kept, in the
// view, the events, the firewall, its configuration file and the backups. The networks of the server keep what the
// rules of its peers reach.
func TestAccessRules(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "10.20.0.0/16", "fd00:5::/64"}
	input.DNS = []string{"192.168.1.1", "1.1.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	alice := f.user("alice")
	peerInput := PeerInput{Name: "alice laptop", Enabled: true, UserID: alice.ID}

	// refused: not a network, outside the networks of the server, overlapping, blank, too many
	many := []string{}
	for index := range MaxNetworks + 1 {
		many = append(many, fmt.Sprintf("192.168.1.%d", index))
	}
	for _, test := range []struct {
		access []string
		code   string
	}{
		{[]string{"printer"}, "invalid"},
		{[]string{"0.0.0.0/0"}, "invalid"},
		{[]string{"172.16.0.0/16"}, "outside"},
		{[]string{"192.168.0.0/16"}, "outside"},
		{[]string{"fd00:6::1"}, "outside"},
		{[]string{"192.168.1.0/28", "192.168.1.8/29"}, "overlap"},
		{[]string{" ", ""}, "required"},
		{many, "too_many"},
	} {
		peerInput.Access = &test.access
		if _, err := f.s.CreatePeer(testActor, office.ID, peerInput); fields(t, err)["access"] != test.code {
			t.Errorf("%v: %v, not %s", test.access, err, test.code)
		}
	}

	// a host, a network and an IPv6 host
	peerInput.Access = access(" 192.168.1.10 ", "10.20.5.0/24", "fd00:5::20")
	peer, err := f.s.CreatePeer(testActor, office.ID, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"192.168.1.10/32", "10.20.5.0/24", "fd00:5::20/128"}
	if !slices.Equal(peer.Access, expected) {
		t.Fatalf("view: %v", peer.Access)
	}
	if e := f.lastEvent("peer_added"); !strings.Contains(e.Detail, "reaches 192.168.1.10/32, 10.20.5.0/24, fd00:5::20/128") {
		t.Errorf("event: %+v", e)
	}
	// the firewall: its rules; the DNS servers of the server to ask
	state := f.net.State.Servers[0]
	if len(state.Peers) != 1 || len(state.Peers[0].Access) != 3 || state.Peers[0].Access[0] != netip.MustParsePrefix("192.168.1.10/32") ||
		len(state.DNS) != 2 {
		t.Fatalf("state: %+v", state)
	}
	// its configuration file routes its networks and the DNS server inside the networks of the server
	_, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.10/32, 10.20.5.0/24, fd00:5::20/128, 192.168.1.1/32\n") {
		t.Errorf("configuration file:\n%s", text)
	}

	// missing from the input: kept, so an older web UI doesn't take them away
	peerInput.Access = nil
	peerInput.Name = "laptop"
	if view, err := f.s.UpdatePeer(testActor, peer.ID, peerInput); err != nil || !slices.Equal(view.Access, expected) {
		t.Fatalf("kept: %v %v", view, err)
	}
	// the networks of the server can't leave them out
	narrower := inputOf(office)
	narrower.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
	if _, err := f.s.UpdateServer(testActor, office.ID, narrower); fields(t, err)["networks"] != "in_peer_access" {
		t.Errorf("networks without the ones of a peer: %v", err)
	}
	narrower.Networks = []string{"192.168.1.0/25", "10.20.0.0/16", "fd00:5::/64"}
	if _, err := f.s.UpdateServer(testActor, office.ID, narrower); err != nil {
		t.Errorf("networks that keep the ones of the peers: %v", err)
	}

	// the backups keep them, and refuse what isn't valid
	data := f.sealed(adminID, func(c *backupContent) {
		if c.Version != BackupVersion || !slices.Equal(c.Peers[0].Access, expected) {
			t.Fatalf("content: %+v", c.Peers[0])
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if peers, _ := f.db.Q().Peers(0); !slices.Equal(peers[0].Access, expected) {
		t.Errorf("restored: %+v", peers[0])
	}
	for _, wrong := range [][]string{{"172.16.0.0/16"}, {"printer"}} {
		data = f.sealed(adminID, func(c *backupContent) { c.Peers[0].Access = wrong })
		if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err == nil ||
			!strings.Contains(err.Error(), "access rules") {
			t.Errorf("%v restored: %v", wrong, err)
		}
	}

	// an empty list: all the networks again
	peerInput.Access = access()
	view, err := f.s.UpdatePeer(testActor, peer.ID, peerInput)
	if err != nil || view.Access == nil || len(view.Access) != 0 {
		t.Fatalf("all again: %+v %v", view, err)
	}
	if e := f.lastEvent("peer_changed"); !strings.Contains(e.Detail, "reaches: 192.168.1.10/32, 10.20.5.0/24, fd00:5::20/128 → all the networks") {
		t.Errorf("event: %+v", e)
	}
	if f.net.State.Servers[0].Peers[0].Access != nil {
		t.Errorf("state: %+v", f.net.State.Servers[0].Peers[0])
	}
	if _, text, _ = f.s.PeerConfig(testActor, peer.ID); !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/25, 10.20.0.0/16, fd00:5::/64\n") {
		t.Errorf("configuration file:\n%s", text)
	}
}

// What the firewall gets: only the rules still inside the networks of the server; a peer with rules and nothing left
// reaches none of them, not all.
func TestPeerAccess(t *testing.T) {
	networks := parsePrefixes([]string{"192.168.1.0/24"})
	if got := peerAccess(&store.Peer{}, networks); got != nil {
		t.Errorf("all: %v", got)
	}
	got := peerAccess(&store.Peer{Access: []string{"192.168.1.10/32", "172.16.0.0/16"}}, networks)
	if len(got) != 1 || got[0] != netip.MustParsePrefix("192.168.1.10/32") {
		t.Errorf("inside: %v", got)
	}
	if got := peerAccess(&store.Peer{Access: []string{"172.16.0.0/16"}}, networks); got == nil || len(got) != 0 {
		t.Errorf("nothing left: %v", got)
	}
}
