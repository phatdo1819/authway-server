package core

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// A change of the rules of a peer forgets only what the names whose rules changed taught it, and closes only its
// connections to those addresses: the rest stays open, with its connections. An address that two names taught stays
// while one of them is still in the rules with the same ports, as long as that one holds it open. A restart keeps the
// names; an address saved without them (an older version) goes at the next change.
func TestRuleChangesForgetOnlyTheirNames(t *testing.T) {
	f := setup(t)
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	addr := netip.MustParseAddr
	office := f.server(store.AuthKey)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24"}
	input.DNS = []string{"192.168.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	update := PeerInput{Name: "kiosk", Enabled: true,
		Access: access("files.corp.lan tcp/445", "db.corp.lan", "*.apps.lan", "y.apps.lan", "app.example.com tcp/443",
			"192.168.1.10")}
	peer, err := f.s.CreatePeer(testActor, office.ID, update)
	if err != nil {
		t.Fatal(err)
	}
	address := addr(peer.Address)
	learnedAt := f.clock.Now()
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.20 600"))
	f.s.learn(address, answer(t, "db.corp.lan.", "A 192.168.1.30 600"))
	// one address, two names
	f.s.learn(address, answer(t, "x.apps.lan.", "A 192.168.1.40 900"))
	f.s.learn(address, answer(t, "y.apps.lan.", "A 192.168.1.40 300"))
	records := replyRecords(t, f.s.learn(address, answer(t, "app.example.com.", "A 203.0.113.10 600")))
	if len(records) != 1 || !strings.HasPrefix(records[0], "A 198.18.") {
		t.Fatalf("answer: %v", records)
	}
	standIn := addr(strings.TrimPrefix(records[0], "A "))
	reaches := func(target netip.Addr, ports string) bool { return f.net.ReachesPorts("wg0", address, target, ports) }
	if !reaches(addr("192.168.1.20"), "tcp/445") || !reaches(addr("192.168.1.30"), "") ||
		!reaches(addr("192.168.1.40"), "") || !reaches(standIn, "tcp/443") {
		t.Fatalf("learned: %+v", f.net.Learned)
	}
	change := func(rules ...string) {
		t.Helper()
		f.net.Forgotten, f.net.ForgottenTo = nil, nil
		update.Access = access(rules...)
		update.Version = f.peerView(peer.ID).Version
		if _, err := f.s.UpdatePeer(testActor, peer.ID, update); err != nil {
			t.Fatal(err)
		}
	}

	// an address rule changes: no name forgotten, no connection closed
	change("files.corp.lan tcp/445", "db.corp.lan", "*.apps.lan", "y.apps.lan", "app.example.com tcp/443", "192.168.1.11")
	if len(f.net.Forgotten) != 0 || len(f.net.ForgottenTo) != 0 || !reaches(addr("192.168.1.20"), "tcp/445") ||
		!reaches(addr("192.168.1.30"), "") || !reaches(addr("192.168.1.40"), "") || !reaches(standIn, "tcp/443") {
		t.Fatalf("after an address rule changed: %v %v %+v", f.net.Forgotten, f.net.ForgottenTo, f.net.Learned)
	}

	// files.corp.lan gets other ports, db.corp.lan and *.apps.lan go: their addresses close, with their connections
	// only; 192.168.1.40 stays for y.apps.lan, until its own answer runs out
	change("files.corp.lan tcp/445,3389", "y.apps.lan", "app.example.com tcp/443", "192.168.1.11")
	want := []network.Learned{{Peer: address, Address: addr("192.168.1.20")},
		{Peer: address, Address: addr("192.168.1.30")}}
	if len(f.net.Forgotten) != 0 || !slices.Equal(f.net.ForgottenTo, want) {
		t.Errorf("closed: %v %v", f.net.Forgotten, f.net.ForgottenTo)
	}
	if reaches(addr("192.168.1.20"), "tcp/445") || reaches(addr("192.168.1.30"), "") ||
		!reaches(addr("192.168.1.40"), "") || !reaches(standIn, "tcp/443") {
		t.Errorf("after the names changed: %+v", f.net.Learned)
	}
	until := f.s.learned[peer.ID].until[learnedKey{addr("192.168.1.40"), ""}]
	if !until.Equal(learnedAt.Add(300*time.Second + LearnedMargin)) {
		t.Errorf("192.168.1.40 open until %v, not y.apps.lan's time", until)
	}
	// a new answer opens files.corp.lan with its ports of now
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.20 600"))
	if !reaches(addr("192.168.1.20"), "tcp/445,3389") {
		t.Errorf("learned again: %+v", f.net.Learned)
	}

	// the internet name goes: its stand-in address closes, the rest stays
	change("files.corp.lan tcp/445,3389", "y.apps.lan", "192.168.1.11")
	if !slices.Equal(f.net.ForgottenTo, []network.Learned{{Peer: address, Address: standIn}}) || reaches(standIn, "tcp/443") ||
		!reaches(addr("192.168.1.20"), "tcp/445,3389") || !reaches(addr("192.168.1.40"), "") {
		t.Errorf("after the internet name went: %v %+v", f.net.ForgottenTo, f.net.Learned)
	}

	// a restart keeps the names of each address
	f.s.Close()
	restart := func() *Service {
		t.Helper()
		s, err := New(f.db, network.NewFake(), Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log,
			StandIns: netip.MustParsePrefix("198.18.0.0/16")})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := restart()
	s.mu.Lock()
	entry := s.learned[peer.ID]
	if entry == nil || len(entry.from[learnedKey{addr("192.168.1.40"), ""}]) != 1 ||
		entry.from[learnedKey{addr("192.168.1.40"), ""}]["y.apps.lan"].IsZero() ||
		entry.from[learnedKey{addr("192.168.1.20"), "tcp/445,3389"}]["files.corp.lan"].IsZero() {
		t.Errorf("after a restart: %+v", entry)
	}
	s.mu.Unlock()
	s.Close()

	// saved by an older version, without the names: they go at the next change of the rules
	text, err := f.db.Q().Meta(metaNames)
	if err != nil {
		t.Fatal(err)
	}
	var saved savedNames
	if err := json.Unmarshal([]byte(text), &saved); err != nil || len(saved.Peers) != 1 || len(saved.Peers[0].Names) == 0 {
		t.Fatalf("saved: %v %s", err, text)
	}
	saved.Peers[0].Names = nil
	data, _ := json.Marshal(saved)
	if err := f.db.Q().SetMeta(metaNames, string(data)); err != nil {
		t.Fatal(err)
	}
	s = restart()
	defer s.Close()
	stored, err := f.db.Q().Peer(peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.learned[peer.ID].until) != 2 {
		t.Fatalf("read back: %+v", s.learned[peer.ID])
	}
	if closed := s.forgetChangedNamesLocked(stored); len(closed) != 2 || s.learned[peer.ID] != nil {
		t.Errorf("without their names: %v %+v", closed, s.learned[peer.ID])
	}
}
