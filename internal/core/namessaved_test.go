package core

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The learned and stand-in addresses survive a restart: written NamesSaveInterval after a change at most, at the stop,
// and at once after a restore, then read again at the start, what still holds.
func TestNamesKeptAcrossRestarts(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	addr := netip.MustParseAddr
	office := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
		input.DNS = []string{"192.168.1.1"}
	})
	kiosk, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true,
		Access: access("files.corp.lan", "*.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "laptop", Enabled: true, Access: access("*.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	address, address6, other := addr(kiosk.Address), addr(kiosk.Address6), addr(laptop.Address)
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.20 600", "AAAA fd00:5::20 600"))
	records := replyRecords(t, f.s.learn(address, answer(t, "app.example.com.", "A 203.0.113.10 600")))
	standIn := addr(strings.TrimPrefix(records[0], "A "))
	// the Authway app of the laptop routes the internet addresses itself
	f.s.Learn(other, answer(t, "web.example.com.", "A 203.0.113.20 600"), true)
	saved := func() string {
		text, err := f.db.Q().Meta(metaNames)
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	f.s.Tick()
	if text := saved(); !strings.Contains(text, `"192.168.1.20"`) || !strings.Contains(text, `"`+standIn.String()+`"`) {
		t.Fatalf("not written: %s", text)
	}

	// a restart: another service on the same database, with a new firewall
	restart := func(standIns string) *network.Fake {
		t.Helper()
		fake := network.NewFake()
		_, err := New(f.db, fake, Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log, StandIns: netip.MustParsePrefix(standIns)})
		if err != nil {
			t.Fatal(err)
		}
		return fake
	}
	fake := restart("198.18.0.0/16")
	if !fake.Reaches("wg0", address, addr("192.168.1.20")) || !fake.Reaches("wg0", address6, addr("fd00:5::20")) ||
		fake.ReachesThrough("wg0", address, standIn) != addr("203.0.113.10") || !fake.Reaches("wg0", other, addr("203.0.113.20")) {
		t.Errorf("after a restart: %+v %v", fake.Learned, fake.StandIns)
	}
	if len(fake.State.StandIns) != 1 || fake.State.StandIns[0] != (network.StandIn{Address: standIn, Real: addr("203.0.113.10")}) {
		t.Errorf("stand-ins after a restart: %+v", fake.State.StandIns)
	}

	// a change: written NamesSaveInterval after the writing before, or at the stop
	f.s.learn(address, answer(t, "files.corp.lan.", "A 192.168.1.21 600"))
	f.clock.advance(TickInterval)
	f.s.Tick()
	if strings.Contains(saved(), "192.168.1.21") {
		t.Error("written too soon")
	}
	f.s.Close()
	if !strings.Contains(saved(), "192.168.1.21") {
		t.Error("not written at the stop")
	}
	// a change of the configuration writes the versions of now: a peer renamed keeps what it learned
	if _, err := f.s.UpdatePeer(testActor, laptop.ID, PeerInput{Name: "desk", Enabled: true, Access: access("*.example.com")}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(NamesSaveInterval)
	f.s.Tick()
	if fake := restart("198.18.0.0/16"); !fake.Reaches("wg0", other, addr("203.0.113.20")) {
		t.Errorf("renamed: %+v", fake.Learned)
	}

	// another stand-in network: its stand-in addresses are gone, the rest stays
	fake = restart("198.19.0.0/16")
	if fake.ReachesThrough("wg0", address, standIn).IsValid() || fake.Reaches("wg0", address, standIn) || len(fake.StandIns) != 0 ||
		!fake.Reaches("wg0", address, addr("192.168.1.20")) || !fake.Reaches("wg0", other, addr("203.0.113.20")) {
		t.Errorf("another stand-in network: %+v %v", fake.Learned, fake.StandIns)
	}

	// a peer changed by an older version of Authway Server, which doesn't write them: what it learned is gone
	stored, err := f.db.Q().Peer(kiosk.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.Access = []string{"files.corp.lan", "*.example.org"}
	if err := f.db.Q().UpdatePeer(stored); err != nil {
		t.Fatal(err)
	}
	if fake := restart("198.18.0.0/16"); fake.Reaches("wg0", address, addr("192.168.1.20")) || fake.Reaches("wg0", address, standIn) ||
		!fake.Reaches("wg0", other, addr("203.0.113.20")) {
		t.Errorf("changed meanwhile: %+v", fake.Learned)
	}

	// past their time: nothing
	f.clock.advance(600*time.Second + LearnedMargin)
	if fake := restart("198.18.0.0/16"); len(fake.Learned["wg0"]) != 0 {
		t.Errorf("expired: %+v", fake.Learned)
	}

	// a restore writes at once that there's nothing
	f.s.Learn(other, answer(t, "web.example.com.", "A 203.0.113.20 600"), true)
	f.clock.advance(NamesSaveInterval)
	f.s.Tick()
	if !strings.Contains(saved(), "203.0.113.20") {
		t.Fatal("not written before the restore")
	}
	data := f.sealed(adminID, func(*backupContent) {})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if text := saved(); text != "{}" {
		t.Errorf("after a restore: %s", text)
	}
}
