package core

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/store"
)

// webEvents are the latest events of the web UI, the newest first
func (f *fixture) webEvents() []EventView {
	page, err := f.s.EventsPage(Filter{Limit: 100}, EventsWeb)
	if err != nil {
		f.t.Fatal(err)
	}
	return page.Items
}

// the latest event of a kind, or a failure
func (f *fixture) lastEvent(kind string) EventView {
	f.t.Helper()
	for _, event := range f.webEvents() {
		if event.Kind == kind {
			return event
		}
	}
	f.t.Fatalf("no %s event in %+v", kind, f.webEvents())
	return EventView{}
}

// Each change made in the web UI is an event: what, by whom, from where, and what changed.
func TestAuditTrail(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	bob := f.user("bob")
	if e := f.lastEvent("server_added"); e.By != "tester" || e.Source != "192.0.2.10" || e.ServerName != server.Name ||
		e.Detail != "wg0, UDP port 51820, 10.8.0.0/24 and fd00:aaaa:bbbb::/64, login: password" {
		t.Errorf("server added: %+v", e)
	}
	if e := f.lastEvent("peer_added"); e.PeerName != "alice laptop" || e.Username != "alice" || e.Detail != "10.8.0.2" {
		t.Errorf("peer added: %+v", e)
	}

	// saved without a change: no event
	count := len(f.webEvents())
	if _, err := f.s.UpdateServer(testActor, server.ID, inputOf(server)); err != nil {
		t.Fatal(err)
	}
	if len(f.webEvents()) != count {
		t.Errorf("an event without a change: %+v", f.webEvents()[0])
	}
	input := inputOf(server)
	input.AuthMode = store.AuthPasswordOTP
	input.Networks = []string{"192.168.1.0/24", "10.1.0.0/16"}
	input.DetectCopies = false
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("server_changed"); e.Detail != "networks: 192.168.1.0/24 → 192.168.1.0/24, 10.1.0.0/16, login: password → password and code, copy detection off" {
		t.Errorf("server changed: %q", e.Detail)
	}

	if _, err := f.s.UpdatePeer(testActor, peer.ID, PeerInput{Name: "laptop", Enabled: false, UserID: bob.ID}); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("peer_changed"); e.Detail != "name: alice laptop → laptop, disabled, user: alice → bob" || e.Username != "bob" {
		t.Errorf("peer changed: %+v", e)
	}
	if _, _, err := f.s.PeerConfig(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("peer_config"); e.PeerName != "laptop" || e.By != "tester" {
		t.Errorf("configuration: %+v", e)
	}
	// nobody logged in: nothing ended
	if err := f.s.LogoutPeer(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	for _, event := range f.webEvents() {
		if event.Kind == "session_ended" {
			t.Errorf("a session ended without a session: %+v", event)
		}
	}
	if _, err := f.s.UpdateUser(testActor, bob.ID, UserInput{Username: "bob", FullName: "Bob Chen", Password: "Another,5678"}); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("user_changed"); e.Detail != "full name: none → Bob Chen, new password" {
		t.Errorf("user changed: %q", e.Detail)
	}
	if err := f.s.DeleteUser(testActor, bob.ID); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("user_deleted"); e.Username != "bob" || e.Detail != "with its peers: Office 0 · laptop" {
		t.Errorf("user deleted: %+v", e)
	}

	// the administrators: the one who acts is By, the one changed is the user
	if _, err := f.s.EnsureAdmin("root", "Admin password 1"); err != nil {
		t.Fatal(err)
	}
	admins, _ := f.s.Admins()
	root := Actor{ID: admins[0].ID, From: "192.0.2.20"}
	if _, err := f.s.CreateAdmin(root, AdminInput{Username: "olga", Role: store.RoleOperator, Password: "Orange tree 4521"}); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("admin_added"); e.Username != "olga" || e.By != "root" || e.Source != "192.0.2.20" || e.Detail != "Operator" {
		t.Errorf("administrator added: %+v", e)
	}
	for _, event := range f.webEvents() {
		if event.By == "" && event.Kind != "admin_login" {
			t.Errorf("a change without its administrator: %+v", event)
		}
	}
}

// The events of a session ended in the web UI, and the filters of the events.
func TestEventFilters(t *testing.T) {
	f := setup(t)
	office := f.server(store.AuthPassword)
	lab := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(office, alice)
	f.peer(lab, alice)
	if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: "alice", Password: "wrong"})
	f.clock.advance(time.Hour)
	later := f.clock.now.Unix()
	if err := f.s.LogoutPeer(testActor, peer.ID); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("session_ended"); e.PeerName != "alice laptop" || e.Username != "alice" || e.By != "tester" {
		t.Errorf("session ended: %+v", e)
	}

	all, _ := f.s.EventsPage(Filter{Limit: 100}, "")
	web, _ := f.s.EventsPage(Filter{Limit: 100}, EventsWeb)
	vpn, _ := f.s.EventsPage(Filter{Limit: 100}, EventsVPN)
	if vpn.Total != 1 || vpn.Items[0].Kind != "login_failed" || web.Total+vpn.Total != all.Total {
		t.Errorf("by type: all %d, web %d, vpn %+v", all.Total, web.Total, vpn.Items)
	}
	check := func(name string, filter Filter, want int) {
		t.Helper()
		filter.Limit = 100
		page, err := f.s.EventsPage(filter, "")
		if err != nil || page.Total != want || len(page.Items) != want {
			t.Errorf("%s: total %d, %d items, want %d (%v)", name, page.Total, len(page.Items), want, err)
		}
	}
	// server_added, peer_added, login_failed, session_ended
	check("server", Filter{ServerID: office.ID}, 4)
	check("server gone", Filter{ServerID: 999}, 0)
	// each word in one of the columns, whatever the case: the peer, the server, the administrator
	check("words", Filter{Search: "LAPTOP office"}, 4)
	check("more words", Filter{Search: "laptop office tester"}, 3)
	check("address", Filter{Search: "203.0.113"}, 1)
	// % and _ are letters, not patterns
	check("percent", Filter{Search: "%"}, 0)
	check("underscore", Filter{Search: "_"}, 0)
	check("since", Filter{Since: later}, 1)
	check("until", Filter{Until: later}, all.Total-1)
	page, _ := f.s.EventsPage(Filter{Limit: 2, Offset: 1}, "")
	if len(page.Items) != 2 || page.Total != all.Total || page.Items[0].ID != all.Items[1].ID {
		t.Errorf("page: %+v of %d", page.Items, page.Total)
	}
}

// The login history and the connections: by server, words, time (what overlaps it) and page.
func TestHistoryFilters(t *testing.T) {
	f := setup(t)
	office := f.server(store.AuthPassword)
	lab := f.server(store.AuthKey)
	alice := f.user("alice")
	peer := f.peer(office, alice)
	start := f.clock.now.Unix()
	for range 3 {
		if a := f.login(peer, "203.0.113.7"); a.Status != 200 {
			t.Fatalf("login: %+v", a)
		}
		f.clock.advance(10 * time.Minute)
		f.s.Logout(netip.MustParseAddr(peer.Address), "10.8.0.1")
		f.clock.advance(50 * time.Minute)
	}
	history, err := f.s.HistoryPage(Filter{Limit: 2})
	if err != nil || history.Total != 3 || len(history.Items) != 2 || history.Items[0].EndedAt < history.Items[1].EndedAt {
		t.Fatalf("history: %+v, %v", history, err)
	}
	// the second session, from start+1h to start+1h10
	second, _ := f.s.HistoryPage(Filter{Limit: 10, Since: start + 3600 + 300, Until: start + 3600 + 400})
	if second.Total != 1 || second.Items[0].StartedAt != start+3600 {
		t.Errorf("by time: %+v", second)
	}
	if page, _ := f.s.HistoryPage(Filter{Limit: 10, ServerID: lab.ID}); page.Total != 0 {
		t.Errorf("another server: %+v", page)
	}
	if page, _ := f.s.HistoryPage(Filter{Limit: 10, Search: "laptop 203.0.113.7"}); page.Total != 3 {
		t.Errorf("words: %+v", page)
	}

	q := f.db.Q()
	add := func(server *ServerView, peerName, endpoint string, from, to int64) {
		c := &store.Connection{ServerID: server.ID, PeerID: 1, ServerName: server.Name, PeerName: peerName,
			Address: "10.8.0.2", Endpoint: endpoint, StartedAt: from, LastSeen: max(to, from)}
		if err := q.CreateConnection(c); err != nil {
			t.Fatal(err)
		}
		if to != 0 {
			if err := q.EndConnection(c.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(office, "early", "198.51.100.1:40000", start, start+600)
	add(office, "middle", "198.51.100.2:40000", start+1800, start+3600)
	add(lab, "open", "203.0.113.9:40000", start+7200, 0)
	connections := func(filter Filter) []string {
		filter.Limit = 10
		page, err := f.s.ConnectionsPage(filter)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, c := range page.Items {
			names = append(names, c.PeerName)
		}
		if page.Total != len(names) {
			t.Errorf("total %d for %v", page.Total, names)
		}
		return names
	}
	for _, test := range []struct {
		name   string
		filter Filter
		want   string
	}{
		{"all, the latest started first", Filter{}, "open middle early"},
		{"overlap", Filter{Since: start + 3000, Until: start + 4000}, "middle"},
		{"open, still going", Filter{Since: start + 9000}, "open"},
		{"server", Filter{ServerID: office.ID}, "middle early"},
		{"public IP", Filter{Search: "198.51.100.2"}, "middle"},
	} {
		if got := strings.Join(connections(test.filter), " "); got != test.want {
			t.Errorf("%s: %q, want %q", test.name, got, test.want)
		}
	}
}

// A backslash in the words is a letter too: it doesn't escape the next one.
func TestSearchBackslash(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthKey)
	if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: `a\b`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for search, want := range map[string]int{`a\b`: 1, "ab": 0, `\`: 1} {
		if page, _ := f.s.EventsPage(Filter{Limit: 10, Search: search}, ""); page.Total != want {
			t.Errorf("%q: %d, want %d", search, page.Total, want)
		}
	}
}

// Every list of Activity has the newest on top, by the time it started: a session that ended last but started first
// comes after the one started later, an old connection still open after a new one.
func TestActivityNewestFirst(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	alice := f.peer(server, f.user("alice"))
	bob := f.peer(server, f.user("bob"))
	start := f.clock.now.Unix()
	if a := f.login(alice, "203.0.113.7"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	f.clock.advance(10 * time.Minute)
	if a := f.login(bob, "203.0.113.8"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}
	names := func(views []SessionView) string {
		var list []string
		for _, view := range views {
			list = append(list, view.PeerName)
		}
		return strings.Join(list, ", ")
	}
	open, err := f.s.OpenSessions()
	if err != nil || names(open) != "bob laptop, alice laptop" {
		t.Errorf("open sessions: %s %v", names(open), err)
	}
	f.clock.advance(10 * time.Minute)
	f.s.Logout(netip.MustParseAddr(bob.Address), "10.8.0.1")
	f.clock.advance(10 * time.Minute)
	f.s.Logout(netip.MustParseAddr(alice.Address), "10.8.0.1")
	if history, _ := f.s.HistoryPage(Filter{Limit: 10}); names(history.Items) != "bob laptop, alice laptop" {
		t.Errorf("history: %s", names(history.Items))
	}

	q := f.db.Q()
	old := &store.Connection{ServerID: server.ID, PeerID: alice.ID, ServerName: server.Name, PeerName: "still open",
		Address: alice.Address, StartedAt: start, LastSeen: start}
	recent := &store.Connection{ServerID: server.ID, PeerID: bob.ID, ServerName: server.Name, PeerName: "ended",
		Address: bob.Address, StartedAt: start + 600, LastSeen: start + 900}
	for _, c := range []*store.Connection{old, recent} {
		if err := q.CreateConnection(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.EndConnection(recent.ID); err != nil {
		t.Fatal(err)
	}
	page, _ := f.s.ConnectionsPage(Filter{Limit: 10})
	if len(page.Items) != 2 || page.Items[0].PeerName != "ended" || page.Items[1].PeerName != "still open" {
		t.Errorf("connections: %+v", page.Items)
	}
}
