package core

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/store"
)

// learn is Learn for a device without the Authway app
func (s *Service) learn(address netip.Addr, reply []byte) []byte {
	return s.Learn(address, reply, false)
}

// replyRecords are the records of the answer of a reply: "A address", "AAAA address", "CNAME target" or the type
func replyRecords(t *testing.T, reply []byte) []string {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	var records []string
	for _, record := range message.Answers {
		switch body := record.Body.(type) {
		case *dnsmessage.AResource:
			records = append(records, "A "+netip.AddrFrom4(body.A).String())
		case *dnsmessage.AAAAResource:
			records = append(records, "AAAA "+netip.AddrFrom16(body.AAAA).String())
		case *dnsmessage.CNAMEResource:
			records = append(records, "CNAME "+body.CNAME.String())
		default:
			records = append(records, record.Header.Type.String())
		}
	}
	return records
}

// Names on the internet: in the answer to the peer, their IPv4 internet addresses become stand-in addresses, open for
// the peer and leading to them; their IPv6 internet addresses go; the rest stays. The same internet address has the
// same stand-in address for every peer, after a restart too, and keeps it a day after the last one could use it.
func TestNamesOnTheInternet(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	addr := netip.MustParseAddr
	office := f.server(store.AuthKey)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
	input.DNS = []string{"192.168.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("*.example.com", "files.corp.lan")})
	if err != nil {
		t.Fatal(err)
	}
	// its file routes the stand-in addresses through the tunnel; the firewall knows them
	_, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/24, fd00:5::/64, 198.18.0.0/16\n") {
		t.Errorf("configuration file:\n%s", text)
	}
	if f.net.State.StandInNetwork != netip.MustParsePrefix("198.18.0.0/16") || !f.net.State.Servers[0].StandIns {
		t.Fatalf("state: %v %+v", f.net.State.StandInNetwork, f.net.State.Servers[0])
	}

	address := addr(peer.Address)
	app := answer(t, "app.example.com.", "CNAME app.example.com. edge.cdn.net.", "A 203.0.113.10 300 edge.cdn.net.",
		"A 192.168.1.20 300 edge.cdn.net.", "A 10.99.0.1 300 edge.cdn.net.", "AAAA 2001:db8::10 300 edge.cdn.net.",
		"AAAA fd00:5::20 300 edge.cdn.net.")
	records := replyRecords(t, f.s.learn(address, app))
	if len(records) != 5 || records[0] != "CNAME edge.cdn.net." || !strings.HasPrefix(records[1], "A 198.18.") ||
		!slices.Equal(records[2:], []string{"A 192.168.1.20", "A 10.99.0.1", "AAAA fd00:5::20"}) {
		t.Fatalf("answer: %v", records)
	}
	standIn := addr(strings.TrimPrefix(records[1], "A "))
	if real := f.net.ReachesThrough("wg0", address, standIn); real != addr("203.0.113.10") {
		t.Errorf("through %s: %v", standIn, real)
	}
	// inside the networks as before; a private address outside them, nothing
	if !f.net.Reaches("wg0", address, addr("192.168.1.20")) || f.net.Reaches("wg0", address, addr("10.99.0.1")) {
		t.Errorf("learned: %+v", f.net.Learned)
	}
	// the same answer, the same stand-in address
	if records := replyRecords(t, f.s.learn(address, app)); records[1] != "A "+standIn.String() || len(f.s.standIns) != 1 {
		t.Errorf("again: %v, %d stand-ins", records, len(f.s.standIns))
	}
	// a name that isn't one of its rules: the answer as it was, nothing learned
	other := answer(t, "www.other.net.", "A 198.51.100.7 300")
	if got := f.s.learn(address, other); !slices.Equal(got, other) || len(f.s.standIns) != 1 {
		t.Errorf("another name: %v", replyRecords(t, got))
	}
	// the HTTPS records of its names go: their hints would skip the stand-in addresses
	https := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeHTTPS,
			Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("app.example.com."),
			Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.HTTPSResource{
			SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."),
				Params: []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamIPv4Hint, Value: []byte{203, 0, 113, 10}}}}}}},
	}
	data, err := https.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if records := replyRecords(t, f.s.learn(address, data)); len(records) != 0 {
		t.Errorf("HTTPS: %v", records)
	}

	// another peer with names: the same stand-in address, open for it too; a peer that sends all its traffic through
	// the tunnel: the internet addresses as they are
	second, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "desk", Enabled: true, Access: access("app.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if records := replyRecords(t, f.s.learn(addr(second.Address), app)); records[1] != "A "+standIn.String() ||
		f.net.ReachesThrough("wg0", addr(second.Address), standIn) != addr("203.0.113.10") {
		t.Errorf("second peer: %v", records)
	}
	all, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "all", Enabled: true, RouteAll: true, Access: access("app.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if records := replyRecords(t, f.s.learn(addr(all.Address), app)); !slices.Contains(records, "A 203.0.113.10") ||
		!slices.Contains(records, "AAAA 2001:db8::10") || f.net.Reaches("wg0", addr(all.Address), standIn) {
		t.Errorf("route all: %v", records)
	}
	if _, text, _ := f.s.PeerConfig(testActor, all.ID); strings.Contains(text, "198.18") {
		t.Errorf("route all file:\n%s", text)
	}

	// the same stand-in address after a restart
	again, err := New(f.db, f.net, Options{LoginPort: 8181, Now: f.clock.Now, Log: f.s.log, StandIns: f.s.opts.StandIns})
	if err != nil {
		t.Fatal(err)
	}
	again.mu.Lock()
	restarted, _, _ := again.standInLocked(addr("203.0.113.10"))
	again.mu.Unlock()
	if restarted != standIn {
		t.Errorf("after a restart: %v, not %v", restarted, standIn)
	}
	f.s.mu.Lock()
	f.s.applyLocked()
	f.s.mu.Unlock()

	// closed for the peers at the time to live and the margin; the stand-in address leads there a day more
	f.clock.advance(300*time.Second + LearnedMargin + time.Second)
	f.s.Tick()
	if f.net.ReachesThrough("wg0", address, standIn).IsValid() || f.net.StandIns[standIn] != addr("203.0.113.10") {
		t.Errorf("expired: %+v %v", f.net.Learned, f.net.StandIns)
	}
	f.clock.advance(StandInGrace)
	f.s.Tick()
	if len(f.net.StandIns) != 0 || len(f.s.standIns) != 0 || len(f.s.standInOf) != 0 {
		t.Errorf("not forgotten: %v", f.net.StandIns)
	}

	// a restore forgets them all
	f.s.learn(address, app)
	if len(f.s.standIns) != 1 {
		t.Fatalf("%d stand-ins before the restore", len(f.s.standIns))
	}
	data = f.sealed(adminID, func(*backupContent) {})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if len(f.s.standIns) != 0 || len(f.net.StandIns) != 0 {
		t.Errorf("after a restore: %v", f.net.StandIns)
	}

	// the networks of a server can't overlap them
	input = inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "198.18.5.0/24"}
	if _, err := f.s.UpdateServer(testActor, office.ID, input); fields(t, err)["networks"] != "overlaps_stand_ins" {
		t.Errorf("network overlapping: %v", err)
	}
	input = inputOf(office)
	input.Network = "198.18.200.0/24"
	if _, err := f.s.UpdateServer(testActor, office.ID, input); fields(t, err)["network"] != "overlaps_stand_ins" {
		t.Errorf("VPN network overlapping: %v", err)
	}

	// without stand-in addresses: the internet addresses as they are, nothing in the file
	f.s.opts.StandIns = netip.Prefix{}
	if got := f.s.learn(address, app); !slices.Equal(got, app) {
		t.Errorf("without stand-ins: %v", replyRecords(t, got))
	}
	if _, text, _ := f.s.PeerConfig(testActor, peer.ID); strings.Contains(text, "198.18") {
		t.Errorf("file without stand-ins:\n%s", text)
	}
}

// When the stand-in addresses run out, the new internet addresses go to the device as they are.
func TestStandInsRunOut(t *testing.T) {
	f := setup(t)
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.7.0/24")
	office := f.server(store.AuthKey)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24"}
	input.DNS = []string{"192.168.1.1"}
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("*.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	var list []string
	for index := range 260 {
		list = append(list, fmt.Sprintf("A 203.0.%d.%d 60", index/200, index%200+1))
	}
	records := replyRecords(t, f.s.learn(netip.MustParseAddr(peer.Address), answer(t, "big.example.com.", list...)))
	standIns, real := 0, 0
	for _, record := range records {
		switch {
		case strings.HasPrefix(record, "A 198.18.7."):
			standIns++
			if strings.HasSuffix(record, ".0") || strings.HasSuffix(record, ".255") {
				t.Errorf("stand-in %s", record)
			}
		case strings.HasPrefix(record, "A 203.0."):
			real++
		}
	}
	if standIns != 254 || real != 6 || len(f.s.standIns) != 254 || len(f.net.StandIns) != 254 {
		t.Errorf("%d stand-ins, %d as they are, %d kept", standIns, real, len(f.s.standIns))
	}
}

// The Authway app routes the internet addresses of the names itself: they stay as they are in its answers, open for
// the peer, and listed for the app with the time they stay open; no stand-in address. Without IPv6 in the tunnel, the
// IPv6 ones go.
func TestNamesRoutedByTheApp(t *testing.T) {
	f := setup(t)
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	addr := netip.MustParseAddr
	office := f.server(store.AuthKey)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
	input.DNS = []string{"192.168.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "laptop", Enabled: true, Access: access("*.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	// its file tells the app; the stand-in addresses stay in it, for the other apps
	_, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "# NameRoutes = 1\n") || !strings.Contains(text, ", 198.18.0.0/16\n") {
		t.Errorf("configuration file:\n%s", text)
	}
	address, address6 := addr(peer.Address), addr(peer.Address6)
	app := answer(t, "app.example.com.", "CNAME app.example.com. edge.cdn.net.", "A 203.0.113.10 300 edge.cdn.net.",
		"A 192.168.1.20 300 edge.cdn.net.", "A 10.99.0.1 300 edge.cdn.net.", "AAAA 2001:db8::10 300 edge.cdn.net.",
		"AAAA fd00:5::20 300 edge.cdn.net.")
	reply := f.s.Learn(address, app, true)
	records := replyRecords(t, reply)
	if !slices.Equal(records, []string{"CNAME edge.cdn.net.", "A 203.0.113.10", "A 192.168.1.20", "A 10.99.0.1",
		"AAAA 2001:db8::10", "AAAA fd00:5::20"}) {
		t.Errorf("answer: %v", records)
	}
	// the routes: the internet addresses only, the networks of the server are in the file already
	routes := names.Routes(reply)
	if len(routes) != 2 || routes[0] != (names.Address{Addr: addr("203.0.113.10"), TTL: 300*time.Second + LearnedMargin}) ||
		routes[1] != (names.Address{Addr: addr("2001:db8::10"), TTL: 300*time.Second + LearnedMargin}) {
		t.Errorf("routes: %+v", routes)
	}
	if !f.net.Reaches("wg0", address, addr("203.0.113.10")) || !f.net.Reaches("wg0", address6, addr("2001:db8::10")) ||
		!f.net.Reaches("wg0", address, addr("192.168.1.20")) || f.net.Reaches("wg0", address, addr("10.99.0.1")) ||
		len(f.s.standIns) != 0 {
		t.Errorf("learned: %+v, stand-ins %v", f.net.Learned, f.s.standIns)
	}
	// a device without the app, the same peer: stand-in addresses
	if records := replyRecords(t, f.s.learn(address, app)); !strings.HasPrefix(records[1], "A 198.18.") ||
		len(names.Routes(f.s.learn(address, app))) != 0 {
		t.Errorf("without the app: %v", records)
	}
	// a name that isn't one of its rules: as it was
	other := answer(t, "www.other.net.", "A 198.51.100.7 300")
	if got := f.s.Learn(address, other, true); !slices.Equal(got, other) {
		t.Errorf("another name: %v", replyRecords(t, got))
	}
	// all its traffic through the tunnel: nothing for the app to route, and nothing in its file
	all, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "all", Enabled: true, RouteAll: true, Access: access("app.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.s.Learn(addr(all.Address), app, true); len(names.Routes(got)) != 0 {
		t.Errorf("all its traffic: %+v", names.Routes(got))
	}
	if _, text, _ := f.s.PeerConfig(testActor, all.ID); strings.Contains(text, "NameRoutes") {
		t.Errorf("all its traffic, file:\n%s", text)
	}

	// a server without IPv6: the IPv6 internet addresses go, the IPv4 ones are routed
	plain := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Network6 = ""
		input.Networks = []string{"192.168.9.0/24"}
	})
	kiosk, err := f.s.CreatePeer(testActor, plain.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("app.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	reply = f.s.Learn(addr(kiosk.Address), app, true)
	if records := replyRecords(t, reply); slices.Contains(records, "AAAA 2001:db8::10") || !slices.Contains(records, "A 203.0.113.10") {
		t.Errorf("without IPv6: %v", records)
	}
	if routes := names.Routes(reply); len(routes) != 1 || routes[0].Addr != addr("203.0.113.10") {
		t.Errorf("without IPv6, routes: %+v", routes)
	}
}

// A server without networks takes names, for their internet addresses, but no addresses, which would have nowhere to
// be.
func TestNamesWithoutNetworks(t *testing.T) {
	f := setup(t)
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	addr := netip.MustParseAddr
	server := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = nil
		input.DNS = []string{"1.1.1.1"}
	})
	for _, bad := range [][]string{{"192.168.1.10"}, {"app.example.com", "10.0.0.0/8"}} {
		if _, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "kiosk", Enabled: true, Access: &bad}); fields(t, err)["access"] != "names_only" {
			t.Errorf("%v: %v", bad, err)
		}
	}
	peer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("app.example.com", "*.example.org")})
	if err != nil {
		t.Fatal(err)
	}
	// its file: the VPN network and the stand-in addresses through the tunnel, Authway Server for its DNS, routes for the app
	_, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 198.18.0.0/16\n") ||
		!strings.Contains(text, "DNS = 10.8.0.1, fd00:aaaa:bbbb::1\n") || !strings.Contains(text, "# NameRoutes = 1\n") {
		t.Errorf("configuration file:\n%s", text)
	}
	if state := f.net.State.Servers[0]; !state.StandIns || len(state.Peers) != 1 || !state.Peers[0].Names {
		t.Fatalf("state: %+v", state)
	}
	// an internet name through its stand-in address; a private address, nowhere
	address := addr(peer.Address)
	records := replyRecords(t, f.s.learn(address, answer(t, "app.example.com.", "A 203.0.113.10 300")))
	if len(records) != 1 || !strings.HasPrefix(records[0], "A 198.18.") {
		t.Fatalf("answer: %v", records)
	}
	if real := f.net.ReachesThrough("wg0", address, addr(strings.TrimPrefix(records[0], "A "))); real != addr("203.0.113.10") {
		t.Errorf("through the stand-in address: %v", real)
	}
	f.s.learn(address, answer(t, "intranet.example.org.", "A 192.168.1.20 300"))
	if f.net.Reaches("wg0", address, addr("192.168.1.20")) {
		t.Error("a private address reached")
	}
	// the Authway app routes it as it is
	if routes := names.Routes(f.s.Learn(address, answer(t, "app.example.com.", "A 203.0.113.10 300"), true)); len(routes) != 1 ||
		!f.net.Reaches("wg0", address, addr("203.0.113.10")) {
		t.Errorf("app: %+v", routes)
	}
	// no rules any more: nothing through the tunnel but the server
	if _, err := f.s.UpdatePeer(testActor, peer.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access()}); err != nil {
		t.Fatal(err)
	}
	if _, text, _ := f.s.PeerConfig(testActor, peer.ID); !strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64\n") ||
		strings.Contains(text, "NameRoutes") {
		t.Errorf("without names:\n%s", text)
	}
}
