package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phatdo1819/authway-server/internal/store"
)

// fakeDNS answers the lookups of the tests: the records of each name, "A address ttl" or "AAAA address ttl", and
// NXDOMAIN for the others. It writes down each query, "name type server", and with fails, answers none; with
// failsAAAA, none for IPv6.
type fakeDNS struct {
	mu        sync.Mutex
	records   map[string][]string
	asked     []string
	fails     bool
	failsAAAA bool
}

func (d *fakeDNS) set(name string, records ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = records
}

func (d *fakeDNS) queries() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.asked)
}

func (d *fakeDNS) lookup(_ context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil || len(message.Questions) != 1 {
		return nil, errors.New("not a query")
	}
	question := message.Questions[0]
	name := strings.TrimSuffix(question.Name.String(), ".")
	kind := map[dnsmessage.Type]string{dnsmessage.TypeA: "A", dnsmessage.TypeAAAA: "AAAA"}[question.Type]
	d.asked = append(d.asked, fmt.Sprintf("%s %s %s", name, kind, server))
	if d.fails || (d.failsAAAA && kind == "AAAA") {
		return nil, errors.New("no answer")
	}
	reply := dnsmessage.Message{Header: dnsmessage.Header{ID: message.Header.ID, Response: true}, Questions: message.Questions}
	records, ok := d.records[name]
	if !ok {
		reply.Header.RCode = dnsmessage.RCodeNameError
	}
	for _, record := range records {
		var recordKind, value string
		var ttl uint32
		fmt.Sscanf(record, "%s %s %d", &recordKind, &value, &ttl)
		if recordKind != kind {
			continue
		}
		header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: ttl}
		address := netip.MustParseAddr(value)
		if kind == "A" {
			reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: address.As4()}})
		} else {
			reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: address.As16()}})
		}
	}
	return reply.Pack()
}

// askedFor is how many queries start with prefix: a name, and a type
func askedFor(queries []string, prefix string) int {
	found := 0
	for _, query := range queries {
		if strings.HasPrefix(query, prefix) {
			found++
		}
	}
	return found
}

// Authway Server looks up the exact names of the rules itself, for the peers its DNS server answers: their addresses
// inside the networks open as if the device had asked, and stay open while the lookups go on. Not the wildcards, nor
// the internet addresses, nor for a peer that isn't logged in.
func TestNamesLookedUp(t *testing.T) {
	f := setup(t)
	f.s.opts.StandIns = netip.MustParsePrefix("198.18.0.0/16")
	dns := &fakeDNS{records: map[string][]string{
		"files.corp.lan":  {"A 192.168.1.20 60", "A 10.99.0.1 60", "AAAA fd00:5::20 60"},
		"app.example.com": {"A 203.0.113.10 300"},
	}}
	f.s.opts.Lookup = dns.lookup
	ctx := context.Background()
	addr := netip.MustParseAddr
	office := f.server(store.AuthPassword)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
	input.DNS = []string{"192.168.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	alice := f.user("alice")
	peerInput := PeerInput{Name: "alice laptop", Enabled: true, UserID: alice.ID,
		Access: access("files.corp.lan", "*.apps.lan", "app.example.com", "missing.corp.lan")}
	peer, err := f.s.CreatePeer(testActor, office.ID, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	address, address6 := addr(peer.Address), addr(peer.Address6)
	reaches := func(key netip.Addr, target string) bool {
		return f.net.Reaches("wg0", key, addr(target))
	}

	// not logged in: nothing to look up
	f.s.LookUpNames(ctx)
	if queries := dns.queries(); len(queries) != 0 {
		t.Fatalf("before the login: %v", queries)
	}

	// logged in: its exact names, IPv4 and IPv6, of the DNS servers of its server; what's inside the networks opens
	if answer := f.login(peer, "203.0.113.7"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	f.s.LookUpNames(ctx)
	queries := dns.queries()
	if !slices.Contains(queries, "files.corp.lan A 192.168.1.1:53") || !slices.Contains(queries, "files.corp.lan AAAA 192.168.1.1:53") ||
		askedFor(queries, "app.example.com ") != 2 || askedFor(queries, "missing.corp.lan ") != 2 || len(queries) != 6 {
		t.Fatalf("queries: %v", queries)
	}
	if !reaches(address, "192.168.1.20") || !reaches(address6, "fd00:5::20") || reaches(address, "10.99.0.1") {
		t.Errorf("learned: %+v", f.net.Learned)
	}
	// the internet addresses: only through the answer the device gets
	if reaches(address, "203.0.113.10") || len(f.s.standIns) != 0 || len(f.net.StandIns) != 0 {
		t.Errorf("internet: %+v %v", f.net.Learned, f.net.StandIns)
	}

	// at once again: nothing due
	f.s.LookUpNames(ctx)
	if queries := dns.queries(); len(queries) != 6 {
		t.Errorf("again: %v", queries)
	}

	// each answer runs out, LookupMin at least: looked up again, so the address stays open well past the time to
	// live and the margin of the first answer; the name that doesn't exist, every LookupRetry
	round := func(times int) {
		for range times {
			f.clock.advance(LookupInterval)
			f.handshake(peer, "203.0.113.7")
			f.s.Tick()
			f.s.LookUpNames(ctx)
		}
	}
	round(30)
	queries = dns.queries()
	files, app := askedFor(queries, "files.corp.lan A "), askedFor(queries, "app.example.com A ")
	missing := askedFor(queries, "missing.corp.lan A ")
	if !reaches(address, "192.168.1.20") || files < 14 || files > 17 || app < 3 || app > 5 || missing < 14 || missing > 17 {
		t.Errorf("after 15 minutes: %d %d %d %+v", files, app, missing, f.net.Learned)
	}

	// the name gets another address: it opens at the next lookup
	dns.set("files.corp.lan", "A 192.168.1.21 60")
	round(3)
	if !reaches(address, "192.168.1.21") {
		t.Errorf("new address: %+v", f.net.Learned)
	}

	// its DNS servers stop answering: the addresses close when the last answer and the margin run out
	dns.mu.Lock()
	dns.fails = true
	dns.mu.Unlock()
	round(2)
	if !reaches(address, "192.168.1.21") {
		t.Error("closed at once")
	}
	round(int((60*time.Second + LearnedMargin) / LookupInterval))
	if reaches(address, "192.168.1.21") {
		t.Errorf("still open without answers: %+v", f.net.Learned)
	}
	dns.mu.Lock()
	dns.fails = false
	dns.mu.Unlock()
	round(3)
	if !reaches(address, "192.168.1.21") {
		t.Errorf("not open again: %+v", f.net.Learned)
	}

	// logged out: not looked up any more
	if answer := f.s.Logout(address, "10.8.0.1"); answer.Status != 200 {
		t.Fatalf("logout: %+v", answer)
	}
	before := len(dns.queries())
	round(4)
	if after := len(dns.queries()); after != before || len(f.s.lookups) != 0 {
		t.Errorf("after the logout: %d queries, %d names", after-before, len(f.s.lookups))
	}

	// a server without a login: its peers always; a name of each server is looked up of its own DNS servers, again at
	// once when they change; IPv4 only, without IPv6 networks
	kiosk := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = []string{"192.168.9.0/24"}
		input.DNS = []string{"192.168.9.1"}
	})
	dns.set("print.corp.lan", "A 192.168.9.30 3600")
	device, err := f.s.CreatePeer(testActor, kiosk.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("print.corp.lan")})
	if err != nil {
		t.Fatal(err)
	}
	f.s.LookUpNames(ctx)
	queries = dns.queries()
	if !slices.Contains(queries, "print.corp.lan A 192.168.9.1:53") || slices.Contains(queries, "print.corp.lan AAAA 192.168.9.1:53") ||
		!f.net.Reaches("wg1", addr(device.Address), addr("192.168.9.30")) {
		t.Fatalf("server without a login: %v %+v", queries, f.net.Learned)
	}
	input = inputOf(kiosk)
	input.DNS = []string{"192.168.9.2"}
	if _, err := f.s.UpdateServer(testActor, kiosk.ID, input); err != nil {
		t.Fatal(err)
	}
	f.s.LookUpNames(ctx)
	if !slices.Contains(dns.queries(), "print.corp.lan A 192.168.9.2:53") {
		t.Errorf("new DNS servers: %v", dns.queries())
	}
	// its rules change: not looked up any more
	if _, err := f.s.UpdatePeer(testActor, device.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("*.corp.lan")}); err != nil {
		t.Fatal(err)
	}
	before = len(dns.queries())
	f.clock.advance(2 * time.Hour)
	f.s.LookUpNames(ctx)
	if after := len(dns.queries()); after != before || len(f.s.lookups) != 0 {
		t.Errorf("without exact names: %d queries, %v", after-before, f.s.lookups)
	}
}

// A DNS server that answers for IPv4 but never for IPv6, on a server with IPv6 networks: the IPv4 addresses still open,
// and the IPv6 ones once it answers.
func TestLookupsWithoutIPv6Answers(t *testing.T) {
	f := setup(t)
	dns := &fakeDNS{records: map[string][]string{"files.corp.lan": {"A 192.168.1.20 60", "AAAA fd00:5::20 60"}}, failsAAAA: true}
	f.s.opts.Lookup = dns.lookup
	office := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24", "fd00:5::/64"}
		input.DNS = []string{"192.168.1.1"}
	})
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("files.corp.lan")})
	if err != nil {
		t.Fatal(err)
	}
	address, address6 := netip.MustParseAddr(peer.Address), netip.MustParseAddr(peer.Address6)
	f.s.LookUpNames(context.Background())
	queries := dns.queries()
	if askedFor(queries, "files.corp.lan AAAA ") != 1 || !f.net.Reaches("wg0", address, netip.MustParseAddr("192.168.1.20")) ||
		f.net.Reaches("wg0", address6, netip.MustParseAddr("fd00:5::20")) {
		t.Fatalf("IPv4 only: %v %+v", queries, f.net.Learned)
	}
	dns.mu.Lock()
	dns.failsAAAA = false
	dns.mu.Unlock()
	// looked up again when the IPv4 answer runs out
	f.clock.advance(time.Minute)
	f.s.LookUpNames(context.Background())
	if !f.net.Reaches("wg0", address, netip.MustParseAddr("192.168.1.20")) || !f.net.Reaches("wg0", address6, netip.MustParseAddr("fd00:5::20")) {
		t.Errorf("both: %v %+v", dns.queries(), f.net.Learned)
	}
}

// A restore forgets the names looked up, and the lookups under way keep nothing.
func TestLookupsAfterRestore(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	dns := &fakeDNS{records: map[string][]string{"files.corp.lan": {"A 192.168.1.20 3600"}}}
	office := f.serverWith(store.AuthKey, func(input *ServerInput) {
		input.Networks = []string{"192.168.1.0/24"}
		input.DNS = []string{"192.168.1.1"}
	})
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("files.corp.lan")})
	if err != nil {
		t.Fatal(err)
	}
	data := f.sealed(adminID, func(*backupContent) {})
	// a restore while the lookup waits for its answer
	f.s.opts.Lookup = func(ctx context.Context, server netip.AddrPort, query []byte) ([]byte, error) {
		if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
			t.Error(err)
		}
		return dns.lookup(ctx, server, query)
	}
	f.s.LookUpNames(context.Background())
	if len(f.s.lookups) != 0 || f.net.Reaches("wg0", netip.MustParseAddr(peer.Address), netip.MustParseAddr("192.168.1.20")) {
		t.Errorf("kept across the restore: %v %+v", f.s.lookups, f.net.Learned)
	}
	f.s.opts.Lookup = dns.lookup
	f.s.LookUpNames(context.Background())
	if !f.net.Reaches("wg0", netip.MustParseAddr(peer.Address), netip.MustParseAddr("192.168.1.20")) {
		t.Errorf("not looked up after the restore: %+v", f.net.Learned)
	}
}
