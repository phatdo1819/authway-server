package core

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/phatdo1819/authway-server/internal/store"
)

// answer is the reply of a DNS server to a query for name: records are "A address ttl", "AAAA address ttl" or
// "CNAME owner target"
func answer(t *testing.T, name string, records ...string) []byte {
	t.Helper()
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	for _, record := range records {
		var kind, value string
		var ttl uint32
		owner := name
		if strings.HasPrefix(record, "CNAME") {
			var target string
			fmt.Sscanf(record, "CNAME %s %s", &owner, &target)
			message.Answers = append(message.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}})
			continue
		}
		fmt.Sscanf(record, "%s %s %d %s", &kind, &value, &ttl, &owner)
		header := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner), Class: dnsmessage.ClassINET, TTL: ttl}
		address := netip.MustParseAddr(value)
		if kind == "A" {
			header.Type = dnsmessage.TypeA
			message.Answers = append(message.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: address.As4()}})
		} else {
			header.Type = dnsmessage.TypeAAAA
			message.Answers = append(message.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: address.As16()}})
		}
	}
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Names in the access rules: kept, in the configuration file, and the addresses of their answers open for the peer
// once it's logged in, inside the networks of its server, for the time to live and LearnedMargin; the connections to
// them close when its rules change.
func TestNamesInAccessRules(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	input := inputOf(office)
	input.Networks = []string{"192.168.1.0/24", "10.20.0.0/16", "fd00:5::/64"}
	// the server itself is never asked: the queries would come back
	input.DNS = []string{"10.8.0.1", "192.168.1.1"}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	alice := f.user("alice")
	peerInput := PeerInput{Name: "alice laptop", Enabled: true, UserID: alice.ID}
	for _, bad := range []string{"*", "a.*.lan", "printer", "files.corp.lan:80", "http://files.corp.lan"} {
		peerInput.Access = access(bad)
		if _, err := f.s.CreatePeer(testActor, office.ID, peerInput); fields(t, err)["access"] != "invalid" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// kept in lowercase, once, in the order given
	peerInput.Access = access("Files.Corp.LAN.", "*.apps.lan", "192.168.1.10", "files.corp.lan")
	peer, err := f.s.CreatePeer(testActor, office.ID, peerInput)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(peer.Access, []string{"files.corp.lan", "*.apps.lan", "192.168.1.10/32"}) {
		t.Fatalf("access: %v", peer.Access)
	}
	if e := f.lastEvent("peer_added"); !strings.Contains(e.Detail, "reaches files.corp.lan, *.apps.lan, 192.168.1.10/32") {
		t.Errorf("event: %+v", e)
	}

	// its file: Authway Server for its DNS, and all the networks of the server, whose firewall lets through what the
	// rules allow
	_, text, err := f.s.PeerConfig(testActor, peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "DNS = 10.8.0.1, fd00:aaaa:bbbb::1\n") ||
		!strings.Contains(text, "AllowedIPs = 10.8.0.0/24, fd00:aaaa:bbbb::/64, 192.168.1.0/24, 10.20.0.0/16, fd00:5::/64\n") {
		t.Errorf("configuration file:\n%s", text)
	}
	state := f.net.State.Servers[0].Peers[0]
	if !state.Names || len(state.Access) != 1 || len(state.Learned) != 0 {
		t.Fatalf("state: %+v", state)
	}

	address, address6 := netip.MustParseAddr(peer.Address), netip.MustParseAddr(peer.Address6)
	reaches := func(key netip.Addr, target string) bool {
		return f.net.Reaches("wg0", key, netip.MustParseAddr(target))
	}
	files := answer(t, "files.corp.lan.", "A 192.168.1.20 60", "A 10.99.0.1 60", "AAAA fd00:5::20 3600", "AAAA fd00:9::1 60")

	// not logged in: nobody to answer
	if _, ok := f.s.Resolver(address); ok {
		t.Error("resolver before the login")
	}
	f.s.Learn(address, files)
	if reaches(address, "192.168.1.20") {
		t.Error("learned before the login")
	}

	if answer := f.login(peer, "203.0.113.7"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	upstreams, ok := f.s.Resolver(address)
	if !ok || len(upstreams) != 1 || upstreams[0] != netip.MustParseAddrPort("192.168.1.1:53") {
		t.Fatalf("upstreams: %v %v", upstreams, ok)
	}
	if _, ok := f.s.Resolver(netip.MustParseAddr("10.8.0.99")); ok {
		t.Error("resolver of an address without a peer")
	}

	// its names: the addresses inside the networks, of both versions, at once; not the others
	f.s.Learn(address, files)
	if !reaches(address, "192.168.1.20") || !reaches(address6, "fd00:5::20") || reaches(address, "10.99.0.1") ||
		reaches(address6, "fd00:9::1") {
		t.Fatalf("learned: %+v", f.net.Learned)
	}
	// a wildcard, through an alias; another name, nothing
	f.s.Learn(address, answer(t, "x.apps.lan.", "CNAME x.apps.lan. lb.other.lan.", "A 192.168.1.30 3600 lb.other.lan."))
	f.s.Learn(address, answer(t, "db.corp.lan.", "A 192.168.1.40 3600"))
	f.s.Learn(address, answer(t, "apps.lan.", "A 192.168.1.41 3600"))
	if !reaches(address, "192.168.1.30") || reaches(address, "192.168.1.40") || reaches(address, "192.168.1.41") {
		t.Errorf("names: %+v", f.net.Learned)
	}
	// a whole apply keeps them
	f.s.mu.Lock()
	f.s.applyLocked()
	f.s.mu.Unlock()
	if learned := f.net.State.Servers[0].Peers[0].Learned; len(learned) != 3 || !reaches(address, "192.168.1.30") {
		t.Errorf("applied: %v", learned)
	}

	// the time to live and the margin: 192.168.1.20 closes at the Tick after it, the others stay
	f.clock.advance(60*time.Second + LearnedMargin - time.Second)
	f.handshake(peer, "203.0.113.7")
	f.s.Tick()
	if !reaches(address, "192.168.1.20") {
		t.Fatal("closed before its time")
	}
	f.clock.advance(2 * time.Second)
	f.handshake(peer, "203.0.113.7")
	f.s.Tick()
	if reaches(address, "192.168.1.20") || !reaches(address, "192.168.1.30") || !reaches(address6, "fd00:5::20") {
		t.Fatalf("expired: %+v", f.net.Learned)
	}
	// a new answer opens it again
	f.s.Learn(address, files)
	if !reaches(address, "192.168.1.20") {
		t.Error("not learned again")
	}

	// MaxLearned at most
	var records []string
	for index := range MaxLearned + 10 {
		records = append(records, fmt.Sprintf("A 10.20.%d.%d 3600", index/250, index%250+1))
	}
	f.s.Learn(address, answer(t, "big.apps.lan.", records...))
	if count := len(f.s.learned[peer.ID].until); count != MaxLearned {
		t.Errorf("%d learned", count)
	}

	// its rules change: all forgotten, and the connections it opened to them closed
	peerInput.Access = access("192.168.1.10")
	if _, err := f.s.UpdatePeer(testActor, peer.ID, peerInput); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.net.Forgotten, address) || !slices.Contains(f.net.Forgotten, address6) || len(f.s.learned) != 0 ||
		len(f.net.Learned["wg0"]) != 0 || f.net.State.Servers[0].Peers[0].Names {
		t.Errorf("after a change: %v %+v", f.net.Forgotten, f.net.State.Servers[0].Peers[0])
	}
	if _, ok := f.s.Resolver(address); ok {
		t.Error("resolver without names")
	}
	if _, text, _ = f.s.PeerConfig(testActor, peer.ID); !strings.Contains(text, "DNS = 10.8.0.1, 192.168.1.1\n") {
		t.Errorf("configuration file without names:\n%s", text)
	}

	// names again, learned; then the networks of the server change: forgotten too
	peerInput.Access = access("files.corp.lan")
	if _, err := f.s.UpdatePeer(testActor, peer.ID, peerInput); err != nil {
		t.Fatal(err)
	}
	f.s.Learn(address, files)
	if !reaches(address, "192.168.1.20") {
		t.Fatal("not learned with names again")
	}
	f.net.Forgotten = nil
	input = inputOf(office)
	input.Networks = []string{"192.168.1.0/24"}
	if office, err = f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.net.Forgotten, address) || len(f.s.learned) != 0 || reaches(address, "192.168.1.20") {
		t.Errorf("after the networks changed: %v %+v", f.net.Forgotten, f.net.Learned)
	}

	// the backups keep the names; a restore forgets every learned address and closes every connection to them
	f.s.Learn(address, files)
	data := f.sealed(adminID, func(c *backupContent) {
		if c.Version != BackupVersion || !slices.Equal(c.Peers[0].Access, []string{"files.corp.lan"}) {
			t.Fatalf("content: %+v", c.Peers[0])
		}
	})
	f.net.Forgotten = nil
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if peers, _ := f.db.Q().Peers(0); !slices.Equal(peers[0].Access, []string{"files.corp.lan"}) {
		t.Errorf("restored: %+v", peers[0])
	}
	if len(f.s.learned) != 0 || !slices.Contains(f.net.Forgotten, netip.Addr{}) || len(f.net.Learned["wg0"]) != 0 {
		t.Errorf("after a restore: %v %+v", f.net.Forgotten, f.net.Learned)
	}
}

// A server without a login: the peers with names are always answered. A blocked or disabled peer, a disabled server:
// never.
func TestNamesWithoutLogin(t *testing.T) {
	f := setup(t)
	office := f.server(store.AuthKey)
	peer, err := f.s.CreatePeer(testActor, office.ID, PeerInput{Name: "kiosk", Enabled: true, Access: access("*.corp.lan")})
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(peer.Address)
	// no DNS server for the server: the ones of the container, if it has any
	if upstreams, ok := f.s.Resolver(address); ok != (len(systemResolvers()) > 0) || len(upstreams) != len(systemResolvers()) {
		t.Errorf("upstreams: %v %v", upstreams, ok)
	}
	input := inputOf(office)
	input.DNS = []string{"192.168.1.1"}
	if office, err = f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.Resolver(address); !ok {
		t.Fatal("no resolver without a login")
	}
	f.s.Learn(address, answer(t, "files.corp.lan.", "A 192.168.1.20 60"))
	if !f.net.Reaches("wg0", address, netip.MustParseAddr("192.168.1.20")) {
		t.Error("not learned without a login")
	}
	if err := f.db.Q().SetPeerBlocked(peer.ID, true, f.clock.now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.Resolver(address); ok {
		t.Error("resolver of a blocked peer")
	}
}
