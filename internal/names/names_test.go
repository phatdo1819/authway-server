package names

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParse(t *testing.T) {
	for _, test := range []struct {
		text string
		want string
	}{
		{"files.corp.lan", "files.corp.lan"},
		{" Files.Corp.LAN. ", "files.corp.lan"},
		{"*.corp.lan", "*.corp.lan"},
		{"*.lan", "*.lan"},
		{"_ldap.corp.lan", "_ldap.corp.lan"},
		{"host-1.corp.lan", "host-1.corp.lan"},
	} {
		if rule, ok := Parse(test.text); !ok || rule.String() != test.want {
			t.Errorf("%q: %+v %v", test.text, rule, ok)
		}
	}
	for _, text := range []string{
		"", "*", "*.", "printer", "a.*.lan", "*.*.lan", "-host.corp.lan", "host-.corp.lan", "host..lan", ".corp.lan",
		"192.168.1.10", "192.168.1.300", "10.20", "192.168.1.0/24", "fd00::1", "files.corp.lan:80", "http://corp.lan",
		"bücher.corp.lan", "has space.lan", string(make([]byte, 300)),
	} {
		if rule, ok := Parse(text); ok {
			t.Errorf("%q taken: %+v", text, rule)
		}
	}
}

func TestMatches(t *testing.T) {
	exact, _ := Parse("files.corp.lan")
	wildcard, _ := Parse("*.corp.lan")
	for _, test := range []struct {
		rule Rule
		name string
		want bool
	}{
		{exact, "files.corp.lan.", true},
		{exact, "FILES.corp.lan", true},
		{exact, "a.files.corp.lan", false},
		{exact, "corp.lan", false},
		{wildcard, "files.corp.lan.", true},
		{wildcard, "a.b.corp.lan", true},
		{wildcard, "corp.lan", false},
		{wildcard, "evilcorp.lan", false},
		{wildcard, "corp.lan.evil.com", false},
	} {
		if got := test.rule.Matches(test.name); got != test.want {
			t.Errorf("%s matches %s: %v", test.rule, test.name, got)
		}
	}
	rules := Rules([]string{"192.168.1.10/32", "files.corp.lan", "*.apps.lan"})
	if len(rules) != 2 || !Match(rules, "x.apps.lan") || Match(rules, "apps.lan") || Match(rules, "192.168.1.10") {
		t.Errorf("rules: %+v", rules)
	}
}

// reply builds the answer of a DNS server to a query for name
func reply(t *testing.T, name string, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
	t.Helper()
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true, RCode: rcode},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   answers,
	}
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func header(name string, kind dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET, TTL: ttl}
}

func a(name string, ttl uint32, address string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, dnsmessage.TypeA, ttl), Body: &dnsmessage.AResource{A: netip.MustParseAddr(address).As4()}}
}

func aaaa(name string, ttl uint32, address string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, dnsmessage.TypeAAAA, ttl), Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(address).As16()}}
}

func cname(name string, ttl uint32, target string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: header(name, dnsmessage.TypeCNAME, ttl), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}}
}

func TestAnswer(t *testing.T) {
	// the addresses of the name, through its aliases in any order, with the shortest time to live on the way; not
	// the ones of other names
	data := reply(t, "WWW.corp.lan.", dnsmessage.RCodeSuccess,
		cname("lb.corp.lan.", 60, "pool.corp.lan."),
		cname("www.corp.lan.", 3600, "lb.corp.lan."),
		a("pool.corp.lan.", 300, "192.168.1.20"),
		aaaa("pool.corp.lan.", 30, "fd00:5::20"),
		a("other.corp.lan.", 300, "192.168.1.99"),
		aaaa("pool.corp.lan.", 300, "::ffff:192.168.1.21"),
	)
	name, addresses, ok := Answer(data)
	if !ok || name != "www.corp.lan" || len(addresses) != 2 {
		t.Fatalf("%s %+v %v", name, addresses, ok)
	}
	if addresses[0] != (Address{netip.MustParseAddr("192.168.1.20"), 60 * time.Second}) ||
		addresses[1] != (Address{netip.MustParseAddr("fd00:5::20"), 30 * time.Second}) {
		t.Errorf("addresses: %+v", addresses)
	}

	// a loop of aliases ends
	if _, addresses, ok := Answer(reply(t, "a.corp.lan.", dnsmessage.RCodeSuccess, cname("a.corp.lan.", 60, "b.corp.lan."),
		cname("b.corp.lan.", 60, "a.corp.lan."), a("b.corp.lan.", 60, "192.168.1.5"))); !ok || len(addresses) != 1 {
		t.Errorf("loop: %+v %v", addresses, ok)
	}
	// nothing from an error, a query, or what isn't DNS
	if _, _, ok := Answer(reply(t, "a.corp.lan.", dnsmessage.RCodeNameError)); ok {
		t.Error("NXDOMAIN read")
	}
	query, _ := (&dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.corp.lan."),
		Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if _, _, ok := Answer(query); ok {
		t.Error("query read")
	}
	for _, bad := range [][]byte{nil, []byte("hello"), data[:len(data)-3]} {
		if _, _, ok := Answer(bad); ok {
			t.Errorf("read %q", bad)
		}
	}
}

func TestRefused(t *testing.T) {
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.corp.lan."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	var parser dnsmessage.Parser
	header, err := parser.Start(Refused(query))
	if err != nil || header.ID != 42 || !header.Response || header.RCode != dnsmessage.RCodeServerFailure || !header.RecursionDesired {
		t.Fatalf("%+v %v", header, err)
	}
	if question, err := parser.Question(); err != nil || question.Name.String() != "a.corp.lan." {
		t.Errorf("question: %+v %v", question, err)
	}
	if Refused(Refused(query)) != nil || Refused([]byte("x")) != nil {
		t.Error("a reply or garbage refused")
	}
}
