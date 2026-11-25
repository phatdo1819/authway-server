package names

import (
	"bytes"
	"net/netip"
	"slices"
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

func TestRewrite(t *testing.T) {
	addr := netip.MustParseAddr
	https := dnsmessage.Resource{Header: header("app.example.com.", dnsmessage.TypeHTTPS, 300), Body: &dnsmessage.HTTPSResource{
		SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."),
			Params: []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamIPv4Hint, Value: []byte{203, 0, 113, 10}}}}}}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 99, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA,
			Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			cname("app.example.com.", 300, "edge.cdn.example.net."),
			a("edge.cdn.example.net.", 60, "203.0.113.10"),
			a("edge.cdn.example.net.", 60, "192.168.1.20"),
			aaaa("edge.cdn.example.net.", 60, "2001:db8::10"),
			aaaa("edge.cdn.example.net.", 60, "fd00:5::20"),
			https,
		},
		Additionals: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."),
			Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{}}},
	}
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// an IPv4 address for another, an IPv6 one gone, the HTTPS record gone: the rest as it was
	got, ok := Rewrite(data, map[netip.Addr]netip.Addr{addr("203.0.113.10"): addr("198.18.0.5"), addr("2001:db8::10"): {}}, nil)
	if !ok {
		t.Fatal("not rewritten")
	}
	var result dnsmessage.Message
	if err := result.Unpack(got); err != nil {
		t.Fatal(err)
	}
	if result.Header != message.Header || len(result.Questions) != 1 || len(result.Additionals) != 1 ||
		result.Additionals[0].Header.Type != dnsmessage.TypeOPT || result.Additionals[0].Header.Class != 1232 {
		t.Errorf("header, question or EDNS changed: %+v", result)
	}
	var records []string
	for _, record := range result.Answers {
		switch body := record.Body.(type) {
		case *dnsmessage.CNAMEResource:
			records = append(records, "CNAME "+body.CNAME.String())
		case *dnsmessage.AResource:
			records = append(records, "A "+netip.AddrFrom4(body.A).String())
		case *dnsmessage.AAAAResource:
			records = append(records, "AAAA "+netip.AddrFrom16(body.AAAA).String())
		default:
			records = append(records, record.Header.Type.String())
		}
	}
	if want := []string{"CNAME edge.cdn.example.net.", "A 198.18.0.5", "A 192.168.1.20", "AAAA fd00:5::20"}; !slices.Equal(records, want) {
		t.Errorf("answers: %v", records)
	}
	// still read as an answer to the name, with the TTL of the address it replaces
	if name, addresses, ok := Answer(got); !ok || name != "app.example.com" || len(addresses) != 3 ||
		addresses[0] != (Address{addr("198.18.0.5"), 60 * time.Second}) {
		t.Errorf("answer: %s %+v %v", name, addresses, ok)
	}

	// nothing to change: the same bytes
	plain := reply(t, "files.corp.lan.", dnsmessage.RCodeSuccess, a("files.corp.lan.", 60, "192.168.1.20"))
	if same, ok := Rewrite(plain, map[netip.Addr]netip.Addr{addr("203.0.113.10"): addr("198.18.0.5")}, nil); !ok || !bytes.Equal(same, plain) {
		t.Errorf("unchanged: %v %v", same, ok)
	}
	// an address of the wrong version for its record goes
	if got, ok := Rewrite(plain, map[netip.Addr]netip.Addr{addr("192.168.1.20"): addr("fd00::1")}, nil); !ok {
		t.Error("not rewritten")
	} else if _, addresses, _ := Answer(got); len(addresses) != 0 {
		t.Errorf("wrong version kept: %+v", addresses)
	}
	for _, bad := range [][]byte{nil, []byte("hello"), data[:len(data)-3]} {
		if _, ok := Rewrite(bad, nil, nil); ok {
			t.Errorf("rewrote %q", bad)
		}
	}
}

// The option of the Authway app: taken out of its queries before they go on, and in the answers, the routes for it,
// only from Authway Server.
func TestRoutesOption(t *testing.T) {
	addr := netip.MustParseAddr
	opt := func(options ...dnsmessage.Option) dnsmessage.Resource {
		var header dnsmessage.ResourceHeader
		if err := header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		return dnsmessage.Resource{Header: header, Body: &dnsmessage.OPTResource{Options: options}}
	}
	cookie := dnsmessage.Option{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
	query := func(additionals ...dnsmessage.Resource) []byte {
		data, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 9, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("app.example.com."), Type: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET}}, Additionals: additionals}).Pack()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	asking := query(opt(cookie, dnsmessage.Option{Code: RoutesOption}))
	stripped, asked := TakeRoutes(asking)
	var message dnsmessage.Message
	if err := message.Unpack(stripped); !asked || err != nil || len(message.Additionals) != 1 {
		t.Fatalf("taken: %v %v %+v", asked, err, message)
	}
	if options := message.Additionals[0].Body.(*dnsmessage.OPTResource).Options; len(options) != 1 || options[0].Code != 10 {
		t.Errorf("the other options: %+v", options)
	}
	for _, plain := range [][]byte{query(), query(opt(cookie)), []byte("junk")} {
		if got, asked := TakeRoutes(plain); asked || !bytes.Equal(got, plain) {
			t.Errorf("not asking: %v", asked)
		}
	}

	// the routes in the answer, an OPT record made when the reply has none
	routes := []Address{{addr("203.0.113.10"), 15 * time.Minute}, {addr("2001:db8::10"), 90 * time.Second}}
	for _, base := range [][]byte{reply(t, "app.example.com.", dnsmessage.RCodeSuccess, a("app.example.com.", 60, "203.0.113.10")),
		withOPT(t, reply(t, "app.example.com.", dnsmessage.RCodeSuccess, a("app.example.com.", 60, "203.0.113.10")))} {
		got, ok := Rewrite(base, nil, routes)
		if !ok {
			t.Fatal("not rewritten")
		}
		if read := Routes(got); len(read) != 2 || read[0] != routes[0] || read[1] != routes[1] {
			t.Errorf("routes: %+v", read)
		}
		// another DNS server can't give the app routes: Authway Server replaces them, or takes them out
		again, _ := Rewrite(got, nil, routes[:1])
		if read := Routes(again); len(read) != 1 {
			t.Errorf("replaced: %+v", read)
		}
		if read := Routes(WithoutRoutes(got)); len(read) != 0 {
			t.Errorf("not taken out: %+v", read)
		}
	}
	if Routes(reply(t, "x.", dnsmessage.RCodeSuccess)) != nil || Routes([]byte("junk")) != nil {
		t.Error("routes from nothing")
	}
	// at least a second, as the app reads them
	if read := Routes(mustRewrite(t, reply(t, "x.", dnsmessage.RCodeSuccess), []Address{{addr("203.0.113.1"), 0}})); len(read) != 1 ||
		read[0].TTL != time.Second {
		t.Errorf("short: %+v", read)
	}
}

func mustRewrite(t *testing.T, data []byte, routes []Address) []byte {
	t.Helper()
	got, ok := Rewrite(data, nil, routes)
	if !ok {
		t.Fatal("not rewritten")
	}
	return got
}

// withOPT adds an OPT record to a reply, as a DNS server that knows EDNS answers
func withOPT(t *testing.T, data []byte) []byte {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(data); err != nil {
		t.Fatal(err)
	}
	var header dnsmessage.ResourceHeader
	if err := header.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	message.Additionals = append(message.Additionals, dnsmessage.Resource{Header: header, Body: &dnsmessage.OPTResource{}})
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
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
