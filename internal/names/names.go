// Package names reads the names of the access rules of the peers, and the DNS answers that give their addresses. A
// rule is a name, files.corp.lan, or a wildcard for every name under one, *.corp.lan.
package names

import (
	"encoding/binary"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// MaxLength is the longest name, as DNS writes them.
const MaxLength = 253

// a label of a name: letters, digits, hyphens inside, and the underscores that some names of the local networks have
var label = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// Rule is a name, or with Wildcard every name under it, at any depth, but not the name itself.
type Rule struct {
	Name     string
	Wildcard bool
}

// Parse reads a rule as an administrator writes it: files.corp.lan or *.corp.lan, in any case, with a final dot or
// not. A name alone has two labels at least: a single one is more likely a typo than a host, and the devices ask for
// it with their search domain anyway. false for anything else, an address too.
func Parse(text string) (Rule, bool) {
	text = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(text), "."))
	rule := Rule{Name: text}
	if rest, ok := strings.CutPrefix(text, "*."); ok {
		rule = Rule{Name: rest, Wildcard: true}
	}
	if rule.Name == "" || len(rule.Name) > MaxLength {
		return Rule{}, false
	}
	labels := strings.Split(rule.Name, ".")
	if !rule.Wildcard && len(labels) < 2 {
		return Rule{}, false
	}
	for _, part := range labels {
		if !label.MatchString(part) {
			return Rule{}, false
		}
	}
	// digits only at the end: an address written wrong, 192.168.1.300 say
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return Rule{}, false
	}
	return rule, true
}

// String writes the rule as Parse reads it.
func (r Rule) String() string {
	if r.Wildcard {
		return "*." + r.Name
	}
	return r.Name
}

// Matches tells whether a name asked of DNS is the one of the rule, or under it for a wildcard.
func (r Rule) Matches(name string) bool {
	name = normal(name)
	if r.Wildcard {
		return strings.HasSuffix(name, "."+r.Name)
	}
	return name == r.Name
}

// Rules are the names of a list of access rules: the entries that are names, not addresses or networks.
func Rules(entries []string) []Rule {
	var rules []Rule
	for _, entry := range entries {
		if rule, ok := Parse(entry); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

// Match tells whether a name is one of the rules.
func Match(rules []Rule, name string) bool {
	for _, rule := range rules {
		if rule.Matches(name) {
			return true
		}
	}
	return false
}

func normal(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Address is an address that an answer gives for the name asked, and for how long the answer holds.
type Address struct {
	Addr netip.Addr
	TTL  time.Duration
}

// maxAliases is the longest chain of aliases followed in an answer
const maxAliases = 16

// Answer reads the reply of a DNS server: the name asked, and the addresses of that name in the answers, through the
// aliases (CNAME) of the answer, each with the shortest time to live on its way. false for anything but a successful
// reply to one question.
func Answer(reply []byte) (string, []Address, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(reply)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return "", nil, false
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Class != dnsmessage.ClassINET {
		return "", nil, false
	}
	asked := normal(questions[0].Name.String())
	type alias struct {
		target string
		ttl    uint32
	}
	type record struct {
		owner string
		addr  netip.Addr
		ttl   uint32
	}
	aliases := map[string]alias{}
	var records []record
	for {
		answer, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", nil, false
		}
		owner := normal(answer.Name.String())
		switch {
		case answer.Class != dnsmessage.ClassINET:
			err = parser.SkipAnswer()
		case answer.Type == dnsmessage.TypeCNAME:
			var resource dnsmessage.CNAMEResource
			if resource, err = parser.CNAMEResource(); err == nil {
				aliases[owner] = alias{normal(resource.CNAME.String()), answer.TTL}
			}
		case answer.Type == dnsmessage.TypeA:
			var resource dnsmessage.AResource
			if resource, err = parser.AResource(); err == nil {
				records = append(records, record{owner, netip.AddrFrom4(resource.A), answer.TTL})
			}
		case answer.Type == dnsmessage.TypeAAAA:
			var resource dnsmessage.AAAAResource
			if resource, err = parser.AAAAResource(); err == nil {
				if addr := netip.AddrFrom16(resource.AAAA); !addr.Is4In6() {
					records = append(records, record{owner, addr, answer.TTL})
				}
			}
		default:
			err = parser.SkipAnswer()
		}
		if err != nil {
			return "", nil, false
		}
	}
	// the names of the chain from the name asked, with the shortest time to live on the way to each
	reach := map[string]uint32{asked: math.MaxUint32}
	for name, count := asked, 0; count < maxAliases; count++ {
		next, ok := aliases[name]
		if !ok {
			break
		}
		if _, loop := reach[next.target]; loop {
			break
		}
		reach[next.target] = min(reach[name], next.ttl)
		name = next.target
	}
	var addresses []Address
	for _, r := range records {
		if limit, ok := reach[r.owner]; ok {
			addresses = append(addresses, Address{Addr: r.addr, TTL: time.Duration(min(limit, r.ttl)) * time.Second})
		}
	}
	return asked, addresses, true
}

// RoutesOption is the EDNS option of the Authway app (a code for local use, RFC 6891). In a query, empty: the device
// routes the internet addresses of the names through the tunnel itself, so the answer keeps them as they are. In the
// answer, the addresses to route and for how long: for each one, 4 or 6, the address, then the seconds on 4 bytes.
const RoutesOption = 65430

// TakeRoutes tells whether a query asks for the routes of its answer, and returns it without the option, as the DNS
// servers get it: the query as it was when it doesn't ask.
func TakeRoutes(query []byte) ([]byte, bool) {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil || !dropRoutes(&message) {
		return query, false
	}
	data, err := message.Pack()
	if err != nil {
		// the DNS servers ignore an option they don't know
		return query, true
	}
	return data, true
}

// WithoutRoutes is a reply without RoutesOption: only Authway Server gives the device routes, never another DNS
// server. The reply as it was when it has none.
func WithoutRoutes(reply []byte) []byte {
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil || !dropRoutes(&message) {
		return reply
	}
	if data, err := message.Pack(); err == nil {
		return data
	}
	return reply
}

// dropRoutes takes RoutesOption out of a message: true when it had it
func dropRoutes(message *dnsmessage.Message) bool {
	found := false
	for _, record := range message.Additionals {
		opt, ok := record.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		kept := opt.Options[:0]
		for _, option := range opt.Options {
			if option.Code == RoutesOption {
				found = true
				continue
			}
			kept = append(kept, option)
		}
		opt.Options = kept
	}
	return found
}

// routesData is the data of RoutesOption in an answer
func routesData(routes []Address) []byte {
	var data []byte
	for _, route := range routes {
		seconds := int64(route.TTL / time.Second)
		seconds = min(max(seconds, 1), math.MaxUint32)
		if route.Addr.Is4() {
			address := route.Addr.As4()
			data = append(append(data, 4), address[:]...)
		} else {
			address := route.Addr.As16()
			data = append(append(data, 6), address[:]...)
		}
		data = binary.BigEndian.AppendUint32(data, uint32(seconds))
	}
	return data
}

// Routes reads the routes of an answer, as the Authway app does: none without RoutesOption.
func Routes(reply []byte) []Address {
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil {
		return nil
	}
	var routes []Address
	for _, record := range message.Additionals {
		opt, ok := record.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			data := option.Data
			for option.Code == RoutesOption && len(data) > 0 {
				size := map[byte]int{4: 4, 6: 16}[data[0]]
				if size == 0 || len(data) < 1+size+4 {
					break
				}
				address, _ := netip.AddrFromSlice(data[1 : 1+size])
				seconds := binary.BigEndian.Uint32(data[1+size:])
				routes = append(routes, Address{Addr: address, TTL: time.Duration(seconds) * time.Second})
				data = data[1+size+4:]
			}
		}
	}
	return routes
}

// Rewrite changes the addresses of a reply: each A or AAAA record whose address is a key of change gets the address
// it maps to, of the same version, or goes when that one is invalid. The HTTPS and SVCB records go too, whatever
// change holds: their hints would give the device addresses that the rest of the reply doesn't. With routes, the
// reply tells the Authway app which addresses to route through the tunnel, in RoutesOption. The reply as it was when
// nothing changes; false when it can't be read or written again.
func Rewrite(reply []byte, change map[netip.Addr]netip.Addr, routes []Address) ([]byte, bool) {
	var message dnsmessage.Message
	if err := message.Unpack(reply); err != nil {
		return nil, false
	}
	changed := dropRoutes(&message)
	edit := func(records []dnsmessage.Resource) []dnsmessage.Resource {
		kept := records[:0]
		for _, record := range records {
			switch body := record.Body.(type) {
			case *dnsmessage.AResource:
				if to, ok := change[netip.AddrFrom4(body.A)]; ok {
					changed = true
					if !to.Is4() {
						continue
					}
					body.A = to.As4()
				}
			case *dnsmessage.AAAAResource:
				if to, ok := change[netip.AddrFrom16(body.AAAA)]; ok {
					changed = true
					if !to.Is6() || to.Is4In6() {
						continue
					}
					body.AAAA = to.As16()
				}
			case *dnsmessage.HTTPSResource, *dnsmessage.SVCBResource:
				changed = true
				continue
			}
			kept = append(kept, record)
		}
		return kept
	}
	message.Answers = edit(message.Answers)
	message.Authorities = edit(message.Authorities)
	message.Additionals = edit(message.Additionals)
	if len(routes) > 0 {
		var opt *dnsmessage.OPTResource
		for _, record := range message.Additionals {
			if found, ok := record.Body.(*dnsmessage.OPTResource); ok {
				opt = found
				break
			}
		}
		if opt == nil {
			// the query of the app has one: a DNS server that doesn't know EDNS answers without it
			var header dnsmessage.ResourceHeader
			if err := header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
				return nil, false
			}
			opt = &dnsmessage.OPTResource{}
			message.Additionals = append(message.Additionals, dnsmessage.Resource{Header: header, Body: opt})
		}
		opt.Options = append(opt.Options, dnsmessage.Option{Code: RoutesOption, Data: routesData(routes)})
		changed = true
	}
	if !changed {
		return reply, true
	}
	data, err := message.Pack()
	if err != nil {
		return nil, false
	}
	return data, true
}

// Refused is the reply that says a query can't be answered now (SERVFAIL), for a query whose DNS servers didn't
// answer: the device tries again, or its next server. nil for what isn't a query.
func Refused(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.Response {
		return nil
	}
	questions, err := parser.AllQuestions()
	if err != nil {
		return nil
	}
	reply := dnsmessage.Message{
		Header: dnsmessage.Header{ID: header.ID, Response: true, OpCode: header.OpCode, RecursionDesired: header.RecursionDesired,
			RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure},
		Questions: questions,
	}
	data, err := reply.Pack()
	if err != nil {
		return nil
	}
	return data
}
