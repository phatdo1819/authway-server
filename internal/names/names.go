// Package names reads the names of the access rules of the peers, and the DNS answers that give their addresses. A
// rule is a name, files.corp.lan, or a wildcard for every name under one, *.corp.lan.
package names

import (
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
