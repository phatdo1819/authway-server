package network

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// The ports of a rule, as an administrator writes them: read in any case and order, written back the same way for the
// same ports, merged, and refused when they make no sense.
func TestParsePorts(t *testing.T) {
	for _, test := range []struct {
		words string
		text  string
	}{
		{"tcp/443", "tcp/443"},
		{"TCP/443", "tcp/443"},
		{"tcp/443,80", "tcp/80,443"},
		{"udp/53 tcp/22", "tcp/22 udp/53"},
		{"tcp/80 tcp/443", "tcp/80,443"},
		{"tcp/8000-8090", "tcp/8000-8090"},
		{"tcp/80-85,84-90,91", "tcp/80-91"},
		{"tcp/1-65535", "tcp/1-65535"},
		{"tcp", "tcp"},
		{"tcp/22 tcp", "tcp"},
		{"tcp tcp/22", "tcp"},
		{"icmp", "icmp"},
		{"icmp tcp/3389 icmp", "tcp/3389 icmp"},
		{"udp tcp/443 icmp", "tcp/443 udp icmp"},
	} {
		ports, ok := ParsePorts(strings.Fields(test.words))
		if !ok || ports.String() != test.text || ports.All() {
			t.Errorf("%q: %v %q", test.words, ok, ports.String())
			continue
		}
		// written back, it reads the same
		again, ok := ParsePorts(strings.Fields(ports.String()))
		if !ok || again.String() != test.text {
			t.Errorf("%q again: %v %q", test.text, ok, again.String())
		}
	}
	tooMany := "tcp/" + strings.Repeat("1,", MaxPortItems) + "2"
	for _, words := range []string{"", "tcp/", "tcp/0", "tcp/65536", "tcp/80-", "tcp/-80", "tcp/90-80", "tcp/+80", "tcp/ 80",
		"tcp/80,", "tcp/,80", "tcp/1e3", "sctp/80", "icmp/8", "443", "http", "tcp/80/90", tooMany} {
		if ports, ok := ParsePorts(strings.Fields(words)); ok {
			t.Errorf("%q: read as %q", words, ports.String())
		}
	}
	if !(Ports{}).All() || (Ports{}).String() != "" {
		t.Error("the zero ports")
	}
}

// The matches of nftables: one rule for each protocol, a single port without a set, ICMPv6 for IPv6.
func TestPortMatches(t *testing.T) {
	ports, _ := ParsePorts([]string{"tcp/22,80-90", "udp/53", "icmp"})
	if got := ports.matches(false); !slices.Equal(got, []string{"tcp dport { 22, 80-90 }", "udp dport 53", "meta l4proto icmp"}) {
		t.Errorf("IPv4: %q", got)
	}
	if got := ports.matches(true); got[2] != "meta l4proto ipv6-icmp" {
		t.Errorf("IPv6: %q", got)
	}
	all, _ := ParsePorts([]string{"udp"})
	if got := all.matches(false); !slices.Equal(got, []string{"meta l4proto udp"}) {
		t.Errorf("all of UDP: %q", got)
	}
	if got := (Ports{}).matches(false); len(got) != 0 {
		t.Errorf("all: %q", got)
	}
}

// Rules with ports: their own rules in the chain of the server, before the drops, for addresses and networks; the
// names with ports learn in a set of their own, used only for that traffic, the stand-in addresses too; the
// connections from the networks of a routed server don't depend on the ports.
func TestRulesWithPorts(t *testing.T) {
	addr, prefix := netip.MustParseAddr, netip.MustParsePrefix
	rdp, _ := ParsePorts([]string{"tcp/3389", "icmp"})
	web, _ := ParsePorts([]string{"tcp/80,443"})
	smb, _ := ParsePorts([]string{"tcp/445"})
	state := State{
		LoginPort: 8181, RedirectPort: 8180, DNSPort: 8153, ResolverPort: 8154,
		StandInNetwork: prefix("198.18.0.0/16"),
		Servers: []Server{{
			Interface: "wg0", Gated: true, Redirect: true, Routed: true, Inbound: true, StandIns: true,
			Address: prefix("10.8.0.1/24"), Address6: prefix("fd00:1::1/64"),
			Networks: []netip.Prefix{prefix("192.168.1.0/24"), prefix("fd00:5::/64")},
			Peers: []Peer{
				{Address: addr("10.8.0.2"), Address6: addr("fd00:1::2"), Access: []netip.Prefix{prefix("192.168.1.20/32")},
					AccessPorts: []PortAccess{{prefix("192.168.1.0/24"), web}, {prefix("192.168.1.5/32"), rdp}, {prefix("fd00:5::5/128"), rdp}}},
				{Address: addr("10.8.0.3"), Address6: addr("fd00:1::3"), Access: []netip.Prefix{}, Names: true,
					Learned:      []netip.Addr{addr("192.168.1.10")},
					NamePorts:    []Ports{smb},
					LearnedPorts: map[string][]netip.Addr{"tcp/445": {addr("192.168.1.11"), addr("fd00:5::11"), addr("198.18.0.7")}}},
				// the same ports, from another peer: one set
				{Address: addr("10.8.0.4"), Address6: addr("fd00:1::4"), Access: []netip.Prefix{}, Names: true, NamePorts: []Ports{smb}},
			},
		}},
	}
	rules := Ruleset(state)
	smbSet, smbSet6 := LearnedPortsSet("wg0", false, "tcp/445"), LearnedPortsSet("wg0", true, "tcp/445")
	if smbSet == LearnedSet("wg0", false) || smbSet == smbSet6 || len(smbSet) > 31 {
		t.Fatalf("sets: %s %s", smbSet, smbSet6)
	}
	order := func(lines ...string) {
		t.Helper()
		at := -1
		for _, line := range lines {
			index := strings.Index(rules, line)
			if index < 0 || index < at {
				t.Fatalf("%q missing or out of order in:\n%s", line, rules)
			}
			at = index
		}
	}
	order(
		"set "+smbSet+" {\n\t\ttype ipv4_addr . ipv4_addr\n\t\telements = { 10.8.0.3 . 192.168.1.11, 10.8.0.3 . 198.18.0.7 }\n\t}",
		"set "+smbSet6+" {\n\t\ttype ipv6_addr . ipv6_addr\n\t\telements = { fd00:1::3 . fd00:5::11 }\n\t}",
		// a stand-in address of a name with ports: only for its ports
		`iifname "wg0" ip saddr @wg0_sessions ip daddr 198.18.0.0/16 ip saddr . ip daddr @wg0_learned ct mark set 0x00415701 dnat ip to ip daddr map @stand_ins`,
		`iifname "wg0" ip saddr @wg0_sessions ip daddr 198.18.0.0/16 ip saddr . ip daddr @`+smbSet+` tcp dport 445 ct mark set 0x00415701 dnat ip to ip daddr map @stand_ins`,
		// from the networks of a routed server: what the rules reach, whatever the ports
		`iifname != "wg*" oifname "wg0" ct direction original ip daddr 10.8.0.2 ip saddr { 192.168.1.20/32 } accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip daddr 10.8.0.2 ip saddr 192.168.1.0/24 accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip daddr 10.8.0.2 ip saddr 192.168.1.5/32 accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip daddr . ip saddr @wg0_learned accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip daddr . ip saddr @`+smbSet+` accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip6 daddr fd00:1::2 ip6 saddr fd00:5::5/128 accept`,
		// the chain of the server: the rules without ports, those with, the names, then the drops
		"ip saddr 10.8.0.2 ip daddr { 192.168.1.20/32 } accept",
		"ip saddr 10.8.0.2 ip daddr 192.168.1.0/24 tcp dport { 80, 443 } accept",
		"ip saddr 10.8.0.2 ip daddr 192.168.1.5/32 tcp dport 3389 accept",
		"ip saddr 10.8.0.2 ip daddr 192.168.1.5/32 meta l4proto icmp accept",
		"ip saddr . ip daddr @wg0_learned ct mark set 0x00415701 accept",
		"ip saddr . ip daddr @"+smbSet+" tcp dport 445 ct mark set 0x00415701 accept",
		"ip saddr { 10.8.0.3, 10.8.0.4 } ct mark 0x00415701 accept",
		"ip saddr { 10.8.0.2, 10.8.0.3, 10.8.0.4 } ip daddr { 192.168.1.0/24 } drop",
		"ip6 saddr fd00:1::2 ip6 daddr fd00:5::5/128 tcp dport 3389 accept",
		"ip6 saddr fd00:1::2 ip6 daddr fd00:5::5/128 meta l4proto ipv6-icmp accept",
		"ip6 saddr . ip6 daddr @"+smbSet6+" tcp dport 445 ct mark set 0x00415701 accept",
	)
	if strings.Count(rules, "set "+smbSet+" {") != 1 {
		t.Errorf("the set of the ports twice:\n%s", rules)
	}
	// an IPv4 rule never in the IPv6 rules, nor the other way
	if strings.Contains(rules, "ip6 daddr 192.168") || strings.Contains(rules, "ip daddr fd00:5::5/") {
		t.Errorf("versions mixed:\n%s", rules)
	}
	// between two Apply: the set of the ports of the rule
	learned := Learned{Peer: addr("10.8.0.3"), Address: addr("192.168.1.12"), Ports: "tcp/445"}
	if command := LearnedCommand(true, "wg0", learned); command != "add element inet authway "+smbSet+" { 10.8.0.3 . 192.168.1.12 }" {
		t.Errorf("command: %s", command)
	}
	learned.Ports = ""
	if command := LearnedCommand(false, "wg0", learned); command != "delete element inet authway wg0_learned { 10.8.0.3 . 192.168.1.12 }" {
		t.Errorf("command: %s", command)
	}
}
