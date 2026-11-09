package network

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRuleset(t *testing.T) {
	state := State{
		LoginPort: 8181, RedirectPort: 8180, DNSPort: 8153,
		Servers: []Server{
			{
				Interface: "wg0",
				Address:   netip.MustParsePrefix("10.8.0.1/24"),
				Gated:     true,
				Networks:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("172.16.0.0/16")},
				Peers: []Peer{
					{Address: netip.MustParseAddr("10.8.0.2")},
					{Address: netip.MustParseAddr("10.8.0.3"), RouteAll: true},
				},
				Sessions: []netip.Addr{netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.2")},
			},
			{Interface: "wg1", Address: netip.MustParsePrefix("10.8.1.1/24")},
		},
	}
	rules := Ruleset(state)
	for _, want := range []string{
		"table inet authway\ndelete table inet authway\ntable inet authway {\n",
		"set wg0_sessions {\n\t\ttype ipv4_addr\n\t\telements = { 10.8.0.2 }\n\t}",
		"set wg0_route_all {\n\t\ttype ipv4_addr\n\t\telements = { 10.8.0.3 }\n\t}",
		"set wg1_route_all {\n\t\ttype ipv4_addr\n\t}",
		`iifname "wg0" ip daddr 10.8.0.1 tcp dport 8181 accept`,
		`iifname "wg0" ip daddr 10.8.0.1 icmp type echo-request accept`,
		// the ports of the login page are closed to the other interfaces, without any redirect too
		"tcp dport { 8181, 8180 } drop",
		"udp dport 8153 drop",
		`iifname "wg0" ip saddr != @wg0_sessions meta l4proto tcp reject with tcp reset`,
		`iifname "wg0" ip saddr != @wg0_sessions reject with icmpx type admin-prohibited`,
		`oifname "wg0" ip daddr != @wg0_sessions drop`,
		"ip daddr { 192.168.1.0/24, 172.16.0.0/16 } accept",
		`ip saddr 10.8.0.0/24 oifname != "wg*" masquerade`,
		`ip saddr 10.8.1.0/24 oifname != "wg*" masquerade`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in:\n%s", want, rules)
		}
	}
	// the server without login has no gate
	if strings.Contains(rules, "wg1_sessions") {
		t.Error("wg1 has a gate")
	}
	// without Redirect, no redirect
	if strings.Contains(rules, "prerouting") || strings.Contains(rules, "redirect to") ||
		strings.Contains(rules, `"wg0" ip daddr 10.8.0.1 udp dport 8153`) {
		t.Error("redirects without Redirect")
	}
	// the gate and the rules of each server come before the established connections: a logout, fewer networks or a
	// peer that no longer sends all its traffic cut the connections already open
	forward := strings.Index(rules, "chain forward {")
	established := forward + strings.Index(rules[forward:], "ct state established,related accept")
	for _, before := range []string{
		`iifname "wg0" ip saddr != @wg0_sessions meta l4proto tcp reject`,
		`iifname "wg0" jump wg0_forward`,
		`iifname "wg1" jump wg1_forward`,
	} {
		if at := strings.Index(rules, before); at < forward || at > established {
			t.Errorf("%q must come before the established connections in forward:\n%s", before, rules)
		}
	}
	// each chain of a server ends with a verdict: no packet of a peer goes back to the established connections
	for _, chain := range []string{"chain wg0_forward {", "chain wg1_forward {"} {
		start := strings.Index(rules, chain)
		end := start + strings.Index(rules[start:], "\n\t}")
		if !strings.HasSuffix(rules[start:end], "\t\tdrop") {
			t.Errorf("%s doesn't end with drop:\n%s", chain, rules[start:end])
		}
	}
	if strings.Count(rules, "{") != strings.Count(rules, "}") {
		t.Error("unbalanced braces")
	}
}

func TestRedirect(t *testing.T) {
	state := State{
		LoginPort: 8181, RedirectPort: 8180, DNSPort: 8153,
		Servers: []Server{
			{Interface: "wg0", Address: netip.MustParsePrefix("10.8.0.1/24"), Gated: true, Redirect: true},
			// a server without login has nothing to redirect to
			{Interface: "wg1", Address: netip.MustParsePrefix("10.8.1.1/24"), Redirect: true},
		},
	}
	rules := Ruleset(state)
	for _, want := range []string{
		"type nat hook prerouting priority dstnat; policy accept;",
		`iifname "wg0" ip saddr != @wg0_sessions udp dport 53 limit rate 100/second redirect to :8153`,
		`iifname "wg0" ip saddr != @wg0_sessions tcp dport 80 redirect to :8180`,
		`iifname "wg0" ip daddr 10.8.0.1 tcp dport 8180 accept`,
		`iifname "wg0" ip daddr 10.8.0.1 udp dport 8153 accept`,
		"tcp dport { 8181, 8180 } drop",
		"udp dport 8153 drop",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, `iifname "wg1" ip saddr`) || strings.Contains(rules, `"wg1" ip daddr 10.8.1.1 udp dport 8153`) {
		t.Errorf("wg1 has a gate or a redirect:\n%s", rules)
	}
}

func TestPeerTraffic(t *testing.T) {
	state := State{
		LoginPort: 8181,
		Servers: []Server{
			// wg9 isn't applied: disabled, or deleted
			{Interface: "wg0", Address: netip.MustParsePrefix("10.8.0.1/24"), Gated: true, ClientToClient: true, Reaches: []string{"wg1", "wg9"}},
			{Interface: "wg1", Address: netip.MustParsePrefix("10.8.1.1/24")},
			{Interface: "wg2", Address: netip.MustParsePrefix("10.8.2.1/24")},
		},
	}
	rules := Ruleset(state)
	chain := func(name string) string {
		start := strings.Index(rules, "chain "+name+" {")
		if start < 0 {
			t.Fatalf("no chain %s:\n%s", name, rules)
		}
		end := strings.Index(rules[start:], "\n\t}")
		return rules[start : start+end]
	}
	// before the drop of the other tunnels
	order := func(text string, lines ...string) {
		t.Helper()
		at := -1
		for _, line := range lines {
			index := strings.Index(text, line)
			if index < 0 || index < at {
				t.Fatalf("%q missing or out of order in:\n%s", line, text)
			}
			at = index
		}
	}
	order(chain("wg0_forward"), `oifname "wg0" accept`, `oifname "wg1" accept`, `oifname "wg*" drop`)
	// the answers of wg1, never its new connections
	order(chain("wg1_forward"), `oifname "wg0" ct state established,related accept`, `oifname "wg*" drop`)
	for _, unwanted := range []string{`oifname "wg9"`, `oifname "wg1" accept`, `oifname "wg2"`} {
		if strings.Contains(chain("wg1_forward"), unwanted) || strings.Contains(chain("wg2_forward"), unwanted) {
			t.Errorf("%s in:\n%s", unwanted, rules)
		}
	}
	if strings.Contains(rules, `oifname "wg9"`) {
		t.Errorf("a server not applied is reached:\n%s", rules)
	}
	// the gate of wg0 comes first: both peers must be logged in
	order(rules, `oifname "wg0" ip daddr != @wg0_sessions drop`, `iifname "wg0" jump wg0_forward`, "chain wg0_forward")
}

// a routed server keeps the addresses of its peers towards its networks, and the internet of its peers still goes
// out translated; with Inbound its networks start connections to its peers, logged in, and nothing else does
func TestRouted(t *testing.T) {
	state := State{
		LoginPort: 8181,
		Servers: []Server{
			{
				Interface: "wg0", Gated: true, Routed: true, Inbound: true,
				Address:  netip.MustParsePrefix("10.8.0.1/24"),
				Address6: netip.MustParsePrefix("fd00:1:2:3::1/64"),
				Networks: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8:5::/64")},
			},
			{Interface: "wg1", Routed: true, Address: netip.MustParsePrefix("10.8.1.1/24"),
				Networks: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/16")}},
			// translated: its network sees the container, and starts nothing to its peers
			{Interface: "wg2", Address: netip.MustParsePrefix("10.8.2.1/24"),
				Networks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}},
		},
	}
	rules := Ruleset(state)
	for _, want := range []string{
		`ip saddr 10.8.0.0/24 oifname != "wg*" ip daddr != { 192.168.1.0/24 } masquerade`,
		`ip6 saddr fd00:1:2:3::/64 oifname != "wg*" ip6 daddr != { 2001:db8:5::/64 } masquerade`,
		`ip saddr 10.8.1.0/24 oifname != "wg*" ip daddr != { 172.16.0.0/16 } masquerade`,
		`ip saddr 10.8.2.0/24 oifname != "wg*" masquerade`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in:\n%s", want, rules)
		}
	}
	start := strings.Index(rules, "chain forward {")
	forward := rules[start : start+strings.Index(rules[start:], "\n\t}")]
	order := func(lines ...string) {
		t.Helper()
		at := -1
		for _, line := range lines {
			index := strings.Index(forward, line)
			if index < 0 || index < at {
				t.Fatalf("%q missing or out of order in:\n%s", line, forward)
			}
			at = index
		}
	}
	// the gate first: only the peers logged in; the jumps of the peers before, their packets never come here
	order(`oifname "wg0" ip daddr != @wg0_sessions drop`, `oifname "wg0" ip6 daddr != @wg0_sessions6 drop`,
		`iifname "wg2" jump wg2_forward`,
		`iifname != "wg*" oifname "wg0" ct direction original ip saddr { 192.168.1.0/24 } accept`,
		`iifname != "wg*" oifname "wg0" ct direction original ip6 saddr { 2001:db8:5::/64 } accept`,
		`oifname "wg0" ct direction original drop`,
		`oifname "wg1" ct direction original drop`,
		`oifname "wg2" ct direction original drop`,
		"ct state established,related accept")
	if strings.Count(forward, "ct direction original ip") != 2 {
		t.Errorf("connections from outside to the peers of wg1 or wg2:\n%s", forward)
	}
	if strings.Count(rules, "{") != strings.Count(rules, "}") {
		t.Error("unbalanced braces")
	}
}

func TestSessionCommand(t *testing.T) {
	address := netip.MustParseAddr("10.8.0.2")
	if got := SessionCommand(true, "wg0", address); got != "add element inet authway wg0_sessions { 10.8.0.2 }" {
		t.Error(got)
	}
	if got := SessionCommand(false, "wg0", address); got != "delete element inet authway wg0_sessions { 10.8.0.2 }" {
		t.Error(got)
	}
}

// IPv6 goes through the same gate as IPv4, on the servers with an IPv6 network; the gated servers without one have
// the IPv6 gate too, and every server without one drops IPv6
func TestRulesetIPv6(t *testing.T) {
	state := State{
		LoginPort: 8181, RedirectPort: 8180, DNSPort: 8153,
		Servers: []Server{
			{
				Interface: "wg0", Gated: true, Redirect: true,
				Address:  netip.MustParsePrefix("10.8.0.1/24"),
				Address6: netip.MustParsePrefix("fd00:1:2:3::1/64"),
				Networks: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("2001:db8:5::/64")},
				Peers: []Peer{
					{Address: netip.MustParseAddr("10.8.0.2"), Address6: netip.MustParseAddr("fd00:1:2:3::2")},
					{Address: netip.MustParseAddr("10.8.0.3"), Address6: netip.MustParseAddr("fd00:1:2:3::3"), RouteAll: true},
				},
				Sessions: []netip.Addr{netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("fd00:1:2:3::2")},
			},
			// gated, without IPv6: an IPv6 network of the networks it reaches isn't used
			{Interface: "wg1", Gated: true, Address: netip.MustParsePrefix("10.8.1.1/24"),
				Networks: []netip.Prefix{netip.MustParsePrefix("2001:db8:6::/64")}},
		},
	}
	rules := Ruleset(state)
	chain := func(name string) string {
		start := strings.Index(rules, "chain "+name+" {")
		if start < 0 {
			t.Fatalf("no chain %s:\n%s", name, rules)
		}
		return rules[start : start+strings.Index(rules[start:], "\n\t}")]
	}
	for _, want := range []string{
		"set wg0_sessions {\n\t\ttype ipv4_addr\n\t\telements = { 10.8.0.2 }\n\t}",
		"set wg0_sessions6 {\n\t\ttype ipv6_addr\n\t\telements = { fd00:1:2:3::2 }\n\t}",
		"set wg0_route_all6 {\n\t\ttype ipv6_addr\n\t\telements = { fd00:1:2:3::3 }\n\t}",
		"set wg1_sessions6 {\n\t\ttype ipv6_addr\n\t}",
		`iifname "wg0" ip6 daddr fd00:1:2:3::1 icmpv6 type echo-request accept`,
		`iifname "wg0" ip6 daddr fd00:1:2:3::1 tcp dport 8181 accept`,
		`iifname "wg0" ip6 daddr fd00:1:2:3::1 tcp dport 8180 accept`,
		`iifname "wg0" ip6 daddr fd00:1:2:3::1 udp dport 8153 accept`,
		`iifname "wg0" ip6 saddr != @wg0_sessions6 udp dport 53 limit rate 100/second redirect to :8153`,
		`iifname "wg0" ip6 saddr != @wg0_sessions6 tcp dport 80 redirect to :8180`,
		`ip6 saddr fd00:1:2:3::/64 oifname != "wg*" masquerade`,
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q in:\n%s", want, rules)
		}
	}
	// the gate of both versions comes before the rules of the servers and the established connections, on both
	// gated servers
	forward := chain("forward")
	for _, iface := range []string{"wg0", "wg1"} {
		jump := strings.Index(forward, `iifname "`+iface+`" jump`)
		for _, gate := range []string{
			`iifname "` + iface + `" ip6 saddr != @` + iface + `_sessions6 meta l4proto tcp reject with tcp reset`,
			`iifname "` + iface + `" ip6 saddr != @` + iface + `_sessions6 reject with icmpx type admin-prohibited`,
			`oifname "` + iface + `" ip6 daddr != @` + iface + `_sessions6 drop`,
		} {
			if at := strings.Index(forward, gate); at < 0 || at > jump {
				t.Errorf("%q missing or after the jump in:\n%s", gate, forward)
			}
		}
	}
	wg0, wg1 := chain("wg0_forward"), chain("wg1_forward")
	for _, want := range []string{"ip6 saddr @wg0_route_all6 accept", "ip6 daddr { 2001:db8:5::/64 } accept", "ip daddr { 192.168.1.0/24 } accept"} {
		if !strings.Contains(wg0, want) {
			t.Errorf("missing %q in:\n%s", want, wg0)
		}
	}
	if strings.Contains(wg0, "meta nfproto ipv6 drop") {
		t.Errorf("wg0 drops IPv6:\n%s", wg0)
	}
	if !strings.HasPrefix(strings.TrimSpace(strings.SplitN(wg1, "\n", 2)[1]), "meta nfproto ipv6 drop") || strings.Contains(wg1, "ip6 ") {
		t.Errorf("wg1 doesn't drop IPv6 first:\n%s", wg1)
	}
	// nothing of IPv6 for wg1 but its gate
	for _, unwanted := range []string{"wg1_route_all6", `iifname "wg1" ip6 daddr`, "2001:db8:6::", `ip6 saddr != @wg1_sessions6 udp dport 53`} {
		if strings.Contains(rules, unwanted) {
			t.Errorf("%q in:\n%s", unwanted, rules)
		}
	}
	// the IPv6 and the IPv4 rules don't mix the versions
	if strings.Contains(rules, "ip daddr fd00") || strings.Contains(rules, "ip6 daddr 10.") || strings.Contains(rules, "ip saddr fd00") {
		t.Errorf("versions mixed:\n%s", rules)
	}
	if strings.Count(rules, "{") != strings.Count(rules, "}") {
		t.Error("unbalanced braces")
	}
	if got := SessionCommand(true, "wg0", netip.MustParseAddr("fd00:1:2:3::2")); got != "add element inet authway wg0_sessions6 { fd00:1:2:3::2 }" {
		t.Error(got)
	}
}
