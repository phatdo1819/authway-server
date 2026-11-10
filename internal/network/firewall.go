package network

import (
	"fmt"
	"net/netip"
	"strings"
)

// Table is the nftables table of Authway Server. The container has a network of its own, so the table holds all the
// rules of the tunnels; Docker keeps its own tables, which this one never touches.
const Table = "authway"

// DNSRate is the number of DNS queries a second redirected for each server and each IP version before the login;
// the others are rejected like any other traffic of a peer that isn't logged in.
const DNSRate = 100

// SessionSet is the set of the IPv4 addresses of the peers logged in on an interface, SessionSet6 of their IPv6
// addresses. A gated server has both, with an IPv6 network or not: the gate holds for both versions.
func SessionSet(iface string) string {
	return iface + "_sessions"
}

func SessionSet6(iface string) string {
	return iface + "_sessions6"
}

func routeAllSet(iface string) string {
	return iface + "_route_all"
}

func routeAllSet6(iface string) string {
	return iface + "_route_all6"
}

// Ruleset returns the nftables script that replaces the table at once: the old rules stay until the new ones are
// all in, so there is never a moment without the gate. The sessions are in the script, so they stay too.
//
// Before the login a peer of a gated server reaches the login page and pings its server, nothing else; with
// Redirect its web requests and DNS queries go to the server, which leads them to the login page, and nothing is
// forwarded, so DNS can't carry data out. The checks of the sessions come before the one of the established
// connections: a logout cuts the connections already open.
//
// IPv6 follows the same rules as IPv4, line for line, on the servers with an IPv6 network; the others drop it.
func Ruleset(state State) string {
	var b strings.Builder
	line := func(indent int, format string, args ...any) {
		b.WriteString(strings.Repeat("\t", indent))
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	set := func(name, kind, elements string) {
		line(1, "set %s {", name)
		line(2, "type %s", kind)
		if elements != "" {
			line(2, "elements = { %s }", elements)
		}
		line(1, "}")
	}
	redirecting := false
	for _, server := range state.Servers {
		if server.Gated && server.Redirect {
			redirecting = true
		}
	}

	line(0, "table inet %s", Table)
	line(0, "delete table inet %s", Table)
	line(0, "table inet %s {", Table)

	for _, server := range state.Servers {
		if server.Gated {
			set(SessionSet(server.Interface), "ipv4_addr", addresses(server.Sessions, false))
			set(SessionSet6(server.Interface), "ipv6_addr", addresses(server.Sessions, true))
		}
		var routeAll []netip.Addr
		for _, peer := range server.Peers {
			if peer.RouteAll {
				routeAll = append(routeAll, peer.Address, peer.Address6)
			}
		}
		set(routeAllSet(server.Interface), "ipv4_addr", addresses(routeAll, false))
		if server.IPv6() {
			set(routeAllSet6(server.Interface), "ipv6_addr", addresses(routeAll, true))
		}
	}

	// to the server itself
	line(1, "chain input {")
	line(2, "type filter hook input priority filter; policy accept;")
	line(2, `iifname "wg*" jump from_peers`)
	// the login page and the redirects only through the tunnels, even when no server redirects: they listen anyway
	if ports := portList(state.LoginPort, state.RedirectPort); ports != "" {
		line(2, "tcp dport %s drop", ports)
	}
	if state.DNSPort > 0 {
		line(2, "udp dport %d drop", state.DNSPort)
	}
	line(1, "}")
	line(1, "chain from_peers {")
	line(2, "ct state established,related accept")
	for _, server := range state.Servers {
		address := server.Address.Addr()
		line(2, "iifname %q ip daddr %s icmp type echo-request accept", server.Interface, address)
		line(2, "iifname %q ip daddr %s tcp dport %d accept", server.Interface, address, state.LoginPort)
		if server.Gated && server.Redirect {
			line(2, "iifname %q ip daddr %s tcp dport %d accept", server.Interface, address, state.RedirectPort)
			line(2, "iifname %q ip daddr %s udp dport %d accept", server.Interface, address, state.DNSPort)
		}
		if server.IPv6() {
			address6 := server.Address6.Addr()
			line(2, "iifname %q ip6 daddr %s icmpv6 type echo-request accept", server.Interface, address6)
			line(2, "iifname %q ip6 daddr %s tcp dport %d accept", server.Interface, address6, state.LoginPort)
			if server.Gated && server.Redirect {
				line(2, "iifname %q ip6 daddr %s tcp dport %d accept", server.Interface, address6, state.RedirectPort)
				line(2, "iifname %q ip6 daddr %s udp dport %d accept", server.Interface, address6, state.DNSPort)
			}
		}
	}
	// a quick answer rather than a timeout: the apps of the peer see at once that nothing is there
	line(2, "meta l4proto tcp reject with tcp reset")
	line(2, "reject with icmpx type admin-prohibited")
	line(1, "}")

	// before the routing: the redirects of the peers that aren't logged in
	if redirecting {
		line(1, "chain prerouting {")
		line(2, "type nat hook prerouting priority dstnat; policy accept;")
		for _, server := range state.Servers {
			if !server.Gated || !server.Redirect {
				continue
			}
			unauthorized := []string{fmt.Sprintf("iifname %q ip saddr != @%s", server.Interface, SessionSet(server.Interface))}
			if server.IPv6() {
				unauthorized = append(unauthorized, fmt.Sprintf("iifname %q ip6 saddr != @%s", server.Interface, SessionSet6(server.Interface)))
			}
			for _, unauth := range unauthorized {
				line(2, "%s udp dport 53 limit rate %d/second redirect to :%d", unauth, DNSRate, state.DNSPort)
				line(2, "%s tcp dport 80 redirect to :%d", unauth, state.RedirectPort)
			}
		}
		line(1, "}")
	}

	// through the server
	line(1, "chain forward {")
	line(2, "type filter hook forward priority filter; policy drop;")
	for _, server := range state.Servers {
		if server.Gated {
			// both versions, even without an IPv6 network: a peer not logged in sends nothing through
			for _, unauth := range []string{
				fmt.Sprintf("iifname %q ip saddr != @%s", server.Interface, SessionSet(server.Interface)),
				fmt.Sprintf("iifname %q ip6 saddr != @%s", server.Interface, SessionSet6(server.Interface)),
			} {
				line(2, "%s meta l4proto tcp reject with tcp reset", unauth)
				line(2, "%s reject with icmpx type admin-prohibited", unauth)
			}
			line(2, "oifname %q ip daddr != @%s drop", server.Interface, SessionSet(server.Interface))
			line(2, "oifname %q ip6 daddr != @%s drop", server.Interface, SessionSet6(server.Interface))
		}
	}
	// every packet of a peer goes through the rules of its server, those of the connections already open too: fewer
	// networks or a peer that no longer sends all its traffic cut them at once. Each chain ends with a verdict, so
	// only the answers to the peers reach the rule of the established connections
	for _, server := range state.Servers {
		line(2, "iifname %q jump %s_forward", server.Interface, server.Interface)
	}
	// what comes from outside the tunnels and goes in the way a connection started: the networks of a server with
	// Inbound start connections to its peers, logged in by the rules above. Nothing else reaches a peer but the
	// answers to its own connections, those already open too: Inbound off cuts them at once
	for _, server := range state.Servers {
		if server.Inbound {
			// a peer with access rules: only from its own networks
			for _, family := range families(server) {
				var limited []netip.Addr
				for _, peer := range server.Peers {
					address := family.address(peer)
					if !peer.Limited() || !address.IsValid() {
						continue
					}
					limited = append(limited, address)
					if networks := prefixes(peer.Access, family.ipv6); networks != "" {
						line(2, `iifname != "wg*" oifname %q ct direction original %s daddr %s %s saddr { %s } accept`,
							server.Interface, family.name, address, family.name, networks)
					}
				}
				if peers := addresses(limited, family.ipv6); peers != "" {
					line(2, "oifname %q ct direction original %s daddr { %s } drop", server.Interface, family.name, peers)
				}
			}
			if networks := prefixes(server.Networks, false); networks != "" {
				line(2, `iifname != "wg*" oifname %q ct direction original ip saddr { %s } accept`, server.Interface, networks)
			}
			if networks := prefixes(server.Networks, true); networks != "" && server.IPv6() {
				line(2, `iifname != "wg*" oifname %q ct direction original ip6 saddr { %s } accept`, server.Interface, networks)
			}
		}
		line(2, "oifname %q ct direction original drop", server.Interface)
	}
	line(2, "ct state established,related accept")
	line(1, "}")
	// the servers whose peers start connections to the peers of each server: these get their answers back
	reachedBy := map[string][]string{}
	present := map[string]bool{}
	for _, server := range state.Servers {
		present[server.Interface] = true
	}
	for _, server := range state.Servers {
		for _, target := range server.Reaches {
			if target != server.Interface && present[target] {
				reachedBy[target] = append(reachedBy[target], server.Interface)
			}
		}
	}
	for _, server := range state.Servers {
		line(1, "chain %s_forward {", server.Interface)
		if !server.IPv6() {
			line(2, "meta nfproto ipv6 drop")
		}
		if server.ClientToClient {
			line(2, "oifname %q accept", server.Interface)
		}
		for _, target := range server.Reaches {
			if target != server.Interface && present[target] {
				line(2, "oifname %q accept", target)
			}
		}
		// the answers of the peers to the connections started by the peers of the servers that reach them
		for _, source := range reachedBy[server.Interface] {
			line(2, "oifname %q ct state established,related accept", source)
		}
		// no other traffic between the peers, nor to the other tunnels
		line(2, `oifname "wg*" drop`)
		limitedRules(server, line)
		line(2, "ip saddr @%s accept", routeAllSet(server.Interface))
		if server.IPv6() {
			line(2, "ip6 saddr @%s accept", routeAllSet6(server.Interface))
		}
		if networks := prefixes(server.Networks, false); networks != "" {
			line(2, "ip daddr { %s } accept", networks)
		}
		if networks := prefixes(server.Networks, true); networks != "" && server.IPv6() {
			line(2, "ip6 daddr { %s } accept", networks)
		}
		line(2, "drop")
		line(1, "}")
	}

	// what leaves the tunnels goes out with the address of the container, not the ones of the peers: nothing outside
	// routes the tunnels back, IPv6 neither, its addresses are unique local ones. But a routed server: its networks
	// see the peers, their router sends the tunnels back through the container; the internet of its peers with
	// RouteAll still goes out with the address of the container
	line(1, "chain postrouting {")
	line(2, "type nat hook postrouting priority srcnat; policy accept;")
	for _, server := range state.Servers {
		translated := func(family string, tunnel netip.Prefix, ipv6 bool) {
			rule := fmt.Sprintf(`%s saddr %s oifname != "wg*"`, family, tunnel.Masked())
			if networks := prefixes(server.Networks, ipv6); server.Routed && networks != "" {
				rule += fmt.Sprintf(" %s daddr != { %s }", family, networks)
			}
			line(2, "%s masquerade", rule)
		}
		translated("ip", server.Address, false)
		if server.IPv6() {
			translated("ip6", server.Address6, true)
		}
	}
	line(1, "}")

	line(0, "}")
	return b.String()
}

// privateNetworks are the networks that a peer with access rules reaches only when they're in its rules, even when it
// sends all its traffic through the tunnel: the local networks, the Docker networks and the Docker host on them
var (
	privateNetworks = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("169.254.0.0/16"),
	}
	privateNetworks6 = []netip.Prefix{netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10")}
)

// ipFamily is a version of IP in the rules: its keyword, and the address of a peer in it
type ipFamily struct {
	name string
	ipv6 bool
}

func (f ipFamily) address(peer Peer) netip.Addr {
	if f.ipv6 {
		return peer.Address6
	}
	return peer.Address
}

// families are the versions the tunnel of a server carries
func families(server Server) []ipFamily {
	if server.IPv6() {
		return []ipFamily{{"ip", false}, {"ip6", true}}
	}
	return []ipFamily{{"ip", false}}
}

// limitedRules are the rules of the peers with access rules, in the chain of their server before the ones of all its
// peers: their own networks, the DNS servers of the server, and nothing else of the networks of the server nor of
// the private networks. What's left, the internet, follows the rules of all the peers: only with RouteAll.
func limitedRules(server Server, line func(int, string, ...any)) {
	for _, family := range families(server) {
		var limited []netip.Addr
		for _, peer := range server.Peers {
			address := family.address(peer)
			if !peer.Limited() || !address.IsValid() {
				continue
			}
			limited = append(limited, address)
			if networks := prefixes(peer.Access, family.ipv6); networks != "" {
				line(2, "%s saddr %s %s daddr { %s } accept", family.name, address, family.name, networks)
			}
		}
		peers := addresses(limited, family.ipv6)
		if peers == "" {
			continue
		}
		// the peers ask the DNS servers of the configuration file, wherever they are
		if dns := addresses(server.DNS, family.ipv6); dns != "" {
			line(2, "%s saddr { %s } %s daddr { %s } meta l4proto { tcp, udp } th dport 53 accept",
				family.name, peers, family.name, dns)
		}
		if networks := prefixes(server.Networks, family.ipv6); networks != "" {
			line(2, "%s saddr { %s } %s daddr { %s } drop", family.name, peers, family.name, networks)
		}
		private := privateNetworks
		if family.ipv6 {
			private = privateNetworks6
		}
		line(2, "%s saddr { %s } %s daddr { %s } drop", family.name, peers, family.name, prefixes(private, family.ipv6))
	}
}

// SessionCommand returns the nftables command that adds or removes a peer logged in, by one of its addresses: the
// set of its version.
func SessionCommand(add bool, iface string, address netip.Addr) string {
	verb := "delete"
	if add {
		verb = "add"
	}
	set := SessionSet(iface)
	if address.Is6() {
		set = SessionSet6(iface)
	}
	return fmt.Sprintf("%s element inet %s %s { %s }", verb, Table, set, address)
}

// portList is a port or a set of ports for nftables, without the ones not set
func portList(ports ...int) string {
	var texts []string
	for _, port := range ports {
		if port > 0 {
			texts = append(texts, fmt.Sprint(port))
		}
	}
	if len(texts) > 1 {
		return "{ " + strings.Join(texts, ", ") + " }"
	}
	return strings.Join(texts, "")
}

// addresses are the elements of a set of one version, without the invalid ones and the duplicates
func addresses(list []netip.Addr, ipv6 bool) string {
	texts := make([]string, 0, len(list))
	seen := map[netip.Addr]bool{}
	for _, address := range list {
		if address.IsValid() && address.Is6() == ipv6 && !address.Is4In6() && !seen[address] {
			seen[address] = true
			texts = append(texts, address.String())
		}
	}
	return strings.Join(texts, ", ")
}

func prefixes(list []netip.Prefix, ipv6 bool) string {
	texts := make([]string, 0, len(list))
	for _, prefix := range list {
		if prefix.IsValid() && prefix.Addr().Is6() == ipv6 && !prefix.Addr().Is4In6() {
			texts = append(texts, prefix.Masked().String())
		}
	}
	return strings.Join(texts, ", ")
}
