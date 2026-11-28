package core

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The access rules of a peer: the networks it reaches, inside the networks of its server, instead of all of them, and
// names (see names.go), the only rules of a server without networks. A rule can end with ports, the only traffic it
// allows: 10.0.0.5 tcp/3389, files.corp.lan tcp/445, 10.0.0.0/24 tcp/80,443 udp/53 icmp (see network.Ports).
// The firewall of the container enforces them, whatever the configuration file says, with NAT and routed alike. A
// peer with rules that sends all its traffic through the tunnel also reaches the internet, but no other private
// network. Its configuration file routes only its own networks, and the DNS servers of the server inside the
// networks of the server.

// checkAccess returns the access rules of a peer from the input: nil for all the networks of its server. Missing from
// the input, they stay as they were, so an older web UI can't take them away; an empty list is all the networks. A
// bare address is that one host.
func checkAccess(input *[]string, current []string, server *store.Server, c *checks) []string {
	if input == nil {
		return current
	}
	if len(*input) == 0 {
		return nil
	}
	networks := parsePrefixes(server.Networks)
	// the networks of the rules without ports
	var list []netip.Prefix
	// the rules as they're kept, in the order given: the networks as netip writes them, the names in lowercase, the
	// ports as network.Ports writes them
	entries := []string{}
	for _, text := range *input {
		words := strings.Fields(text)
		if len(words) == 0 {
			continue
		}
		var ports network.Ports
		if len(words) > 1 {
			parsed, ok := network.ParsePorts(words[1:])
			if !ok {
				c.fail("access", "invalid_ports")
				continue
			}
			ports = parsed
		}
		suffix := ""
		if !ports.All() {
			suffix = " " + ports.String()
		}
		prefix, ok := parseAccess(words[0])
		if !ok {
			// a name, files.corp.lan or *.corp.lan: its addresses are learned inside the networks of the server, and
			// on the internet. A server without networks takes names too, for the internet ones
			rule, ok := names.Parse(words[0])
			switch {
			case !ok:
				c.fail("access", "invalid")
			case !containsText(entries, rule.String()+suffix):
				entries = append(entries, rule.String()+suffix)
			}
			continue
		}
		switch {
		case len(networks) == 0:
			c.fail("access", "names_only")
		case !insideAny(prefix, networks):
			c.fail("access", "outside")
		case !ports.All():
			// a rule of its own in the firewall: it can overlap the others
			if !containsText(entries, prefix.String()+suffix) {
				entries = append(entries, prefix.String()+suffix)
			}
		case overlapsAny(prefix, list):
			// nftables refuses networks that overlap in the same rule
			c.fail("access", "overlap")
		default:
			list = append(list, prefix)
			entries = append(entries, prefix.String())
		}
	}
	_, failed := c.fields["access"]
	switch {
	case len(entries) == 0 && !failed:
		// only blank lines: never all the networks by mistake
		c.fail("access", "required")
	case len(entries) > MaxNetworks:
		c.fail("access", "too_many")
	}
	return entries
}

// parseAccess reads a network, or an address as a network of one host.
func parseAccess(text string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		address, err := netip.ParseAddr(text)
		if err != nil {
			return netip.Prefix{}, false
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	}
	if prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

// insideAny tells whether a network is inside one of a list.
func insideAny(prefix netip.Prefix, list []netip.Prefix) bool {
	for _, network := range list {
		if network.Addr().Is6() == prefix.Addr().Is6() && network.Bits() <= prefix.Bits() && network.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// accessRule is an access rule as it's kept, read: an address or a network, else a name, and the traffic it allows.
type accessRule struct {
	// valid for an address or a network
	prefix netip.Prefix
	name   names.Rule
	ports  network.Ports
}

// parseRule reads an access rule as it's kept: false for one that can't be read, which the firewall leaves out
func parseRule(text string) (accessRule, bool) {
	words := strings.Fields(text)
	if len(words) == 0 {
		return accessRule{}, false
	}
	var rule accessRule
	if len(words) > 1 {
		ports, ok := network.ParsePorts(words[1:])
		if !ok {
			return accessRule{}, false
		}
		rule.ports = ports
	}
	if prefix, ok := parseAccess(words[0]); ok {
		rule.prefix = prefix
		return rule, true
	}
	name, ok := names.Parse(words[0])
	if !ok {
		return accessRule{}, false
	}
	name.Ports = rule.ports.String()
	rule.name = name
	return rule, true
}

// accessPrefixes are the addresses and the networks of access rules, those with ports too, in their order
func accessPrefixes(access []string) []netip.Prefix {
	var list []netip.Prefix
	for _, text := range access {
		if rule, ok := parseRule(text); ok && rule.prefix.IsValid() {
			list = append(list, rule.prefix)
		}
	}
	return list
}

func parsePrefixes(texts []string) []netip.Prefix {
	list := make([]netip.Prefix, 0, len(texts))
	for _, text := range texts {
		if prefix, err := netip.ParsePrefix(text); err == nil {
			list = append(list, prefix.Masked())
		}
	}
	return list
}

// accessText is the access rules of a peer for the events.
func accessText(access []string) string {
	if access == nil {
		return "all the networks"
	}
	return strings.Join(access, ", ")
}

// peerAccess is what the firewall gets of the access rules of a peer without ports: only what's still inside the
// networks of its server. Nil for all of them; a peer with rules and nothing left reaches none.
func peerAccess(peer *store.Peer, networks []netip.Prefix) []netip.Prefix {
	if peer.Access == nil {
		return nil
	}
	list := []netip.Prefix{}
	for _, text := range peer.Access {
		if rule, ok := parseRule(text); ok && rule.prefix.IsValid() && rule.ports.All() && insideAny(rule.prefix, networks) {
			list = append(list, rule.prefix)
		}
	}
	return list
}

// peerPortAccess is what the firewall gets of the access rules of a peer with ports, inside the networks of its
// server
func peerPortAccess(peer *store.Peer, networks []netip.Prefix) []network.PortAccess {
	var list []network.PortAccess
	for _, text := range peer.Access {
		if rule, ok := parseRule(text); ok && rule.prefix.IsValid() && !rule.ports.All() && insideAny(rule.prefix, networks) {
			list = append(list, network.PortAccess{Prefix: rule.prefix, Ports: rule.ports})
		}
	}
	return list
}

// namePortsOf are the ports of the names of access rules with some, each once
func namePortsOf(access []string) []network.Ports {
	var list []network.Ports
	seen := map[string]bool{}
	for _, text := range access {
		if rule, ok := parseRule(text); ok && !rule.prefix.IsValid() && !rule.ports.All() && !seen[rule.ports.String()] {
			seen[rule.ports.String()] = true
			list = append(list, rule.ports)
		}
	}
	return list
}

// allowedNetworks are the networks that the configuration file of a peer routes through the tunnel, besides the
// tunnels: the networks of its server, or with access rules its own and the DNS servers inside the networks of the
// server, which it couldn't ask otherwise. With names in its rules, all the networks of the server: their addresses
// aren't known in advance, and the firewall of the server lets through only what the rules allow.
func allowedNetworks(server *store.Server, peer *store.Peer) []string {
	if peer.Access == nil || hasNames(peer.Access) {
		return append([]string{}, server.Networks...)
	}
	networks := parsePrefixes(server.Networks)
	// the ports don't matter here: the firewall of the server filters them
	var access []netip.Prefix
	for _, prefix := range accessPrefixes(peer.Access) {
		if insideAny(prefix, networks) && !slices.Contains(access, prefix) {
			access = append(access, prefix)
		}
	}
	list := prefixTexts(access)
	for _, text := range server.DNS {
		address, err := netip.ParseAddr(text)
		if err != nil {
			continue
		}
		host := netip.PrefixFrom(address, address.BitLen())
		if insideAny(host, networks) && !insideAny(host, access) && !containsText(list, host.String()) {
			list = append(list, host.String())
		}
	}
	return list
}

// checkNetworksOfPeers refuses networks of a server that leave out what the access rules of its peers reach: the
// peers are changed first.
func checkNetworksOfPeers(server *store.Server, peers []store.Peer, c *checks) {
	networks := parsePrefixes(server.Networks)
	for _, peer := range peers {
		for _, prefix := range accessPrefixes(peer.Access) {
			if !insideAny(prefix, networks) {
				c.fail("networks", "in_peer_access")
				return
			}
		}
	}
}
