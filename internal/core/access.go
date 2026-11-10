package core

import (
	"net/netip"
	"strings"

	"github.com/phatdo1819/authway-server/internal/store"
)

// The access rules of a peer: the networks it reaches, inside the networks of its server, instead of all of them.
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
	var list []netip.Prefix
	for _, text := range *input {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		prefix, ok := parseAccess(text)
		switch {
		case !ok:
			c.fail("access", "invalid")
		case !insideAny(prefix, networks):
			c.fail("access", "outside")
		case overlapsAny(prefix, list):
			// nftables refuses networks that overlap in the same rule
			c.fail("access", "overlap")
		default:
			list = append(list, prefix)
		}
	}
	_, failed := c.fields["access"]
	switch {
	case len(list) == 0 && !failed:
		// only blank lines: never all the networks by mistake
		c.fail("access", "required")
	case len(list) > MaxNetworks:
		c.fail("access", "too_many")
	}
	return prefixTexts(list)
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

// peerAccess is what the firewall gets of the access rules of a peer: only what's still inside the networks of its
// server. Nil for all of them; a peer with rules and nothing left reaches none.
func peerAccess(peer *store.Peer, networks []netip.Prefix) []netip.Prefix {
	if peer.Access == nil {
		return nil
	}
	list := []netip.Prefix{}
	for _, prefix := range parsePrefixes(peer.Access) {
		if insideAny(prefix, networks) {
			list = append(list, prefix)
		}
	}
	return list
}

// allowedNetworks are the networks that the configuration file of a peer routes through the tunnel, besides the
// tunnels: the networks of its server, or with access rules its own and the DNS servers inside the networks of the
// server, which it couldn't ask otherwise.
func allowedNetworks(server *store.Server, peer *store.Peer) []string {
	if peer.Access == nil {
		return append([]string{}, server.Networks...)
	}
	networks := parsePrefixes(server.Networks)
	access := peerAccess(peer, networks)
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
		for _, prefix := range parsePrefixes(peer.Access) {
			if !insideAny(prefix, networks) {
				c.fail("networks", "in_peer_access")
				return
			}
		}
	}
}
