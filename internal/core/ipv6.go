package core

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"strconv"

	"github.com/phatdo1819/authway-server/internal/store"
)

// IPv6 in the tunnels: a server can have an IPv6 network besides its IPv4 one, and its peers then have an IPv6
// address too, the one in the same place of the network: 10.8.0.5 in 10.8.0.0/24 is fd12:3456:789a:1::5 in
// fd12:3456:789a:1::/64, and the server is ::1 as it is .1. Nothing more to choose or to keep for a peer, and the
// network can be added to a server that already has peers: their next configuration file has it.

// The lengths of an IPv6 network of the tunnels: a /64 is the usual one. It must hold at least as many addresses as
// the IPv4 network, for every peer to have one.
const (
	MinNetwork6Bits = 64
	MaxNetwork6Bits = 120
)

// metaIPv6Prefix keeps the /48 of unique local addresses the IPv6 networks are suggested from, before a server has one
const metaIPv6Prefix = "ipv6_prefix"

// tunnel6Of is the IPv6 network of a server, invalid when it has none.
func tunnel6Of(server *store.Server) netip.Prefix {
	prefix, err := netip.ParsePrefix(server.Network6)
	if err != nil || !prefix.Addr().Is6() {
		return netip.Prefix{}
	}
	return prefix.Masked()
}

func ipv4Value(address netip.Addr) uint32 {
	bytes := address.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

// address6 is the IPv6 address of an IPv4 address of the tunnel.
func address6(tunnel, tunnel6 netip.Prefix, address netip.Addr) (netip.Addr, bool) {
	if !tunnel.IsValid() || !tunnel6.IsValid() || !address.Is4() || !tunnel.Contains(address) {
		return netip.Addr{}, false
	}
	offset := ipv4Value(address) - ipv4Value(tunnel.Masked().Addr())
	if hostBits := 128 - tunnel6.Bits(); hostBits < 32 && offset >= 1<<hostBits {
		return netip.Addr{}, false
	}
	// the host part of the network is zero, and the offset fits in it: it goes in the last 32 bits
	bytes := tunnel6.Masked().Addr().As16()
	binary.BigEndian.PutUint32(bytes[12:], binary.BigEndian.Uint32(bytes[12:])|offset)
	return netip.AddrFrom16(bytes), true
}

// address4 is the other way: the IPv4 address of an IPv6 address of the tunnel, when it is the one of an IPv4
// address.
func address4(tunnel, tunnel6 netip.Prefix, address netip.Addr) (netip.Addr, bool) {
	if !tunnel.IsValid() || !tunnel6.IsValid() || !address.Is6() || address.Is4In6() || !tunnel6.Contains(address) {
		return netip.Addr{}, false
	}
	bytes, base := address.As16(), tunnel6.Masked().Addr().As16()
	for index := 0; index < 12; index++ {
		if bytes[index] != base[index] {
			return netip.Addr{}, false
		}
	}
	offset := binary.BigEndian.Uint32(bytes[12:]) ^ binary.BigEndian.Uint32(base[12:])
	if offset >= 1<<(32-tunnel.Bits()) {
		return netip.Addr{}, false
	}
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], ipv4Value(tunnel.Masked().Addr())+offset)
	return netip.AddrFrom4(result), true
}

// addressesOf are the addresses of a peer in its tunnel: its IPv4 one, then its IPv6 one when the server has an
// IPv6 network.
func addressesOf(server *store.Server, address string) []netip.Addr {
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}
	list := []netip.Addr{parsed}
	if tunnel, err := netip.ParsePrefix(server.Network); err == nil {
		if other, ok := address6(tunnel.Masked(), tunnel6Of(server), parsed); ok {
			list = append(list, other)
		}
	}
	return list
}

// peerAddress6 is the IPv6 address of a peer, "" when its server has no IPv6 network.
func peerAddress6(server *store.Server, address string) string {
	if list := addressesOf(server, address); len(list) == 2 {
		return list[1].String()
	}
	return ""
}

// ula48Locked is the /48 of unique local addresses (RFC 4193) the IPv6 networks are suggested from: the one of a
// server that has one, else a random one, kept for the next suggestions.
func (s *Service) ula48Locked(servers []store.Server) (netip.Prefix, error) {
	for index := range servers {
		if tunnel6 := tunnel6Of(&servers[index]); tunnel6.IsValid() && tunnel6.Addr().IsPrivate() {
			return netip.PrefixFrom(tunnel6.Addr(), 48).Masked(), nil
		}
	}
	q := s.db.Q()
	if text, err := q.Meta(metaIPv6Prefix); err == nil && text != "" {
		if prefix, err := netip.ParsePrefix(text); err == nil && prefix.Addr().Is6() && prefix.Bits() == 48 {
			return prefix, nil
		}
	}
	var bytes [16]byte
	bytes[0] = 0xfd
	if _, err := rand.Read(bytes[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	prefix := netip.PrefixFrom(netip.AddrFrom16(bytes), 48)
	if err := q.SetMeta(metaIPv6Prefix, prefix.String()); err != nil {
		return netip.Prefix{}, err
	}
	return prefix, nil
}

// suggestNetwork6 is a free /64 of the /48 for a server with the IPv4 network tunnel: the subnet reads like the third
// number of the IPv4 network, 10.8.12.0/24 gets fd…:12::/64, else the next free one.
func suggestNetwork6(ula netip.Prefix, tunnel netip.Prefix, taken []netip.Prefix) netip.Prefix {
	start := uint64(0)
	if tunnel.IsValid() && tunnel.Addr().Is4() {
		third := tunnel.Masked().Addr().As4()[2]
		start, _ = strconv.ParseUint(strconv.Itoa(int(third)), 16, 16)
	}
	for step := uint64(0); step < 1<<16; step++ {
		bytes := ula.Masked().Addr().As16()
		binary.BigEndian.PutUint16(bytes[6:8], uint16(start+step))
		candidate := netip.PrefixFrom(netip.AddrFrom16(bytes), 64)
		if !overlapsAny(candidate, taken) {
			return candidate
		}
	}
	return netip.Prefix{}
}

// clientKey groups the public IPs of the devices for the protections: an IPv4 address alone, an IPv6 address by its
// /64. A network gives its devices many IPv6 addresses of one /64, and changes them over the day: the lock of a
// session and the counts of the failed logins hold for the network, as they do for the devices behind one IPv4 NAT.
func clientKey(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	address = address.Unmap()
	if address.Is4() {
		return address.String()
	}
	return netip.PrefixFrom(address, 64).Masked().String()
}

// sameClient tells whether two public IPs are those of the same network, as clientKey groups them.
func sameClient(a, b string) bool {
	return clientKey(a) == clientKey(b)
}

// checkIPv6Locked refuses an IPv6 network new to a server when the tunnels can't have IPv6 addresses. A restore
// doesn't ask: its configuration applies, and the error shows on the System page.
func (s *Service) checkIPv6Locked(server *store.Server, before string) error {
	if server.Network6 == "" || server.Network6 == before {
		return nil
	}
	if err := s.net.IPv6(); err != nil {
		return &ValidationError{Fields: map[string]string{"network6": "ipv6_off"}, Detail: err.Error()}
	}
	return nil
}
