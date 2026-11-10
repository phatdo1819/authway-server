// Package network puts the configuration on the system: the WireGuard interfaces and the nftables rules of the gate.
package network

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// State is the whole configuration to apply: Apply makes the system match it.
type State struct {
	Servers []Server
	// the TCP port of the login page, reachable only through the tunnels
	LoginPort int
	// before the login, the web requests (TCP 80) and the DNS queries (UDP 53) of the peers of the servers with
	// Redirect go to these ports, where Authway Server leads them to the login page
	RedirectPort int
	DNSPort      int
}

type Server struct {
	Interface  string
	ListenPort int
	PrivateKey wgtypes.Key
	// the address of the server, with the length of its network: 10.8.0.1/24
	Address netip.Prefix
	// its IPv6 address, with the length of its IPv6 network, invalid when it has none: fd00:1:2:3::1/64
	Address6 netip.Prefix
	MTU      int // 0: 1420, the default of WireGuard
	// the peers must log in: before that, they reach only the login page and ping the server
	Gated bool
	// with Gated: before the login, any plain http:// address and any name lead to the login page
	Redirect bool
	// the networks the peers reach, of both versions; the peers with RouteAll reach everything, except the other
	// tunnels. The IPv6 ones only with an IPv6 network
	Networks []netip.Prefix
	Peers    []Peer
	// the addresses of the peers logged in, of both versions, used only when Gated
	Sessions []netip.Addr
	// the peers reach each other, and start connections to the peers of the servers of Reaches, by interface: one
	// way, the answers pass back. With a login, both peers must be logged in
	ClientToClient bool
	Reaches        []string
	// Networks see the addresses of the peers, not the one of the container: no translation towards them. The rest,
	// the internet of the peers with RouteAll, still goes out with the address of the container. With Inbound,
	// Networks also start connections to the peers, those logged in when Gated
	Routed  bool
	Inbound bool
	// the DNS servers of the peers: the peers with access rules reach them on port 53, wherever they are
	DNS []netip.Addr
}

// IPv6 tells whether the tunnel of the server carries IPv6.
func (s Server) IPv6() bool {
	return s.Address6.IsValid() && s.Address6.Addr().Is6()
}

type Peer struct {
	PublicKey    wgtypes.Key
	PresharedKey wgtypes.Key
	Address      netip.Addr
	// invalid when the server has no IPv6 network
	Address6 netip.Addr
	RouteAll bool
	// the access rules: the networks the peer reaches, of both versions, inside Networks of its server; nil for all
	// of them. With RouteAll, the peer also reaches the internet, but no other private network
	Access []netip.Prefix
}

// Limited tells whether the peer has access rules.
func (p Peer) Limited() bool {
	return p.Access != nil
}

// PeerStats is what WireGuard knows of a peer.
type PeerStats struct {
	Interface string
	// the public address the peer sends from, invalid before its first handshake
	Endpoint      netip.AddrPort
	LastHandshake time.Time // zero before the first one
	Received      int64
	Sent          int64
	// not from WireGuard: when the peer last sent something, as far as Authway Server saw its counter grow
	Active time.Time
}

// Network applies the configuration. The methods are called one at a time.
type Network interface {
	// Apply makes the interfaces and the rules match the state. When the rules can't be set, no interface stays up.
	Apply(State) error
	// AddSession and RemoveSession open and close the gate for one peer, by its addresses, between two Apply.
	AddSession(iface string, addresses ...netip.Addr) error
	RemoveSession(iface string, addresses ...netip.Addr) error
	// FlushRedirected forgets the redirected connections of a peer that just logged in: conntrack keeps the redirect
	// of a flow, and its DNS queries and web requests must now reach their real destination.
	FlushRedirected(addresses ...netip.Addr) error
	// Stats returns the peers of all the interfaces, by public key.
	Stats() (map[wgtypes.Key]PeerStats, error)
	// IPv6 says why the tunnels can't have IPv6 addresses, nil when they can.
	IPv6() error
	Close() error
}

// DefaultMTU is the MTU of an interface without one, as wg-quick sets it.
const DefaultMTU = 1420
