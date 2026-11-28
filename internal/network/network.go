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
	// the DNS queries (UDP and TCP 53) of the peers with names in their access rules go to this port, once they're
	// logged in: Authway Server asks the DNS servers for them, and lets them reach the addresses of those names
	ResolverPort int
	// the addresses that stand in for the internet addresses of names, in the answers to the peers with names of the
	// servers with StandIns: the peers connect to them through the tunnel, and the server sends the connections on to
	// the internet addresses, with its own address. Invalid: none
	StandInNetwork netip.Prefix
	StandIns       []StandIn
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
	// its peers with names reach the internet addresses of their names through the stand-in addresses of
	// State.StandInNetwork, learned like the others
	StandIns bool
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
	// of them. With RouteAll, the peer also reaches the internet, but no other private network. Access has the rules
	// without ports, AccessPorts those with ports
	Access      []netip.Prefix
	AccessPorts []PortAccess
	// names in the access rules: its DNS queries go to Authway Server, and it also reaches Learned, the addresses
	// those names had in the answers, inside Networks of its server, and the stand-in addresses of their internet
	// addresses. Only with Access. The names of rules with ports learn in LearnedPorts, by the text of their ports
	// (Ports.String), one list for each of NamePorts
	Names        bool
	Learned      []netip.Addr
	NamePorts    []Ports
	LearnedPorts map[string][]netip.Addr
}

// Limited tells whether the peer has access rules.
func (p Peer) Limited() bool {
	return p.Access != nil
}

// Learned is an address that a peer reaches, learned from the answer to its DNS query for a name of its access rules:
// Peer is one of its addresses, of the version of Address. Ports is the text of the ports of the rule of the name,
// "" for all the traffic.
type Learned struct {
	Peer    netip.Addr
	Address netip.Addr
	Ports   string
}

// LearnedMark is the conntrack mark of the connections opened to a learned address: they stay open when the address
// expires, as long as the session does, and until the access rules of the peer change for the name that opened it.
const LearnedMark = 0x00415701

// StandIn is an address of State.StandInNetwork, and the internet address that the connections to it go to.
type StandIn struct {
	Address netip.Addr
	Real    netip.Addr
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
	// A *Warning means everything is set, but some of it works less well.
	Apply(State) error
	// AddSession and RemoveSession open and close the gate for one peer, by its addresses, between two Apply.
	AddSession(iface string, addresses ...netip.Addr) error
	RemoveSession(iface string, addresses ...netip.Addr) error
	// FlushRedirected forgets the redirected connections of a peer that just logged in: conntrack keeps the redirect
	// of a flow, and its DNS queries and web requests must now reach their real destination.
	FlushRedirected(addresses ...netip.Addr) error
	// AddLearned and RemoveLearned let peers reach learned addresses, or no longer, between two Apply.
	AddLearned(iface string, learned ...Learned) error
	RemoveLearned(iface string, learned ...Learned) error
	// ForgetLearned closes the connections of peers to the addresses they learned, of all of them without addresses:
	// their access rules changed.
	ForgetLearned(addresses ...netip.Addr) error
	// ForgetLearnedTo closes the connections of peers to some of the addresses they learned only, each a Learned
	// without its ports: the names that opened them changed, the others stay.
	ForgetLearnedTo(learned ...Learned) error
	// AddStandIns and RemoveStandIns set where stand-in addresses lead, or no longer, between two Apply.
	AddStandIns(standIns ...StandIn) error
	RemoveStandIns(standIns ...StandIn) error
	// Stats returns the peers of all the interfaces, by public key.
	Stats() (map[wgtypes.Key]PeerStats, error)
	// IPv6 says why the tunnels can't have IPv6 addresses, nil when they can.
	IPv6() error
	Close() error
}

// Warning is what Apply returns when the firewall rules and the peers are all set, but a tunnel works less well than
// it should: its MTU, or its IPv6 address, can't be set. The tunnels carry their traffic, so it isn't a failure, and
// trying again a few seconds later wouldn't change it.
type Warning struct{ Err error }

func (w *Warning) Error() string { return w.Err.Error() }
func (w *Warning) Unwrap() error { return w.Err }

// DefaultMTU is the MTU of an interface without one, as wg-quick sets it.
const DefaultMTU = 1420
