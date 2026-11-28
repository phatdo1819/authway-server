// Package peerconf writes the WireGuard configuration file of a peer.
//
// The comments "# Name =", "# Login =", "# NameRoutes =" and "# Fallback =" are read by Authway: the name of the
// VPN, the login page, the names of its access rules that the app routes itself (see names.RoutesOption) and the
// other addresses of the server. The other WireGuard apps ignore them.
package peerconf

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type Config struct {
	PeerName   string
	ServerName string
	PrivateKey string
	Address    netip.Addr
	// invalid when the server has no IPv6 network
	Address6 netip.Addr
	DNS      []string
	MTU      int
	// the login page, "" when the server needs none
	Login string
	// names in its access rules: the Authway app asks the DNS servers of the file itself, and routes the internet
	// addresses of the names through the tunnel, as the answers say
	NameRoutes bool

	ServerPublicKey string
	PresharedKey    string
	AllowedIPs      []string
	Endpoint        string // host:port, the host of an IPv6 address in brackets
	// the other addresses of the server, written as Endpoint is
	Fallbacks []string
	Keepalive int
}

// Endpoint joins a host and a port as WireGuard reads them: an IPv6 address in brackets.
func Endpoint(host string, port int) string {
	if address, err := netip.ParseAddr(host); err == nil && address.Is6() {
		return fmt.Sprintf("[%s]:%d", address, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// LoginURL is the address of the login page of a server, through its tunnel.
func LoginURL(server netip.Addr, port int) string {
	if server.Is6() {
		return fmt.Sprintf("http://[%s]:%d/", server, port)
	}
	return fmt.Sprintf("http://%s:%d/", server, port)
}

// AllowedIPs are the networks the peer sends through the tunnel: all of them, or the tunnels and the networks of
// the server. tunnel6 is invalid when the server has no IPv6 network: a peer that sends all its traffic then sends
// only IPv4 through it, as before.
func AllowedIPs(routeAll bool, tunnel, tunnel6 netip.Prefix, networks []string) []string {
	if routeAll {
		if tunnel6.IsValid() {
			return []string{"0.0.0.0/0", "::/0"}
		}
		return []string{"0.0.0.0/0"}
	}
	list := []string{tunnel.Masked().String()}
	if tunnel6.IsValid() {
		list = append(list, tunnel6.Masked().String())
	}
	for _, network := range networks {
		if !slices.Contains(list, network) {
			list = append(list, network)
		}
	}
	return list
}

func (c *Config) String() string {
	return c.write(true)
}

// Settings is the file without its keys, the private and the preshared ones: what the Authway app takes from Authway
// Server to update a VPN it has, with the keys it has.
func (c *Config) Settings() string {
	return c.write(false)
}

func (c *Config) write(keys bool) string {
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	line("[Interface]")
	line("# Name = %s", oneLine(c.PeerName))
	if c.Login != "" {
		line("# Login = %s", c.Login)
	}
	if c.NameRoutes {
		line("# NameRoutes = 1")
	}
	if keys {
		line("PrivateKey = %s", c.PrivateKey)
	}
	if c.Address6.IsValid() {
		line("Address = %s/32, %s/128", c.Address, c.Address6)
	} else {
		line("Address = %s/32", c.Address)
	}
	if len(c.DNS) > 0 {
		line("DNS = %s", strings.Join(c.DNS, ", "))
	}
	if c.MTU > 0 {
		line("MTU = %d", c.MTU)
	}
	line("")
	line("[Peer]")
	line("# Name = %s", oneLine(c.ServerName))
	line("PublicKey = %s", c.ServerPublicKey)
	if keys {
		line("PresharedKey = %s", c.PresharedKey)
	}
	line("AllowedIPs = %s", strings.Join(c.AllowedIPs, ", "))
	line("Endpoint = %s", c.Endpoint)
	if len(c.Fallbacks) > 0 {
		line("# Fallback = %s", strings.Join(c.Fallbacks, ", "))
	}
	if c.Keepalive > 0 {
		line("PersistentKeepalive = %d", c.Keepalive)
	}
	return b.String()
}

// maxTunnelName is the longest name of a tunnel in the WireGuard apps
const maxTunnelName = 32

// FileName is the name of the configuration file of a peer, <server>-<peer>.conf: the WireGuard apps take it as the
// name of the tunnel, so at most 32 letters, digits and "_=+.-". When both names don't fit, the longer one is cut,
// down to half of the room at least.
func FileName(serverName, peerName string) string {
	server, peer := tunnelName(serverName), tunnelName(peerName)
	switch {
	case server == "" && peer == "":
		return "wireguard.conf"
	case peer == "":
		return cut(server, maxTunnelName) + ".conf"
	case server == "":
		return cut(peer, maxTunnelName) + ".conf"
	}
	room := maxTunnelName - 1
	if len(server)+len(peer) > room {
		half := room / 2
		switch {
		case len(server) <= half:
			peer = cut(peer, room-len(server))
		case len(peer) <= half:
			server = cut(server, room-len(peer))
		default:
			server = cut(server, half)
			peer = cut(peer, room-len(server))
		}
	}
	return server + "-" + peer + ".conf"
}

// tunnelName keeps the characters of a name that a tunnel name takes, a space as "-"
func tunnelName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_=+.-", r):
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), ".-")
}

// cut keeps the first characters of a tunnel name, at most size, without a "." or "-" at the end
func cut(name string, size int) string {
	if len(name) > size {
		name = name[:size]
	}
	return strings.TrimRight(name, ".-")
}

func oneLine(text string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(text)
}
