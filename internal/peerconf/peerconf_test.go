package peerconf

import (
	"net/netip"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	config := Config{
		PeerName:        "Alice laptop",
		ServerName:      "Office",
		PrivateKey:      "PRIVATE",
		Address:         netip.MustParseAddr("10.8.0.2"),
		DNS:             []string{"192.168.1.1"},
		Login:           LoginURL(netip.MustParseAddr("10.8.0.1"), 8181),
		ServerPublicKey: "PUBLIC",
		PresharedKey:    "PSK",
		AllowedIPs:      AllowedIPs(false, netip.MustParsePrefix("10.8.0.0/24"), netip.Prefix{}, []string{"192.168.1.0/24"}),
		Endpoint:        Endpoint("vpn.example.com", 51820),
		Keepalive:       25,
	}
	want := `[Interface]
# Name = Alice laptop
# Login = http://10.8.0.1:8181/
PrivateKey = PRIVATE
Address = 10.8.0.2/32
DNS = 192.168.1.1

[Peer]
# Name = Office
PublicKey = PUBLIC
PresharedKey = PSK
AllowedIPs = 10.8.0.0/24, 192.168.1.0/24
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`
	if got := config.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestEndpointAndNames(t *testing.T) {
	if got := Endpoint("2001:db8::1", 51820); got != "[2001:db8::1]:51820" {
		t.Error(got)
	}
	if got := Endpoint("203.0.113.5", 51821); got != "203.0.113.5:51821" {
		t.Error(got)
	}
	if got := AllowedIPs(true, netip.MustParsePrefix("10.8.0.0/24"), netip.Prefix{}, []string{"192.168.1.0/24"}); strings.Join(got, ",") != "0.0.0.0/0" {
		t.Error(got)
	}
	for _, test := range []struct{ server, peer, want string }{
		{"ABC", "test22", "ABC-test22.conf"},
		{"Head office (Milan)", "Alice laptop", "Head-office-Milan-Alice-laptop.conf"},
		{"...", "", "wireguard.conf"},
		{"Office", "…", "Office.conf"},
		{"???", "phone", "phone.conf"},
		// at most 32: the longer name is cut, each keeps half of the room at least
		{"Office", "a very long name of a peer, too long", "Office-a-very-long-name-of-a-pee.conf"},
		{"a very long name of a server, too long", "phone", "a-very-long-name-of-a-serv-phone.conf"},
		{"a very long name of a server", "a very long name of a peer", "a-very-long-nam-a-very-long-name.conf"},
		{"a very long name of a server, too long", "", "a-very-long-name-of-a-server-too.conf"},
		// no "-" or "." left where a name is cut
		{"Office-.-x", "abcdefghijklmnopqrstuvwxyz", "Office-.-x-abcdefghijklmnopqrstu.conf"},
		{"abcdefghijklmn. opqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmn-abcdefghijklmnopq.conf"},
	} {
		got := FileName(test.server, test.peer)
		if got != test.want {
			t.Errorf("%q %q: got %q, want %q", test.server, test.peer, got, test.want)
		}
		if name := strings.TrimSuffix(got, ".conf"); len(name) > 32 {
			t.Errorf("%q: longer than 32", got)
		}
	}
	config := Config{PeerName: "two\nlines"}
	if strings.Contains(config.String(), "two\nlines") {
		t.Error("a new line in a name breaks the file")
	}
}

// a server with an IPv6 network: the peer has both addresses, routes both tunnels, and all of IPv6 too when it sends
// all its traffic through the tunnel
func TestDualStack(t *testing.T) {
	tunnel, tunnel6 := netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("fd12:3456:789a:1::/64")
	config := Config{
		PeerName:        "Bob phone",
		ServerName:      "Office",
		PrivateKey:      "PRIVATE",
		Address:         netip.MustParseAddr("10.8.0.5"),
		Address6:        netip.MustParseAddr("fd12:3456:789a:1::5"),
		ServerPublicKey: "PUBLIC",
		PresharedKey:    "PSK",
		AllowedIPs:      AllowedIPs(false, tunnel, tunnel6, []string{"192.168.1.0/24", "2001:db8:1::/64", "fd12:3456:789a:1::/64"}),
		Endpoint:        Endpoint("2001:db8::10", 51820),
	}
	text := config.String()
	for _, want := range []string{
		"Address = 10.8.0.5/32, fd12:3456:789a:1::5/128\n",
		"AllowedIPs = 10.8.0.0/24, fd12:3456:789a:1::/64, 192.168.1.0/24, 2001:db8:1::/64\n",
		"Endpoint = [2001:db8::10]:51820\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if got := AllowedIPs(true, tunnel, tunnel6, []string{"192.168.1.0/24"}); strings.Join(got, ", ") != "0.0.0.0/0, ::/0" {
		t.Error(got)
	}
	if got := LoginURL(netip.MustParseAddr("fd12:3456:789a:1::1"), 8181); got != "http://[fd12:3456:789a:1::1]:8181/" {
		t.Error(got)
	}
}
