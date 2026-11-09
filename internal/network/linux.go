//go:build linux

package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Linux applies the configuration with the kernel WireGuard (netlink, through wgctrl), `ip` and `nft`.
type Linux struct {
	client *wgctrl.Client
	log    *slog.Logger
}

// NewSystem checks the tools and opens the WireGuard control socket.
func NewSystem(log *slog.Logger) (Network, error) {
	for _, tool := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("%s isn't installed: the image needs iproute2 and nftables", tool)
		}
	}
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("WireGuard control: %w", err)
	}
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(data)) != "1" {
		log.Warn("IPv4 forwarding is off: the peers reach only this server. Set the sysctl net.ipv4.ip_forward=1 on the container")
	}
	return &Linux{client: client, log: log}, nil
}

func (l *Linux) Close() error {
	return l.client.Close()
}

func (l *Linux) Apply(state State) error {
	if err := run(Ruleset(state), "nft", "-f", "-"); err != nil {
		// fail closed: without the rules of the gate no tunnel must carry traffic
		l.downAll()
		return fmt.Errorf("the firewall rules can't be set, all the tunnels are down: %w", err)
	}
	links, err := wireguardLinks()
	if err != nil {
		return err
	}
	var errs []error
	wanted := map[string]bool{}
	for _, server := range state.Servers {
		wanted[server.Interface] = true
		if err := l.applyServer(server, links[server.Interface]); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server.Interface, err))
		}
	}
	for name := range links {
		if !wanted[name] {
			if err := run("", "ip", "link", "delete", "dev", name); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (l *Linux) applyServer(server Server, exists bool) error {
	name := server.Interface
	if !exists {
		if err := run("", "ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
			if strings.Contains(err.Error(), "Unknown device type") || strings.Contains(err.Error(), "not supported") {
				return fmt.Errorf("the kernel of the host has no WireGuard (Linux 5.6 or later has it): %w", err)
			}
			return err
		}
	}
	mtu := server.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if err := run("", "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	ipv6Err, err := setAddresses(name, server)
	if err != nil {
		return err
	}
	if err := l.configure(server); err != nil {
		return err
	}
	if err := run("", "ip", "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	return ipv6Err
}

// setAddresses gives the interface the addresses of the server, and takes away the others: one by one, so the
// routes of an address that stays never go. An IPv6 address that can't be set doesn't stop the tunnel: it carries
// IPv4, and the first error says why IPv6 is missing.
func setAddresses(name string, server Server) (error, error) {
	wanted := []netip.Prefix{server.Address}
	if server.IPv6() {
		wanted = append(wanted, server.Address6)
	}
	current, err := interfaceAddresses(name)
	if err != nil {
		return nil, err
	}
	for _, prefix := range current {
		if !slices.Contains(wanted, prefix) {
			if err := run("", "ip", "address", "delete", prefix.String(), "dev", name); err != nil {
				return nil, err
			}
		}
	}
	var ipv6Err error
	for _, prefix := range wanted {
		if slices.Contains(current, prefix) {
			continue
		}
		if prefix.Addr().Is4() {
			if err := run("", "ip", "address", "add", prefix.String(), "dev", name); err != nil {
				return nil, err
			}
			continue
		}
		// a tunnel has no neighbors to ask whether the address is taken
		if err := run("", "ip", "-6", "address", "add", prefix.String(), "dev", name, "nodad"); err != nil {
			reason := err
			if why := ipv6Off(); why != nil {
				reason = why
			}
			ipv6Err = fmt.Errorf("its IPv6 address can't be set, the tunnel carries IPv4 only: %w", reason)
		}
	}
	return ipv6Err, nil
}

// IPv6 reads whether the new interfaces of the container get IPv6: Docker turns it off on the networks without it,
// and a kernel can have none.
func (l *Linux) IPv6() error {
	return ipv6Off()
}

func ipv6Off() error {
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/default/disable_ipv6")
	if err != nil {
		return errors.New("the kernel of the host has no IPv6")
	}
	if strings.TrimSpace(string(data)) != "0" {
		return errors.New("IPv6 is off in the container: set the sysctl net.ipv6.conf.default.disable_ipv6=0, or turn on IPv6 on its Docker network as compose.yaml does")
	}
	return nil
}

// configure changes only the peers that differ, like `wg syncconf`: the other peers keep their handshakes
func (l *Linux) configure(server Server) error {
	key := server.PrivateKey
	port := server.ListenPort
	config := wgtypes.Config{PrivateKey: &key, ListenPort: &port}
	wanted := map[wgtypes.Key]bool{}
	for _, peer := range server.Peers {
		wanted[peer.PublicKey] = true
		preshared := peer.PresharedKey
		// WireGuard takes from a peer only the packets that come from its addresses: no other source gets in
		allowed := []net.IPNet{{IP: peer.Address.AsSlice(), Mask: net.CIDRMask(32, 32)}}
		if server.IPv6() && peer.Address6.Is6() {
			allowed = append(allowed, net.IPNet{IP: peer.Address6.AsSlice(), Mask: net.CIDRMask(128, 128)})
		}
		config.Peers = append(config.Peers, wgtypes.PeerConfig{
			PublicKey:         peer.PublicKey,
			PresharedKey:      &preshared,
			ReplaceAllowedIPs: true,
			AllowedIPs:        allowed,
		})
	}
	device, err := l.client.Device(server.Interface)
	if err != nil {
		return err
	}
	for _, peer := range device.Peers {
		if !wanted[peer.PublicKey] {
			config.Peers = append(config.Peers, wgtypes.PeerConfig{PublicKey: peer.PublicKey, Remove: true})
		}
	}
	return l.client.ConfigureDevice(server.Interface, config)
}

func (l *Linux) downAll() {
	links, err := wireguardLinks()
	if err != nil {
		l.log.Error("can't list the tunnels to take them down", "error", err)
		return
	}
	for name := range links {
		if err := run("", "ip", "link", "set", "dev", name, "down"); err != nil {
			l.log.Error("can't take a tunnel down", "interface", name, "error", err)
		}
	}
}

// AddSession opens the gate for all the addresses of a peer at once: one nftables transaction.
func (l *Linux) AddSession(iface string, addresses ...netip.Addr) error {
	var script strings.Builder
	for _, address := range addresses {
		script.WriteString(SessionCommand(true, iface, address) + "\n")
	}
	if script.Len() == 0 {
		return nil
	}
	return run(script.String(), "nft", "-f", "-")
}

// RemoveSession closes it address by address: one already out doesn't keep the others in.
func (l *Linux) RemoveSession(iface string, addresses ...netip.Addr) error {
	var errs []error
	for _, address := range addresses {
		err := run(SessionCommand(false, iface, address)+"\n", "nft", "-f", "-")
		if err != nil && !strings.Contains(err.Error(), "No such file or directory") {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *Linux) FlushRedirected(addresses ...netip.Addr) error {
	if _, err := exec.LookPath("conntrack"); err != nil {
		// without it, the redirected flows end with their conntrack timeouts: a few seconds for DNS
		return nil
	}
	var errs []error
	for _, address := range addresses {
		family := "ipv4"
		if address.Is6() {
			family = "ipv6"
		}
		for _, args := range [][]string{
			{"-D", "-f", family, "-s", address.String(), "-p", "udp", "--dport", "53"},
			{"-D", "-f", family, "-s", address.String(), "-p", "tcp", "--dport", "80"},
		} {
			// conntrack fails when it deletes nothing
			if err := run("", "conntrack", args...); err != nil && !strings.Contains(err.Error(), "0 flow entries") {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (l *Linux) Stats() (map[wgtypes.Key]PeerStats, error) {
	devices, err := l.client.Devices()
	if err != nil {
		return nil, err
	}
	stats := map[wgtypes.Key]PeerStats{}
	for _, device := range devices {
		for _, peer := range device.Peers {
			entry := PeerStats{Interface: device.Name, Received: peer.ReceiveBytes, Sent: peer.TransmitBytes}
			if peer.LastHandshakeTime.Unix() > 0 {
				entry.LastHandshake = peer.LastHandshakeTime
			}
			if peer.Endpoint != nil {
				if address, ok := netip.AddrFromSlice(peer.Endpoint.IP); ok {
					entry.Endpoint = netip.AddrPortFrom(address.Unmap(), uint16(peer.Endpoint.Port))
				}
			}
			stats[peer.PublicKey] = entry
		}
	}
	return stats, nil
}

func wireguardLinks() (map[string]bool, error) {
	output, err := capture("ip", "-j", "link", "show", "type", "wireguard")
	if err != nil {
		return nil, err
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if len(bytes.TrimSpace(output)) > 0 {
		if err := json.Unmarshal(output, &links); err != nil {
			return nil, fmt.Errorf("ip link: %w", err)
		}
	}
	names := map[string]bool{}
	for _, link := range links {
		names[link.Name] = true
	}
	return names, nil
}

// interfaceAddresses are the addresses of an interface, of both versions, but the link-local ones: Linux gives
// those itself, when it gives any.
func interfaceAddresses(name string) ([]netip.Prefix, error) {
	output, err := capture("ip", "-j", "address", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var links []struct {
		Addresses []struct {
			Local  string `json:"local"`
			Length int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if len(bytes.TrimSpace(output)) > 0 {
		if err := json.Unmarshal(output, &links); err != nil {
			return nil, fmt.Errorf("ip address: %w", err)
		}
	}
	var list []netip.Prefix
	for _, link := range links {
		for _, info := range link.Addresses {
			if address, err := netip.ParseAddr(info.Local); err == nil && !address.IsLinkLocalUnicast() {
				list = append(list, netip.PrefixFrom(address, info.Length))
			}
		}
	}
	return list, nil
}

const commandTimeout = 20 * time.Second

func run(stdin string, name string, args ...string) error {
	_, err := execute(stdin, name, args...)
	return err
}

func capture(name string, args ...string) ([]byte, error) {
	return execute("", name, args...)
}

func execute(stdin string, name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			message := strings.TrimSpace(stderr.String())
			if message == "" {
				message = err.Error()
			}
			return nil, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), message)
		}
		return stdout.Bytes(), nil
	case <-time.After(commandTimeout):
		command.Process.Kill()
		<-done
		return nil, fmt.Errorf("%s %s: no answer after %s", name, strings.Join(args, " "), commandTimeout)
	}
}
