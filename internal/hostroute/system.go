package hostroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

// System changes the host with ip and nft: the helper runs on the network of the host, with NET_ADMIN.
type System struct{}

// the names of the interfaces that go into a rule: those of Docker, br-0123456789ab or docker0, and the usual ones
var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

func command(stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if text := strings.TrimSpace(stderr.String()); text != "" {
			return out, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), text)
		}
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

func family(ipv6 bool) string {
	if ipv6 {
		return "-6"
	}
	return "-4"
}

// the route of ip -j
type ipRoute struct {
	Type     string `json:"type"`
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Prefsrc  string `json:"prefsrc"`
	Protocol string `json:"protocol"`
}

func parseRoutes(data []byte) ([]ipRoute, error) {
	var routes []ipRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("the routes: %w", err)
	}
	return routes, nil
}

// parseDst reads the destination of a route: default, an address alone, or a prefix.
func parseDst(text string, ipv6 bool) (netip.Prefix, error) {
	if text == "default" {
		if ipv6 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), nil
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), nil
	}
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		return prefix.Masked(), err
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (System) RouteGet(addr netip.Addr) (Hop, error) {
	out, err := command("", "ip", "-j", family(addr.Is6()), "route", "get", addr.String())
	if err != nil {
		return Hop{}, err
	}
	routes, err := parseRoutes(out)
	if err != nil {
		return Hop{}, err
	}
	if len(routes) == 0 {
		return Hop{}, errors.New("no route")
	}
	hop := Hop{Type: routes[0].Type, Dev: routes[0].Dev}
	hop.Gateway, _ = netip.ParseAddr(routes[0].Gateway)
	hop.Source, _ = netip.ParseAddr(routes[0].Prefsrc)
	return hop, nil
}

func (System) IsBridge(dev string) bool {
	if !interfaceName.MatchString(dev) {
		return false
	}
	out, err := command("", "ip", "-j", "-d", "link", "show", "dev", dev)
	if err != nil {
		return false
	}
	var links []struct {
		LinkInfo struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	return json.Unmarshal(out, &links) == nil && len(links) == 1 && links[0].LinkInfo.Kind == "bridge"
}

func (System) LocalNetworks(ipv6 bool) ([]netip.Prefix, error) {
	out, err := command("", "ip", "-j", family(ipv6), "address", "show")
	if err != nil {
		return nil, err
	}
	var links []struct {
		Addresses []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("the addresses: %w", err)
	}
	var networks []netip.Prefix
	for _, link := range links {
		for _, address := range link.Addresses {
			if addr, err := netip.ParseAddr(address.Local); err == nil {
				if prefix, err := addr.Prefix(address.PrefixLen); err == nil {
					networks = append(networks, prefix)
				}
			}
		}
	}
	out, err = command("", "ip", "-j", family(ipv6), "route", "show", "scope", "link")
	if err != nil {
		return nil, err
	}
	routes, err := parseRoutes(out)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		// the routes of a whole family, as a default through an interface, aren't networks of the host
		if prefix, err := parseDst(route.Dst, ipv6); err == nil && prefix.Bits() > 0 {
			networks = append(networks, prefix)
		}
	}
	return networks, nil
}

func (System) Routes(ipv6, owned bool) ([]Entry, error) {
	args := []string{"-j", family(ipv6), "route", "show"}
	if owned {
		args = append(args, "proto", Proto)
	}
	out, err := command("", "ip", args...)
	if err != nil {
		return nil, err
	}
	routes, err := parseRoutes(out)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(routes))
	for _, route := range routes {
		dst, err := parseDst(route.Dst, ipv6)
		if err != nil {
			continue
		}
		entry := Entry{Dst: dst, Dev: route.Dev}
		entry.Gateway, _ = netip.ParseAddr(route.Gateway)
		entries = append(entries, entry)
	}
	return entries, nil
}

func (System) ReplaceRoute(entry Entry) error {
	if !interfaceName.MatchString(entry.Dev) {
		return fmt.Errorf("the interface %q", entry.Dev)
	}
	_, err := command("", "ip", family(entry.Dst.Addr().Is6()), "route", "replace", entry.Dst.String(), "via",
		entry.Gateway.String(), "dev", entry.Dev, "proto", Proto)
	return err
}

func (System) DeleteRoute(entry Entry) error {
	args := []string{family(entry.Dst.Addr().Is6()), "route", "del", entry.Dst.String(), "proto", Proto}
	if entry.Gateway.IsValid() {
		args = append(args, "via", entry.Gateway.String())
	}
	if entry.Dev != "" {
		args = append(args, "dev", entry.Dev)
	}
	_, err := command("", "ip", args...)
	return err
}

func (System) Addresses6(dev string) ([]Address, error) {
	if !interfaceName.MatchString(dev) {
		return nil, fmt.Errorf("the interface %q", dev)
	}
	out, err := command("", "ip", "-j", "-6", "address", "show", "dev", dev, "scope", "global")
	if err != nil {
		return nil, err
	}
	return parseAddresses6(out)
}

func parseAddresses6(data []byte) ([]Address, error) {
	var links []struct {
		Addresses []struct {
			Local      string `json:"local"`
			PrefixLen  int    `json:"prefixlen"`
			Temporary  bool   `json:"temporary"`
			Deprecated bool   `json:"deprecated"`
			Tentative  bool   `json:"tentative"`
			Dynamic    bool   `json:"dynamic"`
			Manage     bool   `json:"mngtmpaddr"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("the addresses: %w", err)
	}
	var addresses []Address
	for _, link := range links {
		for _, a := range link.Addresses {
			addr, err := netip.ParseAddr(a.Local)
			if err != nil || !addr.Is6() {
				continue
			}
			addresses = append(addresses, Address{Prefix: netip.PrefixFrom(addr, a.PrefixLen), Temporary: a.Temporary,
				Deprecated: a.Deprecated, Tentative: a.Tentative, Dynamic: a.Dynamic, ManageTemporary: a.Manage})
		}
	}
	return addresses, nil
}

func table(ipv6 bool) string {
	if ipv6 {
		return "ip6"
	}
	return "ip"
}

func (System) Rules(ipv6 bool) ([]Rule, error) {
	out, err := command("", "nft", "-j", "list", "chain", table(ipv6), "filter", "DOCKER-USER")
	if err != nil {
		return nil, fmt.Errorf("%w (%v)", ErrNoChain, err)
	}
	return parseRules(out)
}

// parseRules reads the rules of the helper in nft -j list chain: oifname "br-..." ip daddr 10.8.0.0/24 counter
// accept comment "authway-server", as iptables shows them too.
func parseRules(data []byte) ([]Rule, error) {
	var document struct {
		Nftables []struct {
			Rule *struct {
				Handle  int    `json:"handle"`
				Comment string `json:"comment"`
				Expr    []struct {
					Match *struct {
						Left struct {
							Meta *struct {
								Key string `json:"key"`
							} `json:"meta"`
							Payload *struct {
								Field string `json:"field"`
							} `json:"payload"`
						} `json:"left"`
						Right json.RawMessage `json:"right"`
					} `json:"match"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("the rules: %w", err)
	}
	var rules []Rule
	for _, item := range document.Nftables {
		if item.Rule == nil || item.Rule.Comment != Comment {
			continue
		}
		rule := Rule{Handle: item.Rule.Handle}
		for _, expr := range item.Rule.Expr {
			if expr.Match == nil {
				continue
			}
			switch {
			case expr.Match.Left.Meta != nil && expr.Match.Left.Meta.Key == "oifname":
				json.Unmarshal(expr.Match.Right, &rule.Dev)
			case expr.Match.Left.Payload != nil && expr.Match.Left.Payload.Field == "daddr":
				var prefix struct {
					Prefix struct {
						Addr string `json:"addr"`
						Len  int    `json:"len"`
					} `json:"prefix"`
				}
				var plain string
				if json.Unmarshal(expr.Match.Right, &plain) == nil {
					if addr, err := netip.ParseAddr(plain); err == nil {
						rule.Dst = netip.PrefixFrom(addr, addr.BitLen())
					}
				} else if json.Unmarshal(expr.Match.Right, &prefix) == nil {
					if addr, err := netip.ParseAddr(prefix.Prefix.Addr); err == nil {
						rule.Dst, _ = addr.Prefix(prefix.Prefix.Len)
					}
				}
			}
		}
		if rule.Dev != "" && rule.Dst.IsValid() {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (System) AddRule(ipv6 bool, rule Rule) error {
	if !interfaceName.MatchString(rule.Dev) || !rule.Dst.IsValid() {
		return fmt.Errorf("an invalid rule: %q %s", rule.Dev, rule.Dst)
	}
	// first in the chain, as Docker asks: its own rules come after DOCKER-USER
	script := fmt.Sprintf("insert rule %s filter DOCKER-USER oifname %q %s daddr %s counter accept comment %q\n",
		table(ipv6), rule.Dev, table(ipv6), rule.Dst.Masked(), Comment)
	_, err := command(script, "nft", "-f", "-")
	return err
}

func (System) DeleteRule(ipv6 bool, rule Rule) error {
	_, err := command("", "nft", "delete", "rule", table(ipv6), "filter", "DOCKER-USER", "handle", fmt.Sprint(rule.Handle))
	return err
}
