package hostroute

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeHost is a Docker host: br-1 is the bridge of the container (172.18.0.2), br-2 the one of another project,
// enp2s0 the local network 192.168.100.0/24 with the address 192.168.100.108.
type fakeHost struct {
	locals  []netip.Prefix
	foreign []Entry
	owned   []Entry
	rules   []Rule
	handle  int
	noChain bool
	addrs6  []Address
	calls   []string
}

func newFakeHost() *fakeHost {
	return &fakeHost{locals: []netip.Prefix{
		netip.MustParsePrefix("172.18.0.0/16"), netip.MustParsePrefix("172.19.0.0/16"),
		netip.MustParsePrefix("192.168.100.0/24"), netip.MustParsePrefix("fd00:db80::/64"),
		netip.MustParsePrefix("fdae:1::/64"),
	}}
}

func (f *fakeHost) RouteGet(addr netip.Addr) (Hop, error) {
	switch {
	case addr == netip.MustParseAddr("172.18.0.1") || addr == netip.MustParseAddr("192.168.100.108"):
		return Hop{Type: "local", Dev: "lo", Source: addr}, nil
	case netip.MustParsePrefix("172.18.0.0/16").Contains(addr):
		return Hop{Dev: "br-1", Source: netip.MustParseAddr("172.18.0.1")}, nil
	case netip.MustParsePrefix("172.19.0.0/16").Contains(addr):
		return Hop{Dev: "br-2", Source: netip.MustParseAddr("172.19.0.1")}, nil
	case netip.MustParsePrefix("fdae:1::/64").Contains(addr):
		return Hop{Dev: "br-1", Source: netip.MustParseAddr("fdae:1::1")}, nil
	case netip.MustParsePrefix("192.168.100.0/24").Contains(addr):
		return Hop{Dev: "enp2s0", Source: netip.MustParseAddr("192.168.100.108")}, nil
	case netip.MustParsePrefix("fd00:db80::/64").Contains(addr):
		// the source of the kernel: a temporary address
		return Hop{Dev: "enp2s0", Source: netip.MustParseAddr("fd00:db80::9dd9:f97b:f251:2e18")}, nil
	case addr.Is6():
		return Hop{Dev: "enp2s0", Gateway: netip.MustParseAddr("fe80::1"), Source: netip.MustParseAddr("fd00:db80::9dd9:f97b:f251:2e18")}, nil
	}
	return Hop{Dev: "enp2s0", Gateway: netip.MustParseAddr("192.168.100.1"), Source: netip.MustParseAddr("192.168.100.108")}, nil
}

func (f *fakeHost) IsBridge(dev string) bool { return strings.HasPrefix(dev, "br-") }

func (f *fakeHost) LocalNetworks(ipv6 bool) ([]netip.Prefix, error) {
	var networks []netip.Prefix
	for _, prefix := range f.locals {
		if prefix.Addr().Is6() == ipv6 {
			networks = append(networks, prefix)
		}
	}
	return networks, nil
}

func (f *fakeHost) Routes(ipv6, owned bool) ([]Entry, error) {
	var entries []Entry
	list := f.owned
	if !owned {
		list = append(append([]Entry{}, f.foreign...), f.owned...)
	}
	for _, entry := range list {
		if entry.Dst.Addr().Is6() == ipv6 {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (f *fakeHost) ReplaceRoute(entry Entry) error {
	f.calls = append(f.calls, "add "+entry.Dst.String()+" via "+entry.Gateway.String()+" dev "+entry.Dev)
	for index, other := range f.owned {
		if other.Dst == entry.Dst {
			f.owned[index] = entry
			return nil
		}
	}
	f.owned = append(f.owned, entry)
	return nil
}

func (f *fakeHost) DeleteRoute(entry Entry) error {
	f.calls = append(f.calls, "del "+entry.Dst.String()+" via "+entry.Gateway.String()+" dev "+entry.Dev)
	for index, other := range f.owned {
		if other == entry {
			f.owned = append(f.owned[:index], f.owned[index+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeHost) Addresses6(dev string) ([]Address, error) { return f.addrs6, nil }

func (f *fakeHost) Rules(ipv6 bool) ([]Rule, error) {
	if f.noChain {
		return nil, ErrNoChain
	}
	var rules []Rule
	for _, rule := range f.rules {
		if rule.Dst.Addr().Is6() == ipv6 {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (f *fakeHost) AddRule(ipv6 bool, rule Rule) error {
	f.handle++
	rule.Handle = f.handle
	f.calls = append(f.calls, "accept "+rule.Dst.String()+" on "+rule.Dev)
	f.rules = append(f.rules, rule)
	return nil
}

func (f *fakeHost) DeleteRule(ipv6 bool, rule Rule) error {
	f.calls = append(f.calls, "block "+rule.Dst.String()+" on "+rule.Dev)
	for index, other := range f.rules {
		if other.Handle == rule.Handle {
			f.rules = append(f.rules[:index], f.rules[index+1:]...)
			return nil
		}
	}
	return nil
}

func (f *fakeHost) takeCalls() string {
	calls := strings.Join(f.calls, "; ")
	f.calls = nil
	return calls
}

func newHelper(t *testing.T, host Host) *Helper {
	t.Helper()
	return NewHelper(t.TempDir(), host, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func want(t *testing.T, h *Helper, wanted Wanted) Report {
	t.Helper()
	if err := WriteWanted(h.dir, wanted); err != nil {
		t.Fatal(err)
	}
	report := h.Pass()
	if read, err := ReadReport(h.dir); err != nil || read.At != report.At || len(read.Routes) != len(report.Routes) {
		t.Fatalf("the report written: %+v %v", read, err)
	}
	return report
}

var office = Want{Server: "Office", Tunnel: "10.8.1.0/24", Via: "172.18.0.2", Network: "192.168.100.0/24"}

func TestRouteAddedAndTakenAway(t *testing.T) {
	host := newFakeHost()
	// a route of another project, and one of the admin: neither is touched
	other := Entry{Dst: netip.MustParsePrefix("10.9.0.0/24"), Gateway: netip.MustParseAddr("172.19.0.2"), Dev: "br-2"}
	host.owned = []Entry{other}
	host.foreign = []Entry{{Dst: netip.MustParsePrefix("10.50.0.0/16"), Gateway: netip.MustParseAddr("192.168.100.1"), Dev: "enp2s0"}}
	h := newHelper(t, host)

	report := want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{office}})
	state := report.Routes[0]
	if !state.Routed || state.Error != "" || state.Bridge != "br-1" || state.Host != "192.168.100.108" || state.Inbound {
		t.Fatalf("state: %+v", state)
	}
	if calls := host.takeCalls(); calls != "add 10.8.1.0/24 via 172.18.0.2 dev br-1" {
		t.Errorf("calls: %s", calls)
	}
	if got, ok := report.Find("10.8.1.0/24", "172.18.0.2"); !ok || got != state {
		t.Errorf("find: %+v %v", got, ok)
	}
	// nothing new: nothing changes
	if report = want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{office}}); !report.Routes[0].Routed {
		t.Errorf("again: %+v", report.Routes[0])
	}
	if calls := host.takeCalls(); calls != "" {
		t.Errorf("calls again: %s", calls)
	}
	// the container got another address: the route follows
	moved := office
	moved.Via = "172.18.0.3"
	want(t, h, Wanted{Addresses: []string{"172.18.0.3"}, Routes: []Want{moved}})
	if calls := host.takeCalls(); calls != "add 10.8.1.0/24 via 172.18.0.3 dev br-1" {
		t.Errorf("calls after the move: %s", calls)
	}
	// back to NAT: the route goes, the one of the other project stays
	want(t, h, Wanted{Addresses: []string{"172.18.0.3"}})
	if calls := host.takeCalls(); calls != "del 10.8.1.0/24 via 172.18.0.3 dev br-1" {
		t.Errorf("calls after NAT: %s", calls)
	}
	if len(host.owned) != 1 || host.owned[0] != other {
		t.Errorf("routes left: %+v", host.owned)
	}
}

func TestRefusedRoutes(t *testing.T) {
	host := newFakeHost()
	host.foreign = []Entry{{Dst: netip.MustParsePrefix("10.20.0.0/24"), Gateway: netip.MustParseAddr("192.168.100.1"), Dev: "enp2s0"}}
	h := newHelper(t, host)
	cases := []struct {
		want    Want
		problem string
	}{
		// a macvlan container: the router reaches it directly
		{Want{Tunnel: "10.8.1.0/24", Via: "192.168.100.240", Network: "192.168.100.0/24"}, "isn't on a Docker bridge"},
		{Want{Tunnel: "10.8.1.0/24", Via: "172.18.0.1", Network: "192.168.100.0/24"}, "is an address of the Docker host"},
		{Want{Tunnel: "10.8.1.0/24", Via: "10.1.1.1", Network: "192.168.100.0/24"}, "isn't on a network of the Docker host"},
		{Want{Tunnel: "192.168.100.0/25", Via: "172.18.0.2", Network: "192.168.100.0/24"}, "overlaps 192.168.100.0/24"},
		{Want{Tunnel: "172.16.0.0/12", Via: "172.18.0.2", Network: "192.168.100.0/24"}, "holds the address of the container"},
		{Want{Tunnel: "0.0.0.0/0", Via: "172.18.0.2", Network: "192.168.100.0/24"}, "the whole internet"},
		{Want{Tunnel: "10.20.0.0/24", Via: "172.18.0.2", Network: "192.168.100.0/24"}, "already has a route to 10.20.0.0/24, through 192.168.100.1"},
		{Want{Tunnel: "10.8.1.0/24", Via: "fdae:1::2", Network: "192.168.100.0/24"}, "invalid"},
		{Want{Tunnel: "nonsense", Via: "172.18.0.2", Network: "192.168.100.0/24"}, "invalid"},
	}
	for _, c := range cases {
		report := want(t, h, Wanted{Routes: []Want{c.want}})
		if state := report.Routes[0]; state.Routed || !strings.Contains(state.Error, c.problem) {
			t.Errorf("%+v: %+v", c.want, state)
		}
	}
	if calls := host.takeCalls(); calls != "" {
		t.Errorf("calls: %s", calls)
	}
}

func TestInbound(t *testing.T) {
	host := newFakeHost()
	// a rule of another project stays
	host.rules = []Rule{{Dev: "br-2", Dst: netip.MustParsePrefix("10.9.0.0/24"), Handle: 100}}
	h := newHelper(t, host)
	inbound := office
	inbound.Inbound = true
	report := want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{inbound}})
	if state := report.Routes[0]; !state.Routed || !state.Inbound || state.Error != "" {
		t.Fatalf("state: %+v", state)
	}
	if calls := host.takeCalls(); calls != "add 10.8.1.0/24 via 172.18.0.2 dev br-1; accept 10.8.1.0/24 on br-1" {
		t.Errorf("calls: %s", calls)
	}
	want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{inbound}})
	if calls := host.takeCalls(); calls != "" {
		t.Errorf("calls again: %s", calls)
	}
	// connections from the networks off: the rule goes, the route stays
	report = want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{office}})
	if state := report.Routes[0]; !state.Routed || state.Inbound {
		t.Errorf("state: %+v", state)
	}
	if calls := host.takeCalls(); calls != "block 10.8.1.0/24 on br-1" {
		t.Errorf("calls off: %s", calls)
	}
	if len(host.rules) != 1 || host.rules[0].Handle != 100 {
		t.Errorf("rules left: %+v", host.rules)
	}

	// Docker without DOCKER-USER: routed, the connections from the networks blocked, and it says so
	host.noChain = true
	report = want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{inbound}})
	if state := report.Routes[0]; !state.Routed || state.Inbound || !strings.Contains(state.Error, "stay blocked") {
		t.Errorf("without the chain: %+v", state)
	}
}

func TestIPv6HostAddress(t *testing.T) {
	host := newFakeHost()
	host.addrs6 = []Address{
		{Prefix: netip.MustParsePrefix("fd00:db80::9dd9:f97b:f251:2e18/64"), Temporary: true, Dynamic: true},
		{Prefix: netip.MustParsePrefix("2001:db8::20c:29ff:fe08:41b1/64"), Dynamic: true, ManageTemporary: true},
		{Prefix: netip.MustParsePrefix("fd00:db80::a94d:b354:9fe9:6a8/64"), Deprecated: true, Dynamic: true},
		{Prefix: netip.MustParsePrefix("fd00:db80::5/128"), Dynamic: true},
		{Prefix: netip.MustParsePrefix("fd00:db80::20c:29ff:fe08:41b1/64"), Dynamic: true, ManageTemporary: true},
	}
	h := newHelper(t, host)
	six := Want{Server: "Office", Tunnel: "fd71:be10:95d2:1::/64", Via: "fdae:1::2", Network: "fd00:db80::/64"}
	report := want(t, h, Wanted{Addresses: []string{"172.18.0.2", "fdae:1::2"}, Routes: []Want{office, six}})
	if state := report.Routes[1]; !state.Routed || state.Bridge != "br-1" || state.Host != "fd00:db80::20c:29ff:fe08:41b1" {
		t.Fatalf("IPv6: %+v", state)
	}
	if calls := host.takeCalls(); calls != "add 10.8.1.0/24 via 172.18.0.2 dev br-1; add fd71:be10:95d2:1::/64 via fdae:1::2 dev br-1" {
		t.Errorf("calls: %s", calls)
	}
	// a network the host reaches through its router: a stable address of the interface, then the source
	six.Network = "2001:db8:5::/48"
	if state := want(t, h, Wanted{Routes: []Want{six}}).Routes[0]; state.Host != "2001:db8::20c:29ff:fe08:41b1" {
		t.Errorf("through the router: %+v", state)
	}
	host.addrs6 = host.addrs6[:1]
	if state := want(t, h, Wanted{Routes: []Want{six}}).Routes[0]; state.Host != "fd00:db80::9dd9:f97b:f251:2e18" {
		t.Errorf("only a temporary address: %+v", state)
	}
}

func TestCleanAndRestart(t *testing.T) {
	host := newFakeHost()
	other := Entry{Dst: netip.MustParsePrefix("10.9.0.0/24"), Gateway: netip.MustParseAddr("172.19.0.2"), Dev: "br-2"}
	host.owned = []Entry{other}
	h := newHelper(t, host)
	inbound := office
	inbound.Inbound = true
	want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{inbound}})
	host.takeCalls()

	// a new helper after a restart knows the bridge from the report: a wanted file without the address still
	// takes the route away
	again := NewHelper(h.dir, host, h.log)
	if !again.bridges["br-1"] || again.bridges["br-2"] {
		t.Errorf("bridges: %v", again.bridges)
	}
	if err := WriteWanted(h.dir, Wanted{}); err != nil {
		t.Fatal(err)
	}
	again.Pass()
	if calls := host.takeCalls(); calls != "del 10.8.1.0/24 via 172.18.0.2 dev br-1; block 10.8.1.0/24 on br-1" {
		t.Errorf("calls: %s", calls)
	}

	want(t, again, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{inbound}})
	host.takeCalls()
	again.Clean()
	if calls := host.takeCalls(); calls != "del 10.8.1.0/24 via 172.18.0.2 dev br-1; block 10.8.1.0/24 on br-1" {
		t.Errorf("clean: %s", calls)
	}
	if len(host.owned) != 1 || host.owned[0] != other {
		t.Errorf("routes left: %+v", host.owned)
	}
	if _, err := os.Stat(filepath.Join(h.dir, ReportFile)); !os.IsNotExist(err) {
		t.Errorf("the report stays: %v", err)
	}
	if err := Health(h.dir, time.Now()); err == nil {
		t.Error("healthy without a report")
	}
}

func TestPassWithoutWanted(t *testing.T) {
	host := newFakeHost()
	h := newHelper(t, host)
	if report := h.Pass(); report.Error != "" || len(report.Routes) != 0 || report.At == 0 {
		t.Errorf("nothing written yet: %+v", report)
	}
	if err := Health(h.dir, time.Now()); err != nil {
		t.Errorf("health: %v", err)
	}
	want(t, h, Wanted{Addresses: []string{"172.18.0.2"}, Routes: []Want{office}})
	host.takeCalls()
	// a file that can't be read keeps the routes
	if err := os.WriteFile(filepath.Join(h.dir, WantedFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if report := h.Pass(); report.Error == "" || len(host.owned) != 1 {
		t.Errorf("unreadable: %+v %+v", report, host.owned)
	}
	if err := Health(h.dir, time.Now()); err == nil {
		t.Error("healthy with an unreadable file")
	}
}

func TestReader(t *testing.T) {
	dir := t.TempDir()
	reader := NewReader(dir)
	now := time.Unix(1_800_000_000, 0)
	if _, ok := reader.Get(now); ok {
		t.Error("running without a report")
	}
	if err := writeReport(dir, Report{At: now.Unix(), Routes: []State{{Tunnel: "10.8.1.0/24", Via: "172.18.0.2", Routed: true}}}); err != nil {
		t.Fatal(err)
	}
	// read again after a second only
	if _, ok := reader.Get(now.Add(500 * time.Millisecond)); ok {
		t.Error("read again at once")
	}
	if report, ok := reader.Get(now.Add(time.Second)); !ok || len(report.Routes) != 1 {
		t.Errorf("fresh: %+v %v", report, ok)
	}
	if _, ok := reader.Get(now.Add(StaleAfter + time.Second)); ok {
		t.Error("an old report counts")
	}
}

func TestParse(t *testing.T) {
	// what nft -j shows of a rule of the helper, on a Debian host with Docker 29
	rules, err := parseRules([]byte(`{"nftables": [{"metainfo": {"version": "1.1.3"}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 15}},
	{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 263, "comment": "authway-server", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-309ead0925c4"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "10.8.1.0", "len": 24}}}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}},
	{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 264, "comment": "authway-server", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-1"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.8.2.7"}}, {"accept": null}]}},
	{"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 265, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "eth9"}}, {"drop": null}]}}]}`))
	if err != nil || len(rules) != 2 || rules[0] != (Rule{Dev: "br-309ead0925c4", Dst: netip.MustParsePrefix("10.8.1.0/24"), Handle: 263}) ||
		rules[1] != (Rule{Dev: "br-1", Dst: netip.MustParsePrefix("10.8.2.7/32"), Handle: 264}) {
		t.Errorf("rules: %+v %v", rules, err)
	}

	routes, err := parseRoutes([]byte(`[{"dst":"default","gateway":"192.168.100.1","dev":"enp2s0","protocol":"dhcp","prefsrc":"192.168.100.108","metric":100,"flags":[]},{"dst":"10.8.1.0/24","gateway":"172.18.0.2","dev":"br-309ead0925c4","protocol":"77","flags":[]},{"dst":"10.8.1.9","dev":"wg0","flags":[]}]`))
	if err != nil || len(routes) != 3 || routes[1].Gateway != "172.18.0.2" || routes[1].Protocol != "77" {
		t.Fatalf("routes: %+v %v", routes, err)
	}
	for text, expected := range map[string]string{"default": "0.0.0.0/0", "10.8.1.0/24": "10.8.1.0/24", "10.8.1.9": "10.8.1.9/32", "10.8.1.9/24": "10.8.1.0/24"} {
		if prefix, err := parseDst(text, false); err != nil || prefix.String() != expected {
			t.Errorf("%s: %s %v", text, prefix, err)
		}
	}
	if prefix, err := parseDst("default", true); err != nil || prefix.String() != "::/0" {
		t.Errorf("IPv6 default: %s %v", prefix, err)
	}

	addresses, err := parseAddresses6([]byte(`[{"ifindex":2,"ifname":"enp2s0","addr_info":[{"family":"inet6","local":"fd00:db80::9dd9:f97b:f251:2e18","prefixlen":64,"scope":"global","temporary":true,"dynamic":true},{"family":"inet6","local":"fd00:db80::5","prefixlen":128,"scope":"global","dynamic":true,"noprefixroute":true},{"family":"inet6","local":"fd00:db80::20c:29ff:fe08:41b1","prefixlen":64,"scope":"global","dynamic":true,"mngtmpaddr":true}]}]`))
	if err != nil || len(addresses) != 3 || !addresses[0].Temporary || addresses[1].Prefix.Bits() != 128 || !addresses[2].ManageTemporary {
		t.Errorf("addresses: %+v %v", addresses, err)
	}
	for name, ok := range map[string]bool{"br-309ead0925c4": true, "docker0": true, "enp2s0": true, `br"; drop`: false, "": false, "a-name-far-too-long": false} {
		if interfaceName.MatchString(name) != ok {
			t.Errorf("interface name %q", name)
		}
	}
}
