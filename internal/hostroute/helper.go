package hostroute

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Hop is how the host reaches an address: ip route get.
type Hop struct {
	// "" or "unicast" for a route, "local" for an address of the host...
	Type    string
	Dev     string
	Gateway netip.Addr
	Source  netip.Addr
}

// Entry is a route of the main table.
type Entry struct {
	Dst     netip.Prefix
	Gateway netip.Addr
	Dev     string
}

// Rule is a rule of the helper in DOCKER-USER: the connections to a tunnel through a bridge pass.
type Rule struct {
	Dev    string
	Dst    netip.Prefix
	Handle int
}

// Address is an IPv6 address of the host, with what makes it a good next hop or not.
type Address struct {
	Prefix                                    netip.Prefix
	Temporary, Deprecated, Tentative, Dynamic bool
	ManageTemporary                           bool
}

// Host is what the helper does on the Docker host: ip and nft on Linux, a fake in the tests.
type Host interface {
	RouteGet(addr netip.Addr) (Hop, error)
	IsBridge(dev string) bool
	// the networks of the host: those of its addresses, and its routes of scope link
	LocalNetworks(ipv6 bool) ([]netip.Prefix, error)
	// the routes of the main table; owned, only those of the helper
	Routes(ipv6, owned bool) ([]Entry, error)
	ReplaceRoute(entry Entry) error
	DeleteRoute(entry Entry) error
	// the global IPv6 addresses of an interface
	Addresses6(dev string) ([]Address, error)
	// the rules of the helper in DOCKER-USER; ErrNoChain without it
	Rules(ipv6 bool) ([]Rule, error)
	AddRule(ipv6 bool, rule Rule) error
	DeleteRule(ipv6 bool, rule Rule) error
}

// Helper keeps the routes of the Docker host in step with what Authway Server asks.
type Helper struct {
	dir  string
	host Host
	log  *slog.Logger
	now  func() time.Time
	// the bridges of the container: the helper changes routes and rules on them only
	bridges map[string]bool
}

func NewHelper(dir string, host Host, log *slog.Logger) *Helper {
	h := &Helper{dir: dir, host: host, log: log, now: time.Now, bridges: map[string]bool{}}
	// the bridges of the routes it added before a restart: they go if nothing asks for them any more
	if report, err := ReadReport(dir); err == nil {
		for _, state := range report.Routes {
			if state.Bridge != "" {
				h.bridges[state.Bridge] = true
			}
		}
	}
	return h
}

// Run passes at once when Authway Server writes, and every Interval anyway: a route taken away on the host, or a
// bridge made again by Docker, comes back. Stopped, it takes its routes and its rules away.
func (h *Helper) Run(ctx context.Context) {
	h.log.Info("routing the tunnels of the routed servers through the Docker host", "folder", h.dir)
	var seen time.Time
	var last time.Time
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		info, err := os.Stat(filepath.Join(h.dir, WantedFile))
		changed := err == nil && !info.ModTime().Equal(seen)
		if changed || h.now().Sub(last) >= Interval {
			if err == nil {
				seen = info.ModTime()
			}
			h.Pass()
			last = h.now()
		}
		select {
		case <-ctx.Done():
			h.Clean()
			return
		case <-ticker.C:
		}
	}
}

// Pass reads what Authway Server asks, changes the host and writes the report.
func (h *Helper) Pass() Report {
	report := Report{At: h.now().Unix(), Routes: []State{}}
	wanted, err := ReadWanted(h.dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Authway Server hasn't written yet: nothing to route
	case err != nil:
		// the routes stay as they are until the file can be read
		report.Error = "can't read what Authway Server asks: " + err.Error()
		h.write(report)
		return report
	}
	report.Routes = h.apply(wanted)
	h.write(report)
	return report
}

func (h *Helper) write(report Report) {
	if err := writeReport(h.dir, report); err != nil {
		h.log.Error("can't write the report", "error", err)
	}
}

type viaInfo struct {
	bridge  string
	problem string
}

type wantedRoute struct {
	index int
	entry Entry
	rule  bool
}

func (h *Helper) apply(wanted Wanted) []State {
	vias := map[netip.Addr]viaInfo{}
	bridgeOf := func(via netip.Addr) viaInfo {
		if info, ok := vias[via]; ok {
			return info
		}
		info := h.findBridge(via)
		if info.bridge != "" {
			h.bridges[info.bridge] = true
		}
		vias[via] = info
		return info
	}
	for _, text := range wanted.Addresses {
		if addr, err := netip.ParseAddr(text); err == nil {
			bridgeOf(addr)
		}
	}

	states := make([]State, len(wanted.Routes))
	var routes [2][]wantedRoute
	for index, want := range wanted.Routes {
		state := &states[index]
		state.Tunnel, state.Via = want.Tunnel, want.Via
		tunnel, err1 := netip.ParsePrefix(want.Tunnel)
		via, err2 := netip.ParseAddr(want.Via)
		network, err3 := netip.ParsePrefix(want.Network)
		if err := errors.Join(err1, err2, err3); err != nil || tunnel.Addr().Is6() != via.Is6() || via.Is6() != network.Addr().Is6() {
			state.Error = "an invalid route"
			continue
		}
		tunnel = tunnel.Masked()
		info := bridgeOf(via)
		if info.problem != "" {
			state.Error = info.problem
			continue
		}
		state.Bridge = info.bridge
		if problem := h.conflict(tunnel, via); problem != "" {
			state.Error = problem
			continue
		}
		state.Host = h.hostAddress(network, info.bridge)
		family := 0
		if via.Is6() {
			family = 1
		}
		routes[family] = append(routes[family], wantedRoute{index: index, entry: Entry{Dst: tunnel, Gateway: via, Dev: info.bridge}, rule: want.Inbound})
	}
	for family, wantedRoutes := range routes {
		h.applyRoutes(family == 1, wantedRoutes, states)
		h.applyRules(family == 1, wantedRoutes, states)
	}
	return states
}

// findBridge is the bridge of the host where the container has that address: a Docker bridge, directly.
func (h *Helper) findBridge(via netip.Addr) viaInfo {
	hop, err := h.host.RouteGet(via)
	switch {
	case err != nil:
		return viaInfo{problem: "can't find the container on the Docker host: " + err.Error()}
	case hop.Type != "" && hop.Type != "unicast":
		return viaInfo{problem: via.String() + " is an address of the Docker host, not of the container"}
	case hop.Gateway.IsValid():
		return viaInfo{problem: "the container isn't on a network of the Docker host: " + via.String() + " is through " + hop.Gateway.String()}
	case !h.host.IsBridge(hop.Dev):
		return viaInfo{problem: "the container isn't on a Docker bridge: " + via.String() + " is on " + hop.Dev + ", the router reaches it directly"}
	}
	return viaInfo{bridge: hop.Dev}
}

// conflict says why the route would break the host: a tunnel over a network of the host, or a route to it that
// isn't of the helper.
func (h *Helper) conflict(tunnel netip.Prefix, via netip.Addr) string {
	if tunnel.Bits() == 0 {
		return "the whole internet can't go to the container"
	}
	if tunnel.Contains(via) {
		return "the tunnel network holds the address of the container"
	}
	ipv6 := via.Is6()
	locals, err := h.host.LocalNetworks(ipv6)
	if err != nil {
		return "can't read the networks of the Docker host: " + err.Error()
	}
	for _, local := range locals {
		if local.Overlaps(tunnel) {
			return fmt.Sprintf("the tunnel network %s overlaps %s, a network of the Docker host", tunnel, local)
		}
	}
	all, err1 := h.host.Routes(ipv6, false)
	owned, err2 := h.host.Routes(ipv6, true)
	if err := errors.Join(err1, err2); err != nil {
		return "can't read the routes of the Docker host: " + err.Error()
	}
	for _, entry := range all {
		if entry.Dst == tunnel && !contains(owned, entry) {
			through := entry.Dev
			if entry.Gateway.IsValid() {
				through = entry.Gateway.String()
			}
			return fmt.Sprintf("the Docker host already has a route to %s, through %s", tunnel, through)
		}
	}
	return ""
}

func contains(entries []Entry, entry Entry) bool {
	for _, other := range entries {
		if other == entry {
			return true
		}
	}
	return false
}

// hostAddress is the address of the host towards the network: the source of its route there. For IPv6 a stable
// address of that interface, in the network if it has one: the source is often a temporary address, which changes.
func (h *Helper) hostAddress(network netip.Prefix, bridge string) string {
	target := network.Masked().Addr()
	if network.Bits() < target.BitLen()-1 {
		target = target.Next()
	}
	hop, err := h.host.RouteGet(target)
	if err != nil || hop.Dev == bridge {
		return ""
	}
	if !target.Is6() {
		if hop.Source.IsValid() {
			return hop.Source.String()
		}
		return ""
	}
	addresses, _ := h.host.Addresses6(hop.Dev)
	best, bestRank := netip.Addr{}, 0
	for _, address := range addresses {
		if address.Temporary || address.Deprecated || address.Tentative {
			continue
		}
		rank := 1
		switch {
		case !address.Dynamic:
			rank = 3
		case address.ManageTemporary:
			rank = 2
		}
		if network.Contains(address.Prefix.Addr()) {
			rank += 3
		}
		if rank > bestRank {
			best, bestRank = address.Prefix.Addr(), rank
		}
	}
	if best.IsValid() {
		return best.String()
	}
	if hop.Source.IsValid() {
		return hop.Source.String()
	}
	return ""
}

func (h *Helper) applyRoutes(ipv6 bool, wanted []wantedRoute, states []State) {
	owned, err := h.host.Routes(ipv6, true)
	if err != nil {
		for _, route := range wanted {
			states[route.index].Error = "can't read the routes of the Docker host: " + err.Error()
		}
		return
	}
	// a tunnel still wanted through another address is replaced below, without a moment with no route
	replaced := map[netip.Prefix]bool{}
	for _, route := range wanted {
		replaced[route.entry.Dst] = true
	}
	for _, entry := range owned {
		if h.bridges[entry.Dev] && !replaced[entry.Dst] {
			if err := h.host.DeleteRoute(entry); err != nil {
				h.log.Error("can't take a route away", "route", entry.Dst, "via", entry.Gateway, "error", err)
			} else {
				h.log.Info("route taken away", "route", entry.Dst, "via", entry.Gateway, "bridge", entry.Dev)
			}
		}
	}
	for _, route := range wanted {
		state := &states[route.index]
		if contains(owned, route.entry) {
			state.Routed = true
			continue
		}
		if err := h.host.ReplaceRoute(route.entry); err != nil {
			state.Error = "can't add the route: " + err.Error()
			h.log.Error("can't add a route", "route", route.entry.Dst, "via", route.entry.Gateway, "error", err)
			continue
		}
		state.Routed = true
		h.log.Info("route added", "route", route.entry.Dst, "via", route.entry.Gateway, "bridge", route.entry.Dev)
	}
}

func (h *Helper) applyRules(ipv6 bool, wanted []wantedRoute, states []State) {
	needed := map[Rule]int{}
	for _, route := range wanted {
		if route.rule && states[route.index].Routed {
			needed[Rule{Dev: route.entry.Dev, Dst: route.entry.Dst}] = route.index
		}
	}
	rules, err := h.host.Rules(ipv6)
	if err != nil {
		// nothing to take away, and nothing to add: no problem
		for _, index := range needed {
			states[index].Error = "the connections from the networks stay blocked: " + err.Error()
		}
		return
	}
	present := map[Rule]bool{}
	for _, rule := range rules {
		key := Rule{Dev: rule.Dev, Dst: rule.Dst}
		if _, ok := needed[key]; ok && !present[key] {
			present[key] = true
			continue
		}
		// one of the bridges of the container, or a copy: the helper made it
		if h.bridges[rule.Dev] || present[key] {
			if err := h.host.DeleteRule(ipv6, rule); err != nil {
				h.log.Error("can't take a rule away", "tunnel", rule.Dst, "error", err)
			} else {
				h.log.Info("connections from the networks blocked again", "tunnel", rule.Dst, "bridge", rule.Dev)
			}
		}
	}
	keys := make([]Rule, 0, len(needed))
	for key := range needed {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a].Dst.String() < keys[b].Dst.String() })
	for _, key := range keys {
		state := &states[needed[key]]
		if present[key] {
			state.Inbound = true
			continue
		}
		if err := h.host.AddRule(ipv6, key); err != nil {
			state.Error = "the connections from the networks stay blocked: " + err.Error()
			h.log.Error("can't let the connections from the networks through", "tunnel", key.Dst, "error", err)
			continue
		}
		state.Inbound = true
		h.log.Info("connections from the networks let through", "tunnel", key.Dst, "bridge", key.Dev)
	}
}

// Clean takes away the routes and the rules of the helper on the bridges of the container, and the report: the
// helper stops, nothing keeps them up to date.
func (h *Helper) Clean() {
	for _, ipv6 := range []bool{false, true} {
		h.applyRoutes(ipv6, nil, nil)
		if rules, err := h.host.Rules(ipv6); err == nil {
			for _, rule := range rules {
				if h.bridges[rule.Dev] {
					if err := h.host.DeleteRule(ipv6, rule); err != nil {
						h.log.Error("can't take a rule away", "tunnel", rule.Dst, "error", err)
					}
				}
			}
		}
	}
	os.Remove(filepath.Join(h.dir, ReportFile))
	h.log.Info("stopped: the routes through the container are taken away from the Docker host")
}

// Health is for the health check of the helper: an error when it stopped writing, or can't read what Authway
// Server asks.
func Health(dir string, now time.Time) error {
	report, err := ReadReport(dir)
	switch {
	case err != nil:
		return fmt.Errorf("no report: %w", err)
	case !report.Fresh(now):
		return errors.New("the report is old: the helper is stuck")
	case report.Error != "":
		return errors.New(report.Error)
	}
	return nil
}
