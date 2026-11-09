package system

import (
	"net/netip"
	"strconv"
	"strings"
)

// Uplink is the way out of the container towards an address: the interface of the route, the driver that gives it,
// and the address of the container on it, where the router of a routed server sends the tunnels back.
type Uplink struct {
	Interface string `json:"interface"`
	// macvlan, ipvlan, veth (a Docker bridge), another driver, or "" when it can't be read
	Driver  string `json:"driver"`
	Address string `json:"address"`
}

// The drivers of the network of the container that matter to a routed server.
const (
	// the router of the networks reaches the container directly, at the MAC address of its own
	DriverMacvlan = "macvlan"
	// all the containers share the MAC address of the host, and the kernel gives a packet to the one with its
	// destination address: those for the tunnels go to the host
	DriverIPvlan = "ipvlan"
	// a Docker bridge: the host routes between the container and the networks, behind the rules of Docker; the
	// helper of compose.host-routes.yaml adds the routes there
	DriverVeth = "veth"
)

// RoutedServer is an enabled server routed to its networks, and how the container reaches them.
type RoutedServer struct {
	Name   string
	Routes []Route
}

// Route is what the router of the networks of a routed server needs, for one IP version: the tunnel network through
// the address of the container.
type Route struct {
	Tunnel string
	// the first network of the server of the version of the tunnel
	Network string
	// a zero Interface: no route to the network in the container
	Uplink Uplink
	// on a Docker bridge, the route of the Docker host to the container
	Host HostRoute
}

// HostRoute is the route of a tunnel on the Docker host, through the container on a Docker bridge: the helper of
// compose.host-routes.yaml adds it, and tells the address of the host for the router.
type HostRoute struct {
	State string `json:"state"`
	// the address of the Docker host towards the network: the next hop of the route on the router
	Address string `json:"address"`
	// the address of before, when Address changed: the router still has the route through it, until an
	// administrator says it has the new one
	Previous string `json:"previous,omitempty"`
	// why the route isn't there, or why the connections from the networks stay blocked
	Error string `json:"error"`
}

// The states of a HostRoute.
const (
	// no helper: AUTHWAY_HOST_ROUTES isn't set
	HostOff = "off"
	// the helper hasn't written for a while
	HostStopped = "stopped"
	// asked, not done yet
	HostPending = "pending"
	HostRouted  = "routed"
	// the helper refused it: Error says why
	HostFailed = "failed"
)

type uplinkProbe interface {
	Uplink(to netip.Addr) (Uplink, bool)
}

// Uplink tells how the container reaches an address; false when there's no route to it, or no way to read it.
func (m *Monitor) Uplink(to netip.Addr) (Uplink, bool) {
	if probe, ok := m.probe.(uplinkProbe); ok {
		return probe.Uplink(to)
	}
	return Uplink{}, false
}

// parseRoute4 returns the interface of the route of /proc/net/route that takes the address: the longest prefix, then
// the lowest metric. The addresses and the masks are in the byte order of the network, read as a little-endian
// number.
func parseRoute4(text string, to netip.Addr) string {
	const up, reject = 0x0001, 0x0200
	if !to.Is4() {
		return ""
	}
	target := to.As4()
	best, bestBits, bestMetric := "", -1, uint64(0)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "Iface" {
			continue
		}
		destination, err1 := strconv.ParseUint(fields[1], 16, 32)
		flags, err2 := strconv.ParseUint(fields[3], 16, 32)
		metric, err3 := strconv.ParseUint(fields[6], 10, 32)
		mask, err4 := strconv.ParseUint(fields[7], 16, 32)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || flags&up == 0 || flags&reject != 0 {
			continue
		}
		bits, matches := 0, true
		for index := 0; index < 4; index++ {
			maskByte := byte(mask >> (8 * index))
			if target[index]&maskByte != byte(destination>>(8*index))&maskByte {
				matches = false
			}
			bits += onesCount(maskByte)
		}
		if matches && (bits > bestBits || bits == bestBits && metric < bestMetric) {
			best, bestBits, bestMetric = fields[0], bits, metric
		}
	}
	return best
}

// parseRoute6 does the same with /proc/net/ipv6_route, whose addresses are written in full and lengths in hex; the
// loopback routes are left out, the one that rejects everything included.
func parseRoute6(text string, to netip.Addr) string {
	const up, reject = 0x0001, 0x0200
	if !to.Is6() || to.Is4In6() {
		return ""
	}
	best, bestBits, bestMetric := "", -1, uint64(0)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[9] == "lo" || len(fields[0]) != 32 {
			continue
		}
		length, err1 := strconv.ParseUint(fields[1], 16, 8)
		metric, err2 := strconv.ParseUint(fields[5], 16, 32)
		flags, err3 := strconv.ParseUint(fields[8], 16, 32)
		var raw [16]byte
		var err4 error
		for index := range raw {
			var value uint64
			value, err4 = strconv.ParseUint(fields[0][2*index:2*index+2], 16, 8)
			if err4 != nil {
				break
			}
			raw[index] = byte(value)
		}
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || length > 128 || flags&up == 0 || flags&reject != 0 {
			continue
		}
		prefix := netip.PrefixFrom(netip.AddrFrom16(raw), int(length))
		if prefix.Contains(to) && (int(length) > bestBits || int(length) == bestBits && metric < bestMetric) {
			best, bestBits, bestMetric = fields[9], int(length), metric
		}
	}
	return best
}

func onesCount(value byte) int {
	count := 0
	for ; value != 0; value &= value - 1 {
		count++
	}
	return count
}
