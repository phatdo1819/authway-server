package system

import (
	"math"
	"net/netip"
	"runtime"
	"time"
)

// Simulated is a probe of made-up values, to try the web UI on a computer without Linux: they move like the ones
// of a small server, and the history is full from the start. The System page says they are made up.
func Simulated() Probe {
	return simulated{booted: time.Now().Add(-simUptime)}
}

// the counters start with the made-up host
type simulated struct {
	booted time.Time
}

const simUptime = 3*24*time.Hour + 5*time.Hour

const (
	simProcessors = 4
	simMemory     = 4 << 30
)

// the bytes per second of each interface, received and sent, on average
var simInterfaces = []struct {
	name     string
	received float64
	sent     float64
}{
	{"eth0", 160_000, 70_000}, {"wg0", 90_000, 30_000}, {"wg1", 20_000, 9_000}, {"wg2", 3_000, 1_200}, {"lo", 40, 40},
}

// wave is the count at t of a rate of base plus a sine of amplitude and period: it never goes down while base is
// above amplitude
func wave(t, base, amplitude, period float64) float64 {
	return base*t + amplitude*period/(2*math.Pi)*(1-math.Cos(2*math.Pi*t/period))
}

// CountersAt makes slow waves of hours, quicker ones of minutes, and a ripple
func (s simulated) CountersAt(at time.Time) Counters {
	t := at.Sub(s.booted).Seconds()
	ticks := t * 100 * simProcessors
	busy := 100 * simProcessors * (wave(t, 0.11, 0.04, 4*3600) + wave(t, 0, 0.03, 1800) + wave(t, 0, 0.02, 97))
	c := Counters{
		CPUTotal: uint64(ticks), CPUBusy: uint64(busy), CPUIOWait: uint64(ticks * 0.004), Processors: simProcessors,
		OwnCPU:          time.Duration(wave(t, 0.006, 0.003, 600) * simProcessors * float64(time.Second)),
		MemoryTotal:     simMemory,
		MemoryAvailable: uint64(simMemory * (0.62 + 0.04*math.Sin(2*math.Pi*t/7200))),
		OwnMemory:       uint64(26<<20 + 3<<20*math.Sin(2*math.Pi*t/3000)),
		Interfaces:      map[string]InterfaceCounters{},
	}
	for _, iface := range simInterfaces {
		received := wave(t, iface.received, iface.received*0.45, 6*3600) + wave(t, 0, iface.received*0.3, 1500) +
			wave(t, 0, iface.received*0.15, 113)
		sent := wave(t, iface.sent, iface.sent*0.45, 6*3600) + wave(t, 0, iface.sent*0.3, 1500) + wave(t, 0, iface.sent*0.15, 89)
		c.Interfaces[iface.name] = InterfaceCounters{
			ReceivedBytes: uint64(received), SentBytes: uint64(sent),
			ReceivedPackets: uint64(received / 700), SentPackets: uint64(sent / 400),
		}
	}
	return c
}

// Uplink is the made-up eth0 of a Docker bridge: a routed server warns, as on most hosts
func (s simulated) Uplink(to netip.Addr) (Uplink, bool) {
	uplink := Uplink{Interface: "eth0", Driver: DriverVeth}
	if to.Unmap().Is4() {
		uplink.Address = "172.18.0.2"
	}
	return uplink, true
}

func (s simulated) Counters() (Counters, error) {
	return s.CountersAt(time.Now()), nil
}

func (s simulated) Details() Details {
	synced, forwarding := true, true
	return Details{
		Simulated: true, Hostname: "authway-dev", Kernel: "6.12.0", OS: "made-up values on " + runtime.GOOS,
		Uptime: time.Since(s.booted).Round(time.Second), Load: [3]float64{0.42, 0.37, 0.35}, SwapTotal: 1 << 30, SwapFree: 1 << 30,
		ClockSynced: &synced, IPForward: &forwarding, IPv6On: &forwarding, IPv6Forward: &forwarding, IPv6Route: &forwarding,
		Conntrack: 184, ConntrackMax: 65536, OpenFiles: 23, MaxFiles: 1 << 20,
		Interfaces: []InterfaceInfo{
			{Name: "eth0", Kind: "ethernet", Up: true, MTU: 1500, Addresses: []string{"172.18.0.2/16"}},
			{Name: "wg0", Kind: "wireguard", Up: true, MTU: 1420, Addresses: []string{"10.8.0.1/24"}},
			{Name: "wg1", Kind: "wireguard", Up: true, MTU: 1420, Addresses: []string{"10.9.0.1/24"}},
			{Name: "wg2", Kind: "wireguard", Up: true, MTU: 1420, Addresses: []string{"10.10.0.1/24"}},
			{Name: "lo", Kind: "loopback", Up: true, MTU: 65536, Addresses: []string{"127.0.0.1/8", "::1/128"}},
		},
		Disks: []Disk{{
			Name: "data", Path: "/data", Total: 49 << 30, Used: 9<<30 + 450<<20, Available: 37<<30 + 200<<20,
			Inodes: 3276800, InodesFree: 3105112,
		}},
		DatabaseSize: 122880, DatabaseLog: 32992,
	}
}
