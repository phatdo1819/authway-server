// Package system is the System page of the web UI: the processors, the memory, the network interfaces and the disks
// of the host, what Authway Server uses of them, the checks of what can go wrong, and the latest lines of the log.
//
// A probe reads the system: /proc and /sys on Linux, made-up values elsewhere, to try the web UI. The monitor reads
// the counters every SampleInterval and keeps the rates in memory: an hour of them, and a day of one-minute averages.
// The history starts again with Authway Server.
package system

import (
	"context"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// the time between two readings of the counters
	SampleInterval = 5 * time.Second
	// the history: an hour of readings, and a day of one-minute averages
	RecentPoints = 720
	DayPoints    = 1440
	// the interfaces kept in the history, besides lo: more come only on a host full of containers
	MaxInterfaces = 16
)

// Counters are what the probe counts since the start of the host or of Authway Server.
type Counters struct {
	// the ticks of all the processors, the busy ones, and the ones waiting for a disk
	CPUTotal, CPUBusy, CPUIOWait uint64
	Processors                   int
	// the processor time of Authway Server: its container, else its process
	OwnCPU          time.Duration
	MemoryTotal     uint64
	MemoryAvailable uint64
	// the memory of Authway Server, without the files the kernel caches for it
	OwnMemory  uint64
	Interfaces map[string]InterfaceCounters
}

type InterfaceCounters struct {
	ReceivedBytes, SentBytes, ReceivedPackets, SentPackets uint64
	// both ways
	Errors, Drops uint64
}

// Details are read when the page asks: what needs no history.
type Details struct {
	Simulated bool
	Hostname  string
	Kernel    string
	OS        string
	Container bool
	Uptime    time.Duration
	Load      [3]float64
	SwapTotal uint64
	SwapFree  uint64
	// nil when it can't be read
	ClockSynced *bool
	IPForward   *bool
	// IPv6: the new interfaces get IPv6 addresses, the container forwards it, and has a default route for it
	IPv6On      *bool
	IPv6Forward *bool
	IPv6Route   *bool
	// ConntrackMax 0: unknown
	Conntrack, ConntrackMax int
	OwnMemoryLimit          uint64 // 0: none
	OpenFiles, MaxFiles     int
	Interfaces              []InterfaceInfo
	Disks                   []Disk
	DatabaseSize            int64
	DatabaseLog             int64 // the -wal file
}

type InterfaceInfo struct {
	Name      string
	Kind      string // ethernet, wireguard, loopback, other
	Up        bool
	MTU       int
	Addresses []string
}

// Probe reads the system.
type Probe interface {
	Counters() (Counters, error)
	Details() Details
}

// pastProbe gives the counters of any moment: the made-up values fill the history at once.
type pastProbe interface {
	CountersAt(time.Time) Counters
}

// Certificate is the certificate of the web UI.
type Certificate struct {
	NotAfter   time.Time
	SelfSigned bool
	Names      []string
	// why the files couldn't be loaded the latest time: the certificate before is still used
	Error string
}

// RenewBefore: a self-signed certificate is made again this long before it expires, and a warning comes for the
// others
const RenewBefore = 30 * 24 * time.Hour

type Options struct {
	// the folder of the database: its disk is the one that matters
	DataDir string
	// the certificate of the web UI now; nil, or nil from it: no HTTPS, behind a reverse proxy
	Certificate func() *Certificate
	// nil: the probe of this system, /proc on Linux
	Probe   Probe
	Version string
	Log     *LogRing
	Now     func() time.Time
}

// Point is one step of the history: the averages since the step before.
type Point struct {
	At     int64   `json:"at"`
	CPU    float64 `json:"cpu"`     // percent of all the processors, busy
	OwnCPU float64 `json:"own_cpu"` // percent of all the processors, used by Authway Server
	// bytes: used (the total less the available), and by Authway Server
	Memory    uint64 `json:"memory"`
	OwnMemory uint64 `json:"own_memory"`
	// bytes per second received and sent, by interface
	Network map[string][2]int64 `json:"network"`
}

type History struct {
	// seconds between two points
	Step        int     `json:"step"`
	MemoryTotal uint64  `json:"memory_total"`
	Points      []Point `json:"points"`
}

type Snapshot struct {
	At         int64       `json:"at"`
	Simulated  bool        `json:"simulated"`
	Host       Host        `json:"host"`
	Own        Own         `json:"authway"`
	Interfaces []Interface `json:"interfaces"`
	Disks      []Disk      `json:"disks"`
	Database   Database    `json:"database"`
	IPForward  *bool       `json:"ip_forward"`
	// nil when they can't be read
	IPv6On      *bool     `json:"ipv6_on"`
	IPv6Forward *bool     `json:"ipv6_forward"`
	IPv6Route   *bool     `json:"ipv6_route"`
	Conntrack   Conntrack `json:"conntrack"`
	// nil without HTTPS
	Certificate *CertificateView `json:"certificate"`
	Checks      []Check          `json:"checks"`
}

type CertificateView struct {
	NotAfter   int64    `json:"not_after"`
	SelfSigned bool     `json:"self_signed"`
	Names      []string `json:"names"`
	Error      string   `json:"error"`
}

type Host struct {
	Hostname   string     `json:"hostname"`
	Kernel     string     `json:"kernel"`
	OS         string     `json:"os"`
	Timezone   string     `json:"timezone"`
	Container  bool       `json:"container"`
	Processors int        `json:"processors"`
	Uptime     int64      `json:"uptime"`
	Load       [3]float64 `json:"load"`
	// percent, over the latest SampleInterval
	CPU             float64 `json:"cpu"`
	IOWait          float64 `json:"iowait"`
	MemoryTotal     uint64  `json:"memory_total"`
	MemoryAvailable uint64  `json:"memory_available"`
	SwapTotal       uint64  `json:"swap_total"`
	SwapFree        uint64  `json:"swap_free"`
	ClockSynced     *bool   `json:"clock_synced"`
}

type Own struct {
	Version     string  `json:"version"`
	GoVersion   string  `json:"go_version"`
	Platform    string  `json:"platform"`
	Started     int64   `json:"started"`
	CPU         float64 `json:"cpu"`
	Memory      uint64  `json:"memory"`
	MemoryLimit uint64  `json:"memory_limit"`
	Heap        uint64  `json:"heap"`
	Goroutines  int     `json:"goroutines"`
	OpenFiles   int     `json:"open_files"`
	MaxFiles    int     `json:"max_files"`
}

type Interface struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Up        bool     `json:"up"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
	// bytes per second, over the latest SampleInterval
	Received        int64  `json:"received"`
	Sent            int64  `json:"sent"`
	ReceivedBytes   uint64 `json:"received_bytes"`
	SentBytes       uint64 `json:"sent_bytes"`
	ReceivedPackets uint64 `json:"received_packets"`
	SentPackets     uint64 `json:"sent_packets"`
	Errors          uint64 `json:"errors"`
	Drops           uint64 `json:"drops"`
}

type Disk struct {
	// data: the folder of the database; system: the root of the container, when it's on another disk
	Name       string `json:"name"`
	Path       string `json:"path"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	Available  uint64 `json:"available"`
	Inodes     uint64 `json:"inodes"`
	InodesFree uint64 `json:"inodes_free"`
}

type Database struct {
	Size int64 `json:"size"`
	Log  int64 `json:"log"`
}

type Conntrack struct {
	Count int `json:"count"`
	Max   int `json:"max"` // 0: unknown
}

type sample struct {
	at       time.Time
	counters Counters
}

// Monitor reads the counters every SampleInterval and keeps their history.
type Monitor struct {
	opts    Options
	probe   Probe
	started time.Time

	mu      sync.Mutex
	last    *sample
	minute  *sample
	latest  Point
	iowait  float64
	recent  ring
	day     ring
	readErr string
}

// New starts a monitor; Run reads the counters.
func New(opts Options) *Monitor {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Probe == nil {
		opts.Probe = systemProbe(opts.DataDir)
	}
	if opts.Log == nil {
		opts.Log = NewLogRing()
	}
	m := &Monitor{opts: opts, probe: opts.Probe, started: opts.Now(), recent: ring{max: RecentPoints}, day: ring{max: DayPoints}}
	if past, ok := opts.Probe.(pastProbe); ok {
		m.fill(past)
	}
	return m
}

// fill makes a history up, with a probe that knows the past
func (m *Monitor) fill(past pastProbe) {
	now := m.started
	for at := now.Add(-DayPoints * time.Minute); at.Before(now); at = at.Add(time.Minute) {
		m.day.push(rates(sample{at.Add(-time.Minute), past.CountersAt(at.Add(-time.Minute))}, sample{at, past.CountersAt(at)}))
	}
	for at := now.Add(-RecentPoints * SampleInterval); at.Before(now); at = at.Add(SampleInterval) {
		m.recent.push(rates(sample{at.Add(-SampleInterval), past.CountersAt(at.Add(-SampleInterval))}, sample{at, past.CountersAt(at)}))
	}
}

// Log is where the log keeps its latest lines.
func (m *Monitor) Log() *LogRing {
	return m.opts.Log
}

// Run reads the counters until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(SampleInterval)
	defer ticker.Stop()
	for {
		m.Sample()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sample reads the counters once, and adds a point to the history from the reading before.
func (m *Monitor) Sample() {
	counters, err := m.probe.Counters()
	now := m.opts.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.readErr = err.Error()
		return
	}
	m.readErr = ""
	current := sample{now, counters}
	if m.last != nil && now.After(m.last.at) {
		m.latest = rates(*m.last, current)
		m.recent.push(m.latest)
		m.iowait = 0
		if total := delta(m.last.counters.CPUTotal, counters.CPUTotal); total > 0 {
			m.iowait = round1(float64(delta(m.last.counters.CPUIOWait, counters.CPUIOWait)) / float64(total) * 100)
		}
	}
	m.last = &current
	if m.minute == nil {
		m.minute = &current
	} else if now.Sub(m.minute.at) >= time.Minute-time.Second {
		m.day.push(rates(*m.minute, current))
		m.minute = &current
	}
}

// rates are the averages between two readings
func rates(before, after sample) Point {
	seconds := after.at.Sub(before.at).Seconds()
	b, a := before.counters, after.counters
	point := Point{At: after.at.Unix(), Network: map[string][2]int64{}}
	if total := delta(b.CPUTotal, a.CPUTotal); total > 0 {
		point.CPU = round1(float64(delta(b.CPUBusy, a.CPUBusy)) / float64(total) * 100)
	}
	if seconds > 0 && a.Processors > 0 && a.OwnCPU >= b.OwnCPU {
		point.OwnCPU = round1((a.OwnCPU - b.OwnCPU).Seconds() / (seconds * float64(a.Processors)) * 100)
	}
	if a.MemoryTotal >= a.MemoryAvailable {
		point.Memory = a.MemoryTotal - a.MemoryAvailable
	}
	point.OwnMemory = a.OwnMemory
	if seconds <= 0 {
		return point
	}
	for _, name := range historyInterfaces(a.Interfaces) {
		now, then := a.Interfaces[name], b.Interfaces[name]
		point.Network[name] = [2]int64{
			int64(math.Round(float64(delta(then.ReceivedBytes, now.ReceivedBytes)) / seconds)),
			int64(math.Round(float64(delta(then.SentBytes, now.SentBytes)) / seconds)),
		}
	}
	return point
}

// delta is how much a counter grew: from 0 when it started again, with an interface made again
func delta(before, after uint64) uint64 {
	if after < before {
		return after
	}
	return after - before
}

func round1(value float64) float64 {
	return math.Round(value*10) / 10
}

// historyInterfaces are the interfaces kept in the history: all but lo, the Ethernet and WireGuard names first
func historyInterfaces(interfaces map[string]InterfaceCounters) []string {
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		if name != "lo" {
			names = append(names, name)
		}
	}
	rank := func(name string) int {
		switch {
		case strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "en"):
			return 0
		case strings.HasPrefix(name, "wg"):
			return 1
		}
		return 2
	}
	sort.Slice(names, func(i, j int) bool {
		if rank(names[i]) != rank(names[j]) {
			return rank(names[i]) < rank(names[j])
		}
		return names[i] < names[j]
	})
	if len(names) > MaxInterfaces {
		names = names[:MaxInterfaces]
	}
	return names
}

type ring struct {
	points []Point
	max    int
}

func (r *ring) push(point Point) {
	if len(r.points) == r.max {
		copy(r.points, r.points[1:])
		r.points = r.points[:r.max-1]
	}
	r.points = append(r.points, point)
}

// History gives the points of the latest seconds (an hour at most from the readings, a day from the minutes), only
// the ones after since.
func (m *Monitor) History(seconds int, since int64) History {
	m.mu.Lock()
	defer m.mu.Unlock()
	source, step := &m.recent, int(SampleInterval/time.Second)
	if seconds > RecentPoints*step {
		source, step = &m.day, 60
	}
	if seconds <= 0 || seconds > DayPoints*60 {
		seconds = DayPoints * 60
	}
	history := History{Step: step, Points: []Point{}}
	if m.last != nil {
		history.MemoryTotal = m.last.counters.MemoryTotal
	}
	from := max(m.opts.Now().Unix()-int64(seconds), since)
	for _, point := range source.points {
		if point.At > from {
			history.Points = append(history.Points, point)
		}
	}
	return history
}

// State is what Authway Server knows of itself, for the checks.
type State struct {
	ApplyError string
	// the latest reading of the tunnels
	StatsError string
	StatsAt    time.Time
	// the enabled servers
	Servers []ServerInterface
	// the names of the enabled servers with an IPv6 network
	IPv6Servers []string
	// the enabled servers routed to their networks
	Routed []RoutedServer
}

type ServerInterface struct {
	Name      string
	Interface string
}

// Snapshot is the System page now.
func (m *Monitor) Snapshot(state State) Snapshot {
	details := m.probe.Details()
	now := m.opts.Now()
	m.mu.Lock()
	var counters Counters
	if m.last != nil {
		counters = m.last.counters
	}
	latest, iowait := m.latest, m.iowait
	readErr := m.readErr
	m.mu.Unlock()

	// the TZ of the container, Asia/Bangkok, says more than +07
	timezone, offset := now.Zone()
	if name := os.Getenv("TZ"); name != "" {
		timezone = name
	}
	if offset != 0 {
		timezone += " (UTC" + now.Format("-07:00") + ")"
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	snapshot := Snapshot{
		At:        now.Unix(),
		Simulated: details.Simulated,
		Host: Host{
			Hostname: details.Hostname, Kernel: details.Kernel, OS: details.OS, Timezone: timezone,
			Container: details.Container, Processors: counters.Processors, Uptime: int64(details.Uptime / time.Second),
			Load: details.Load, CPU: latest.CPU, IOWait: iowait, MemoryTotal: counters.MemoryTotal, MemoryAvailable: counters.MemoryAvailable,
			SwapTotal: details.SwapTotal, SwapFree: details.SwapFree, ClockSynced: details.ClockSynced,
		},
		Own: Own{
			Version: m.opts.Version, GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
			Started: m.started.Unix(), CPU: latest.OwnCPU, Memory: counters.OwnMemory, MemoryLimit: details.OwnMemoryLimit,
			Heap: memory.HeapAlloc, Goroutines: runtime.NumGoroutine(), OpenFiles: details.OpenFiles, MaxFiles: details.MaxFiles,
		},
		Interfaces: []Interface{},
		Disks:      details.Disks,
		Database:   Database{Size: details.DatabaseSize, Log: details.DatabaseLog},
		IPForward:  details.IPForward, IPv6On: details.IPv6On, IPv6Forward: details.IPv6Forward, IPv6Route: details.IPv6Route,
		Conntrack: Conntrack{Count: details.Conntrack, Max: details.ConntrackMax},
	}
	if snapshot.Disks == nil {
		snapshot.Disks = []Disk{}
	}
	if m.opts.Certificate != nil {
		if certificate := m.opts.Certificate(); certificate != nil {
			snapshot.Certificate = &CertificateView{NotAfter: certificate.NotAfter.Unix(), SelfSigned: certificate.SelfSigned,
				Names: certificate.Names, Error: certificate.Error}
			if snapshot.Certificate.Names == nil {
				snapshot.Certificate.Names = []string{}
			}
		}
	}
	for _, info := range details.Interfaces {
		view := Interface{Name: info.Name, Kind: info.Kind, Up: info.Up, MTU: info.MTU, Addresses: info.Addresses}
		if view.Addresses == nil {
			view.Addresses = []string{}
		}
		if c, ok := counters.Interfaces[info.Name]; ok {
			view.ReceivedBytes, view.SentBytes = c.ReceivedBytes, c.SentBytes
			view.ReceivedPackets, view.SentPackets = c.ReceivedPackets, c.SentPackets
			view.Errors, view.Drops = c.Errors, c.Drops
		}
		if rate, ok := latest.Network[info.Name]; ok {
			view.Received, view.Sent = rate[0], rate[1]
		}
		snapshot.Interfaces = append(snapshot.Interfaces, view)
	}
	snapshot.Checks = checks(snapshot, state, readErr, m.opts.Log, now)
	return snapshot
}
