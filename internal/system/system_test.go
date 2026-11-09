package system

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// read in the container on the Debian test server
const procStat = `cpu  66178 42 18591 33001281 48178 0 12315 0 0 0
cpu0 16455 6 4592 8249861 11830 0 8205 0 0 0
cpu1 16575 10 4713 8252667 9382 0 2978 0 0 0
cpu2 16575 10 4713 8252667 9382 0 2978 0 0 0
cpu3 16575 10 4713 8252667 9382 0 2978 0 0 0
intr 1234 5 6
`

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0:   42737     231    1    2    0     0          0         0   328700     187    3    4    0     0       0          0
   wg0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`

func TestParse(t *testing.T) {
	total, busy, iowait, processors, err := parseStat(procStat)
	// user nice system idle iowait irq softirq steal
	wantTotal := uint64(66178 + 42 + 18591 + 33001281 + 48178 + 0 + 12315 + 0)
	if err != nil || total != wantTotal || busy != wantTotal-33001281-48178 || iowait != 48178 || processors != 4 {
		t.Errorf("stat: %d %d %d %d %v", total, busy, iowait, processors, err)
	}
	if _, _, _, _, err := parseStat("intr 1 2"); err == nil {
		t.Error("stat without the processors")
	}

	memory := parseMeminfo("MemTotal:        4007648 kB\nMemFree:         1021252 kB\nMemAvailable:    2553260 kB\nHugePages_Total:       0\n")
	if memory["MemTotal"] != 4007648*1024 || memory["MemAvailable"] != 2553260*1024 || memory["HugePages_Total"] != 0 {
		t.Errorf("meminfo: %v", memory)
	}
	// before Linux 3.14
	if old := parseMeminfo("MemFree: 100 kB\nBuffers: 20 kB\nCached: 30 kB\n"); old["MemAvailable"] != 150*1024 {
		t.Errorf("meminfo without MemAvailable: %v", old)
	}
	if rss := parseMeminfo("Name:\tauthway-server\nVmRSS:\t   21540 kB\n")["VmRSS"]; rss != 21540*1024 {
		t.Errorf("VmRSS: %d", rss)
	}

	interfaces := parseNetDev(netDev)
	eth0 := interfaces["eth0"]
	if len(interfaces) != 3 || eth0.ReceivedBytes != 42737 || eth0.ReceivedPackets != 231 || eth0.SentBytes != 328700 ||
		eth0.SentPackets != 187 || eth0.Errors != 4 || eth0.Drops != 6 {
		t.Errorf("net/dev: %+v", interfaces)
	}

	if cpu := parseKeyValues("usage_usec 3633906\nuser_usec 2574882\nnr_periods\n"); cpu["usage_usec"] != 3633906 || len(cpu) != 2 {
		t.Errorf("cpu.stat: %v", cpu)
	}
	if load := parseLoadavg("0.52 0.31 0.05 1/855 34\n"); load != [3]float64{0.52, 0.31, 0.05} {
		t.Errorf("loadavg: %v", load)
	}
	if name := parseOSRelease("NAME=\"Alpine Linux\"\nID=alpine\nPRETTY_NAME=\"Alpine Linux v3.22\"\n"); name != "Alpine Linux v3.22" {
		t.Errorf("os-release: %q", name)
	}
	// a name with spaces and parentheses
	if ticks, ok := parseSelfStat("1234 (a (b) c) S 1 1234 1234 0 -1 4194560 2000 0 0 0 150 50 0 0 20 0 9 0 100"); !ok || ticks != 200 {
		t.Errorf("stat of the process: %d %v", ticks, ok)
	}
	if path, ok := parseCgroup("0::/system.slice/docker-abc.scope\n"); !ok || path != "/system.slice/docker-abc.scope" {
		t.Errorf("cgroup: %q %v", path, ok)
	}
	if _, ok := parseCgroup("12:memory:/docker/abc\n"); ok {
		t.Error("cgroup v1 has no 0:: line")
	}
	if parseLimit("max\n") != 0 || parseLimit("536870912\n") != 512<<20 {
		t.Error("memory.max")
	}
}

type fakeProbe struct {
	counters Counters
	details  Details
	err      error
}

// a new map at each reading, as the probes do
func (p *fakeProbe) Counters() (Counters, error) {
	c := p.counters
	c.Interfaces = map[string]InterfaceCounters{}
	for name, counters := range p.counters.Interfaces {
		c.Interfaces[name] = counters
	}
	return c, p.err
}

func (p *fakeProbe) Details() Details { return p.details }

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// advance moves the counters as a host with 4 processors busy at 25%, Authway Server using 2% of them, eth0
// receiving 1000 bytes a second and sending 500
func (p *fakeProbe) advance(seconds uint64) {
	c := &p.counters
	c.CPUTotal += 400 * seconds
	c.CPUBusy += 100 * seconds
	c.CPUIOWait += 4 * seconds
	c.OwnCPU += time.Duration(seconds) * 80 * time.Millisecond
	eth0 := c.Interfaces["eth0"]
	eth0.ReceivedBytes += 1000 * seconds
	eth0.SentBytes += 500 * seconds
	c.Interfaces["eth0"] = eth0
	lo := c.Interfaces["lo"]
	lo.ReceivedBytes += 7 * seconds
	c.Interfaces["lo"] = lo
}

func newFake() (*Monitor, *fakeProbe, *clock) {
	probe := &fakeProbe{counters: Counters{
		Processors: 4, MemoryTotal: 4 << 30, MemoryAvailable: 3 << 30, OwnMemory: 30 << 20,
		Interfaces: map[string]InterfaceCounters{"eth0": {}, "lo": {}},
	}}
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	return New(Options{Probe: probe, Now: c.Now, Version: "test"}), probe, c
}

func TestRatesAndHistory(t *testing.T) {
	m, probe, c := newFake()
	m.Sample()
	if h := m.History(3600, 0); len(h.Points) != 0 || h.Step != 5 || h.MemoryTotal != 4<<30 {
		t.Fatalf("one reading: %+v", h)
	}
	for range 13 {
		c.now = c.now.Add(SampleInterval)
		probe.advance(5)
		m.Sample()
	}
	h := m.History(3600, 0)
	if len(h.Points) != 13 {
		t.Fatalf("%d points", len(h.Points))
	}
	p := h.Points[12]
	if p.At != c.now.Unix() || p.CPU != 25 || p.OwnCPU != 2 || p.Memory != 1<<30 || p.OwnMemory != 30<<20 ||
		p.Network["eth0"] != [2]int64{1000, 500} {
		t.Errorf("point: %+v", p)
	}
	if _, ok := p.Network["lo"]; ok {
		t.Error("lo is in the history")
	}
	// a minute passed: one point of a minute, with the same averages
	day := m.History(86400, 0)
	if day.Step != 60 || len(day.Points) != 1 || day.Points[0].CPU != 25 || day.Points[0].Network["eth0"] != [2]int64{1000, 500} {
		t.Errorf("minutes: %+v", day)
	}
	// the points after since only, and of the range
	if after := m.History(3600, h.Points[10].At); len(after.Points) != 2 {
		t.Errorf("since: %d points", len(after.Points))
	}
	if last := m.History(10, 0); len(last.Points) != 2 {
		t.Errorf("the latest 10 seconds: %d points", len(last.Points))
	}

	// an interface made again starts from 0: no negative rate, no spike
	c.now = c.now.Add(SampleInterval)
	probe.counters.Interfaces["eth0"] = InterfaceCounters{ReceivedBytes: 2500, SentBytes: 0}
	m.Sample()
	if p := m.History(5, 0).Points[0]; p.Network["eth0"] != [2]int64{500, 0} {
		t.Errorf("counters started again: %+v", p)
	}

	// nothing moved in these 5 seconds
	if s := m.Snapshot(State{}); s.Host.CPU != 0 || s.Own.CPU != 0 || s.Host.IOWait != 0 {
		t.Errorf("idle: %+v %+v", s.Host, s.Own)
	}
	c.now = c.now.Add(SampleInterval)
	probe.advance(5)
	m.Sample()
	s := m.Snapshot(State{})
	if s.Host.CPU != 25 || s.Host.IOWait != 1 || s.Own.CPU != 2 || s.Own.Version != "test" || s.Host.Processors != 4 ||
		s.Host.MemoryAvailable != 3<<30 || s.Own.Memory != 30<<20 || s.At != c.now.Unix() {
		t.Errorf("snapshot: %+v %+v", s.Host, s.Own)
	}

	// a reading that fails adds nothing
	probe.err = io.ErrUnexpectedEOF
	c.now = c.now.Add(SampleInterval)
	m.Sample()
	if n := len(m.History(3600, 0).Points); n != 15 {
		t.Errorf("%d points after a failed reading", n)
	}
}

func TestRingsKeepTheirSize(t *testing.T) {
	m, probe, c := newFake()
	for range RecentPoints + 50 {
		c.now = c.now.Add(SampleInterval)
		probe.advance(5)
		m.Sample()
	}
	if n := len(m.recent.points); n != RecentPoints {
		t.Errorf("%d recent points", n)
	}
	if h := m.History(3600, 0); len(h.Points) != RecentPoints-1 && len(h.Points) != RecentPoints {
		t.Errorf("an hour: %d points", len(h.Points))
	}
	if first := m.recent.points[0].At; first != c.now.Add(-(RecentPoints-1)*SampleInterval).Unix() {
		t.Errorf("the oldest point is at %d", first)
	}
}

func TestSimulatedFillsTheHistory(t *testing.T) {
	m := New(Options{Probe: Simulated()})
	if len(m.recent.points) != RecentPoints || len(m.day.points) != DayPoints {
		t.Fatalf("%d and %d points", len(m.recent.points), len(m.day.points))
	}
	for _, point := range append(append([]Point{}, m.recent.points...), m.day.points...) {
		if point.CPU <= 0 || point.CPU > 100 || point.OwnCPU <= 0 || point.Network["eth0"][0] <= 0 || point.Network["wg2"][1] <= 0 {
			t.Fatalf("point: %+v", point)
		}
	}
	m.Sample()
	s := m.Snapshot(State{Servers: []ServerInterface{{"Office", "wg0"}}})
	if !s.Simulated || len(s.Interfaces) != 5 || s.Interfaces[0].ReceivedBytes == 0 {
		t.Errorf("snapshot: %+v", s)
	}
}

func checkOf(t *testing.T, list []Check, id string) Check {
	t.Helper()
	for _, check := range list {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("no check %s in %+v", id, list)
	return Check{}
}

func TestChecks(t *testing.T) {
	m, probe, c := newFake()
	m.Sample()
	yes, no := true, false
	probe.details = Details{
		ClockSynced: &yes, IPForward: &yes, Conntrack: 10, ConntrackMax: 1000, Load: [3]float64{1, 1, 1},
		Interfaces: []InterfaceInfo{{Name: "eth0", Up: true}, {Name: "wg0", Up: true}, {Name: "wg1", Up: true}},
		Disks:      []Disk{{Name: "data", Total: 100 << 30, Used: 40 << 30, Available: 55 << 30, Inodes: 1000, InodesFree: 900}},
	}
	good := State{StatsAt: c.now.Add(-3 * time.Second), Servers: []ServerInterface{{"Office", "wg0"}, {"Lab", "wg1"}}}
	for _, check := range m.Snapshot(good).Checks {
		if check.Status != CheckOK {
			t.Errorf("not ok: %+v", check)
		}
	}
	if check := checkOf(t, m.Snapshot(good).Checks, "interfaces"); check.Title != "The interfaces of the 2 enabled servers are up" ||
		check.Detail != "wg0 (Office), wg1 (Lab)." {
		t.Errorf("interfaces: %+v", check)
	}

	// everything wrong
	probe.details = Details{
		ClockSynced: &no, IPForward: &no, Conntrack: 950, ConntrackMax: 1000, Load: [3]float64{9, 9, 9},
		Interfaces: []InterfaceInfo{{Name: "eth0", Up: true}, {Name: "wg0", Up: false}},
		Disks: []Disk{
			{Name: "data", Total: 100 << 30, Used: 96 << 30, Available: 3 << 30, Inodes: 1000, InodesFree: 900},
			{Name: "system", Total: 100 << 30, Used: 50 << 30, Available: 50 << 30, Inodes: 1000, InodesFree: 10},
		},
		OwnMemoryLimit: 32 << 20,
	}
	bad := State{ApplyError: "nft: syntax error", StatsError: "netlink: permission denied", Servers: good.Servers}
	m.opts.Log.add(LogEntry{At: c.now.Unix(), Level: "error", Message: "can't apply the configuration", Attrs: "error=x"}, true)
	m.opts.Log.add(LogEntry{At: c.now.Add(-2 * time.Hour).Unix(), Level: "error", Message: "old"}, true)
	list := m.Snapshot(bad).Checks
	for id, want := range map[string]string{
		"configuration": CheckError, "tunnels": CheckError, "interfaces": CheckError, "forwarding": CheckError,
		"clock": CheckWarning, "disk": CheckError, "memory": CheckWarning, "processors": CheckWarning,
		"conntrack": CheckError, "log": CheckWarning,
	} {
		if check := checkOf(t, list, id); check.Status != want {
			t.Errorf("%s: %+v, want %s", id, check, want)
		}
	}
	if check := checkOf(t, list, "interfaces"); check.Detail != "Missing: wg1 (Lab); down: wg0 (Office). The peers of that server can't connect." {
		t.Errorf("interfaces: %q", check.Detail)
	}
	if check := checkOf(t, list, "disk"); !strings.Contains(check.Detail, "The data folder: 3.0 GB available of 100 GB") ||
		!strings.Contains(check.Detail, "only 10 files") {
		t.Errorf("disk: %q", check.Detail)
	}
	if check := checkOf(t, list, "log"); check.Title != "1 error in the log in the last hour" ||
		check.Detail != "The latest: can't apply the configuration (error=x)" {
		t.Errorf("log: %+v", check)
	}

	// unknown when it can't be read, and old readings of the tunnels
	probe.details = Details{}
	list = m.Snapshot(State{StatsAt: c.now.Add(-time.Minute)}).Checks
	for id, want := range map[string]string{"forwarding": CheckUnknown, "clock": CheckUnknown, "disk": CheckUnknown, "tunnels": CheckWarning} {
		if check := checkOf(t, list, id); check.Status != want {
			t.Errorf("%s: %+v, want %s", id, check, want)
		}
	}
	for _, check := range list {
		if check.ID == "conntrack" {
			t.Errorf("conntrack without a maximum: %+v", check)
		}
	}
}

func TestLogRing(t *testing.T) {
	ring := NewLogRing()
	log := slog.New(ring.Handler(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})))
	log.Debug("not kept: below the level")
	log.Info("logged in", "user", "alice", "from", "203.0.113.7:51820")
	server := log.With("server", "Office").WithGroup("peer")
	server.Warn("login failed", "name", "laptop", "detail", "wrong password")
	log.Error("can't apply", "error", `nft: "x" = 1`, slog.Group("table", "name", "authway"))

	all := ring.Entries(true)
	if len(all) != 3 || all[0].Message != "can't apply" || all[2].Message != "logged in" {
		t.Fatalf("all: %+v", all)
	}
	if all[2].Level != "info" || all[2].Attrs != "user=alice from=203.0.113.7:51820" {
		t.Errorf("info: %+v", all[2])
	}
	if all[1].Level != "warn" || all[1].Attrs != `server=Office peer.name=laptop peer.detail="wrong password"` {
		t.Errorf("warning: %+v", all[1])
	}
	if all[0].Attrs != `error="nft: \"x\" = 1" table.name=authway` {
		t.Errorf("error: %q", all[0].Attrs)
	}
	if problems := ring.Entries(false); len(problems) != 2 || problems[0].Level != "error" || problems[1].Level != "warn" {
		t.Errorf("problems: %+v", problems)
	}
	if count, latest := ring.Errors(time.Now().Add(-time.Minute)); count != 1 || latest.Message != "can't apply" {
		t.Errorf("errors: %d %+v", count, latest)
	}

	// the oldest lines go, the problems stay longer
	for range LogLines {
		log.Info("session follows its peer")
	}
	if all := ring.Entries(true); len(all) != LogLines || all[LogLines-1].Message != "session follows its peer" {
		t.Errorf("%d lines, the oldest %q", len(all), all[len(all)-1].Message)
	}
	if problems := ring.Entries(false); len(problems) != 2 {
		t.Errorf("%d problems", len(problems))
	}
}

// The certificate of the web UI: valid, near its end, expired, a new pair that doesn't load; none without HTTPS.
func TestCertificateCheck(t *testing.T) {
	m, _, c := newFake()
	var certificate *Certificate
	m.opts.Certificate = func() *Certificate { return certificate }
	for _, check := range m.Snapshot(State{}).Checks {
		if check.ID == "certificate" {
			t.Errorf("without HTTPS: %+v", check)
		}
	}
	for _, test := range []struct {
		name   string
		cert   Certificate
		status string
		has    string
	}{
		{"self-signed", Certificate{NotAfter: c.now.AddDate(1, 0, 0), SelfSigned: true}, CheckOK, "Self-signed, until"},
		{"own", Certificate{NotAfter: c.now.AddDate(0, 3, 0), Names: []string{"vpn.example.com"}}, CheckOK, "for vpn.example.com."},
		{"near its end", Certificate{NotAfter: c.now.Add(20*24*time.Hour + time.Hour), Names: []string{"vpn.example.com"}}, CheckWarning, "Replace tls/cert.pem"},
		{"self-signed not renewed", Certificate{NotAfter: c.now.Add(-time.Hour), SelfSigned: true}, CheckError, "couldn't make a new one"},
		{"broken pair", Certificate{NotAfter: c.now.AddDate(1, 0, 0), Error: "tls: private key does not match public key"}, CheckError, "The one before is still in use"},
	} {
		certificate = &test.cert
		snapshot := m.Snapshot(State{})
		check := checkOf(t, snapshot.Checks, "certificate")
		if check.Status != test.status || !strings.Contains(check.Detail, test.has) || snapshot.Certificate.NotAfter != test.cert.NotAfter.Unix() {
			t.Errorf("%s: %+v", test.name, check)
		}
	}
	certificate = &Certificate{NotAfter: c.now.Add(20*24*time.Hour + time.Hour)}
	if check := checkOf(t, m.Snapshot(State{}).Checks, "certificate"); check.Title != "The certificate of the web UI expires in 20 days" {
		t.Errorf("days: %q", check.Title)
	}
}

func TestIPv6Check(t *testing.T) {
	m, probe, c := newFake()
	m.Sample()
	yes, no := true, false
	base := Details{ClockSynced: &yes, IPForward: &yes, Interfaces: []InterfaceInfo{{Name: "wg0", Up: true}}}
	servers := []ServerInterface{{"Office", "wg0"}}
	// no server with an IPv6 network: no check, whatever the container does
	probe.details = base
	for _, check := range m.Snapshot(State{StatsAt: c.now, Servers: servers}).Checks {
		if check.ID == "ipv6" {
			t.Fatalf("an IPv6 check without IPv6: %+v", check)
		}
	}
	for _, test := range []struct {
		on, forward, route *bool
		status, title      string
	}{
		{&yes, &yes, &yes, CheckOK, "IPv6 is on"},
		{&no, &yes, &yes, CheckError, "IPv6 is off in the container"},
		{&yes, &no, &yes, CheckError, "IPv6 forwarding is off"},
		{&yes, &yes, &no, CheckWarning, "No IPv6 route out of the container"},
		{&yes, nil, nil, CheckUnknown, "Can't read the state of IPv6"},
	} {
		details := base
		details.IPv6On, details.IPv6Forward, details.IPv6Route = test.on, test.forward, test.route
		probe.details = details
		check := checkOf(t, m.Snapshot(State{StatsAt: c.now, Servers: servers, IPv6Servers: []string{"Office"}}).Checks, "ipv6")
		if check.Status != test.status || check.Title != test.title {
			t.Errorf("%+v: %+v", test, check)
		}
	}
	probe.details = base
	probe.details.IPv6On, probe.details.IPv6Forward, probe.details.IPv6Route = &yes, &yes, &yes
	check := checkOf(t, m.Snapshot(State{StatsAt: c.now, IPv6Servers: []string{"Office", "Lab"}}).Checks, "ipv6")
	if check.Detail != "The servers Office, Lab have an IPv6 network: forwarding is on, with a route out of the container." {
		t.Errorf("two servers: %q", check.Detail)
	}

	// the loopback has a default route that rejects everything: not a way out
	routes := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"fdae0000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
	if parseIPv6DefaultRoute(routes) {
		t.Error("the reject route of the loopback is a route out")
	}
	routes += "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fdaec7729fb900000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
	if !parseIPv6DefaultRoute(routes) {
		t.Error("the default route of eth0 isn't seen")
	}
}

// a routed server works when the container has a MAC address of its own in the network: macvlan
func TestRoutingCheck(t *testing.T) {
	m, probe, c := newFake()
	m.Sample()
	yes := true
	probe.details = Details{ClockSynced: &yes, IPForward: &yes}
	for _, check := range m.Snapshot(State{StatsAt: c.now}).Checks {
		if check.ID == "routing" {
			t.Fatalf("a routing check without a routed server: %+v", check)
		}
	}
	route := func(driver, address string) Route {
		return Route{Tunnel: "10.8.0.0/24", Network: "192.168.1.0/24", Uplink: Uplink{Interface: "eth0", Driver: driver, Address: address}}
	}
	// the Docker bridge, with the helper of the Docker host in a state
	bridged := func(host HostRoute) Route {
		r := route(DriverVeth, "172.18.0.2")
		r.Host = host
		return r
	}
	for _, test := range []struct {
		routes        []Route
		status, title string
		detail        string
	}{
		{[]Route{route(DriverMacvlan, "192.168.1.50"), {Tunnel: "fd00:1::/64", Network: "2001:db8::/64",
			Uplink: Uplink{Interface: "eth0", Driver: DriverMacvlan, Address: "2001:db8::50"}}},
			CheckOK, "The routed servers reach their networks directly",
			"The router of the networks needs these routes: 10.8.0.0/24 via 192.168.1.50 (Office); fd00:1::/64 via 2001:db8::50 (Office)."},
		// another driver: the network of the host, say
		{[]Route{route("virtio_net", "")}, CheckOK, "The routed servers reach their networks directly",
			"The router of the networks needs these routes: 10.8.0.0/24 via the address of the container on eth0 (Office)."},
		{[]Route{bridged(HostRoute{State: HostOff})}, CheckWarning, "A routed server needs routes on the Docker host", ""},
		// a state never set counts as no helper
		{[]Route{route(DriverVeth, "172.18.0.2")}, CheckWarning, "A routed server needs routes on the Docker host", ""},
		{[]Route{bridged(HostRoute{State: HostStopped})}, CheckWarning, "The helper of the Docker host isn't running", ""},
		{[]Route{bridged(HostRoute{State: HostPending})}, CheckUnknown, "The Docker host is adding the routes",
			"The helper of compose.host-routes.yaml adds the routes of Office in a few seconds."},
		{[]Route{bridged(HostRoute{State: HostFailed, Error: "the Docker host already has a route to 10.8.0.0/24, through 192.168.1.1"})},
			CheckError, "The Docker host can't route a server",
			"Office, 10.8.0.0/24: the Docker host already has a route to 10.8.0.0/24, through 192.168.1.1."},
		{[]Route{bridged(HostRoute{State: HostRouted, Address: "192.168.1.10"})}, CheckOK,
			"The routed servers reach their networks through the Docker host",
			"The router of the networks needs these routes: 10.8.0.0/24 via 192.168.1.10 (Office). The Docker host sends them on to the container."},
		// routed, but the connections from the networks stay blocked: said
		{[]Route{bridged(HostRoute{State: HostRouted, Address: "192.168.1.10", Error: "the connections from the networks stay blocked: no chain"})},
			CheckError, "The Docker host can't route a server", "Office, 10.8.0.0/24: the connections from the networks stay blocked: no chain."},
		// the address of the Docker host changed: the router has the address of before
		{[]Route{bridged(HostRoute{State: HostRouted, Address: "192.168.1.20", Previous: "192.168.1.10"})}, CheckWarning,
			"The address of the Docker host changed",
			"The router of the networks still sends the tunnels to the address of before, so the networks don't answer the peers. Change its routes: 10.8.0.0/24 via 192.168.1.20 instead of via 192.168.1.10 (Office). Then say it's done in the warning at the top of the page. Give the Docker host a fixed address, a DHCP reservation for example, so it doesn't change again."},
		{[]Route{route(DriverVeth, "172.18.0.2"), route(DriverIPvlan, "192.168.1.50")}, CheckError, "A routed server can't work on ipvlan", ""},
		{[]Route{{Tunnel: "10.8.0.0/24", Network: "192.168.1.0/24"}}, CheckUnknown, "Can't read the routes of the container",
			"A routed server needs a route to its networks, and the container has none to 192.168.1.0/24 (Office)."},
	} {
		state := State{StatsAt: c.now, Routed: []RoutedServer{{Name: "Office", Routes: test.routes}}}
		check := checkOf(t, m.Snapshot(state).Checks, "routing")
		if check.Status != test.status || check.Title != test.title || test.detail != "" && check.Detail != test.detail {
			t.Errorf("%+v: %+v", test.routes, check)
		}
	}
	state := State{StatsAt: c.now, Routed: []RoutedServer{
		{Name: "Office", Routes: []Route{route(DriverVeth, "")}}, {Name: "Lab", Routes: []Route{route(DriverVeth, "")}}}}
	if check := checkOf(t, m.Snapshot(state).Checks, "routing"); !strings.HasPrefix(check.Detail, "The servers Office, Lab are routed, but") {
		t.Errorf("two servers: %q", check.Detail)
	}
}

func TestParseRoutes(t *testing.T) {
	// a Docker network: the default route and the network of the container, 172.18.0.0/16, and a macvlan one
	routes4 := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"eth1\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"wg0\t000008AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		// a route that's down is no way
		"eth2\t0101A8C0\t00000000\t0000\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n"
	for to, want := range map[string]string{
		"192.168.1.0": "eth1", "192.168.1.1": "eth1", "172.18.5.4": "eth0", "8.8.8.8": "eth0", "172.8.0.1": "wg0",
	} {
		if got := parseRoute4(routes4, netip.MustParseAddr(to)); got != want {
			t.Errorf("%s: %q, want %q", to, got, want)
		}
	}
	if got := parseRoute4("Iface\tDestination\n", netip.MustParseAddr("8.8.8.8")); got != "" {
		t.Errorf("no route: %q", got)
	}
	// the longest prefix, then the lowest metric
	two := "eth0\t0001A8C0\t00000000\t0001\t0\t0\t200\t00FFFFFF\t0\t0\t0\n" +
		"eth1\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if got := parseRoute4(two, netip.MustParseAddr("192.168.1.9")); got != "eth1" {
		t.Errorf("metric: %q", got)
	}

	routes6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n" +
		"20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth1\n" +
		"fdae0000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n" +
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fdae0000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
	for to, want := range map[string]string{"2001:db8::": "eth1", "2001:db8::77": "eth1", "fdae::5": "eth0", "2606:4700::1": "eth0"} {
		if got := parseRoute6(routes6, netip.MustParseAddr(to)); got != want {
			t.Errorf("%s: %q, want %q", to, got, want)
		}
	}
	// only the reject route of the loopback: no way out
	if got := parseRoute6(strings.SplitN(routes6, "\n", 2)[0], netip.MustParseAddr("2606:4700::1")); got != "" {
		t.Errorf("the loopback: %q", got)
	}
}
