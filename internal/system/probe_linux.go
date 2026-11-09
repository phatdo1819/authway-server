//go:build linux

package system

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// the ticks of /proc/self/stat: USER_HZ is 100 on every Linux
	userHZ = 100
	// the kernel status of the clock: no time service keeps it right
	staUnsync = 0x0040
)

type linuxProbe struct {
	dataDir string
	// the folder of the cgroup of Authway Server, its container; "" without one, at the root of a host
	cgroup string
}

func systemProbe(dataDir string) Probe {
	probe := &linuxProbe{dataDir: dataDir}
	if path, ok := parseCgroup(readText("/proc/self/cgroup")); ok {
		dir := filepath.Join("/sys/fs/cgroup", path)
		if _, err := os.Stat(filepath.Join(dir, "memory.current")); err == nil {
			probe.cgroup = dir
		}
	}
	return probe
}

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func (p *linuxProbe) Counters() (Counters, error) {
	var c Counters
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return c, err
	}
	if c.CPUTotal, c.CPUBusy, c.CPUIOWait, c.Processors, err = parseStat(string(stat)); err != nil {
		return c, err
	}
	memory := parseMeminfo(readText("/proc/meminfo"))
	c.MemoryTotal, c.MemoryAvailable = memory["MemTotal"], memory["MemAvailable"]
	// the interfaces of the network of the container
	c.Interfaces = parseNetDev(readText("/proc/net/dev"))
	if p.cgroup != "" {
		c.OwnCPU = time.Duration(parseKeyValues(readText(filepath.Join(p.cgroup, "cpu.stat")))["usage_usec"]) * time.Microsecond
		// as docker stats: without the files cached and not used lately
		current := parseLimit(readText(filepath.Join(p.cgroup, "memory.current")))
		inactive := parseKeyValues(readText(filepath.Join(p.cgroup, "memory.stat")))["inactive_file"]
		if current > inactive {
			c.OwnMemory = current - inactive
		}
	} else {
		if ticks, ok := parseSelfStat(readText("/proc/self/stat")); ok {
			c.OwnCPU = time.Duration(ticks) * time.Second / userHZ
		}
		c.OwnMemory = parseMeminfo(readText("/proc/self/status"))["VmRSS"]
	}
	return c, nil
}

func (p *linuxProbe) Details() Details {
	var d Details
	d.Hostname, _ = os.Hostname()
	d.Kernel = strings.TrimSpace(readText("/proc/sys/kernel/osrelease"))
	d.OS = parseOSRelease(readText("/etc/os-release"))
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			d.Container = true
		}
	}
	if fields := strings.Fields(readText("/proc/uptime")); len(fields) > 0 {
		if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
			d.Uptime = time.Duration(seconds * float64(time.Second))
		}
	}
	d.Load = parseLoadavg(readText("/proc/loadavg"))
	memory := parseMeminfo(readText("/proc/meminfo"))
	d.SwapTotal, d.SwapFree = memory["SwapTotal"], memory["SwapFree"]
	// reading the status of the clock needs no right: only setting it does
	var timex syscall.Timex
	if _, err := syscall.Adjtimex(&timex); err == nil {
		synced := timex.Status&staUnsync == 0
		d.ClockSynced = &synced
	}
	if text := strings.TrimSpace(readText("/proc/sys/net/ipv4/ip_forward")); text != "" {
		on := text == "1"
		d.IPForward = &on
	}
	// the new interfaces take the defaults: the tunnels are created after the start
	if text := strings.TrimSpace(readText("/proc/sys/net/ipv6/conf/default/disable_ipv6")); text != "" {
		on := text == "0"
		d.IPv6On = &on
	} else if _, err := os.Stat("/proc/sys/net/ipv6"); err != nil {
		// a kernel without IPv6
		off := false
		d.IPv6On = &off
	}
	if text := strings.TrimSpace(readText("/proc/sys/net/ipv6/conf/all/forwarding")); text != "" {
		on := text == "1"
		d.IPv6Forward = &on
	}
	if routes := readText("/proc/net/ipv6_route"); routes != "" {
		route := parseIPv6DefaultRoute(routes)
		d.IPv6Route = &route
	}
	// of the network of the container
	d.Conntrack, _ = strconv.Atoi(strings.TrimSpace(readText("/proc/sys/net/netfilter/nf_conntrack_count")))
	d.ConntrackMax, _ = strconv.Atoi(strings.TrimSpace(readText("/proc/sys/net/netfilter/nf_conntrack_max")))
	if p.cgroup != "" {
		d.OwnMemoryLimit = parseLimit(readText(filepath.Join(p.cgroup, "memory.max")))
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		d.OpenFiles = len(entries)
	}
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) == nil {
		d.MaxFiles = int(min(limit.Cur, 1<<31-1))
	}
	d.Interfaces = interfaceInfos()
	d.Disks = disks(p.dataDir)
	d.DatabaseSize = fileSize(filepath.Join(p.dataDir, "authway.db"))
	d.DatabaseLog = fileSize(filepath.Join(p.dataDir, "authway.db-wal"))
	return d
}

// Uplink reads the route of the container towards an address, and the driver of its interface: what tells whether a
// routed server can work.
func (p *linuxProbe) Uplink(to netip.Addr) (Uplink, bool) {
	to = to.Unmap()
	var name string
	if to.Is4() {
		name = parseRoute4(readText("/proc/net/route"), to)
	} else {
		name = parseRoute6(readText("/proc/net/ipv6_route"), to)
	}
	if name == "" {
		return Uplink{}, false
	}
	uplink := Uplink{Interface: name, Driver: driverOf(name)}
	if iface, err := net.InterfaceByName(name); err == nil {
		if addresses, err := iface.Addrs(); err == nil {
			for _, address := range addresses {
				prefix, ok := address.(*net.IPNet)
				if !ok {
					continue
				}
				if ip, ok := netip.AddrFromSlice(prefix.IP); ok && ip.Unmap().Is4() == to.Is4() && !ip.IsLinkLocalUnicast() {
					uplink.Address = ip.Unmap().String()
					break
				}
			}
		}
	}
	return uplink, true
}

// driverOf asks the kernel which driver gives an interface, as ethtool -i does: no right needed
func driverOf(name string) string {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(fd)
	info, err := unix.IoctlGetEthtoolDrvinfo(fd, name)
	if err != nil {
		return ""
	}
	return unix.ByteSliceToString(info.Driver[:])
}

func interfaceInfos() []InterfaceInfo {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}
	infos := make([]InterfaceInfo, 0, len(list))
	for _, iface := range list {
		info := InterfaceInfo{Name: iface.Name, Kind: interfaceKind(iface), Up: iface.Flags&net.FlagUp != 0, MTU: iface.MTU}
		if addresses, err := iface.Addrs(); err == nil {
			for _, address := range addresses {
				if prefix, ok := address.(*net.IPNet); ok && prefix.IP.IsLinkLocalUnicast() {
					continue
				}
				info.Addresses = append(info.Addresses, address.String())
			}
		}
		infos = append(infos, info)
	}
	// Ethernet, WireGuard, the others, lo last
	sort.SliceStable(infos, func(i, j int) bool {
		return kindRank(infos[i]) < kindRank(infos[j]) || kindRank(infos[i]) == kindRank(infos[j]) && infos[i].Name < infos[j].Name
	})
	return infos
}

func kindRank(info InterfaceInfo) int {
	switch info.Kind {
	case "ethernet":
		return 0
	case "wireguard":
		return 1
	case "loopback":
		return 3
	}
	return 2
}

func interfaceKind(iface net.Interface) string {
	if iface.Flags&net.FlagLoopback != 0 {
		return "loopback"
	}
	if strings.Contains(readText("/sys/class/net/"+iface.Name+"/uevent"), "DEVTYPE=wireguard") {
		return "wireguard"
	}
	// ARPHRD_ETHER
	if strings.TrimSpace(readText("/sys/class/net/"+iface.Name+"/type")) == "1" {
		return "ethernet"
	}
	return "other"
}

// disks are the disk of the data folder, and the one of the root of the container when it's another
func disks(dataDir string) []Disk {
	var list []Disk
	data, dataOK := statDisk("data", dataDir)
	if dataOK {
		list = append(list, data)
	}
	if root, ok := statDisk("system", "/"); ok && !(dataOK && root.Total == data.Total && root.Inodes == data.Inodes) {
		list = append(list, root)
	}
	return list
}

func statDisk(name, path string) (Disk, bool) {
	var fs syscall.Statfs_t
	if syscall.Statfs(path, &fs) != nil || fs.Blocks == 0 {
		return Disk{}, false
	}
	size := uint64(fs.Bsize)
	return Disk{
		Name: name, Path: path, Total: fs.Blocks * size, Used: (fs.Blocks - fs.Bfree) * size, Available: fs.Bavail * size,
		Inodes: fs.Files, InodesFree: fs.Ffree,
	}, true
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
