package system

import (
	"errors"
	"strconv"
	"strings"
)

// The files of /proc and /sys, read as text: the same on every system, so tested everywhere.

// parseStat reads the line of all the processors of /proc/stat, in ticks, and counts the processors.
func parseStat(text string) (total, busy, iowait uint64, processors int, err error) {
	found := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cpu" {
			// user nice system idle iowait irq softirq steal: guest and guest_nice are counted in user and nice
			var values [8]uint64
			for index := range values {
				if index+1 < len(fields) {
					values[index], _ = strconv.ParseUint(fields[index+1], 10, 64)
				}
			}
			for _, value := range values {
				total += value
			}
			iowait = values[4]
			busy = total - values[3] - values[4]
			found = true
		} else if strings.HasPrefix(fields[0], "cpu") {
			processors++
		}
	}
	if !found {
		return 0, 0, 0, 0, errors.New("no processor line in /proc/stat")
	}
	return total, busy, iowait, max(processors, 1), nil
}

// parseMeminfo gives the lines of /proc/meminfo in bytes.
func parseMeminfo(text string) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			value *= 1024
		}
		values[strings.TrimSpace(name)] = value
	}
	// before Linux 3.14
	if _, ok := values["MemAvailable"]; !ok {
		values["MemAvailable"] = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	return values
}

// parseNetDev reads the counters of the interfaces in /proc/net/dev.
func parseNetDev(text string) map[string]InterfaceCounters {
	interfaces := map[string]InterfaceCounters{}
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		var values [16]uint64
		for index := range values {
			values[index], _ = strconv.ParseUint(fields[index], 10, 64)
		}
		// received: bytes packets errs drop fifo frame compressed multicast; sent: bytes packets errs drop...
		interfaces[strings.TrimSpace(name)] = InterfaceCounters{
			ReceivedBytes: values[0], ReceivedPackets: values[1], SentBytes: values[8], SentPackets: values[9],
			Errors: values[2] + values[10], Drops: values[3] + values[11],
		}
	}
	return interfaces
}

// parseKeyValues reads the "name value" lines of the files of the cgroups: cpu.stat, memory.stat.
func parseKeyValues(text string) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if value, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
			values[fields[0]] = value
		}
	}
	return values
}

func parseLoadavg(text string) [3]float64 {
	var load [3]float64
	fields := strings.Fields(text)
	for index := range load {
		if index < len(fields) {
			load[index], _ = strconv.ParseFloat(fields[index], 64)
		}
	}
	return load
}

// parseOSRelease gives the name of the system of /etc/os-release: Alpine Linux v3.22
func parseOSRelease(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return ""
}

// parseSelfStat gives the processor time of a process in ticks, user and system, from /proc/self/stat. Its name
// can have spaces and parentheses: the fields start after the last one.
func parseSelfStat(text string) (uint64, bool) {
	end := strings.LastIndexByte(text, ')')
	if end < 0 {
		return 0, false
	}
	// state is the 3rd field, utime the 14th and stime the 15th
	fields := strings.Fields(text[end+1:])
	if len(fields) < 13 {
		return 0, false
	}
	user, err1 := strconv.ParseUint(fields[11], 10, 64)
	system, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return user + system, true
}

// parseCgroup gives the cgroup of a process, from /proc/self/cgroup: the line 0:: of the cgroups v2
func parseCgroup(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return path, true
		}
	}
	return "", false
}

// parseLimit reads memory.max: max is no limit
func parseLimit(text string) uint64 {
	value, err := strconv.ParseUint(strings.TrimSpace(text), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// parseIPv6DefaultRoute tells whether /proc/net/ipv6_route has a default route that leaves: ::/0, up, not the one
// that rejects everything on the loopback, which every kernel with IPv6 has.
func parseIPv6DefaultRoute(text string) bool {
	const up, reject = 0x0001, 0x0200
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" || fields[9] == "lo" {
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err == nil && flags&up != 0 && flags&reject == 0 {
			return true
		}
	}
	return false
}
