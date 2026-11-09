package system

import (
	"fmt"
	"strings"
	"time"
)

// The checks of what goes wrong most: each one ok, warning, error, or unknown when it can't be read.
const (
	CheckOK      = "ok"
	CheckWarning = "warning"
	CheckError   = "error"
	CheckUnknown = "unknown"
)

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// the limits of the checks
const (
	// percent free: below the first a warning, below the second an error
	LowSpace, NoSpace = 10.0, 5.0
	// percent used of the connection tracking table
	ConntrackBusy, ConntrackFull = 75.0, 90.0
	// the load of the processors over 5 minutes, by processor
	Overload = 2.0
	// the tunnels are read every 5 seconds
	StaleStats = 30 * time.Second
)

func checks(s Snapshot, state State, readErr string, log *LogRing, now time.Time) []Check {
	list := []Check{}
	add := func(id, status, title, detail string) {
		list = append(list, Check{ID: id, Status: status, Title: title, Detail: detail})
	}

	if state.ApplyError == "" {
		add("configuration", CheckOK, "The configuration is applied", "The interfaces and the firewall rules match the servers.")
	} else {
		add("configuration", CheckError, "The configuration isn't applied",
			state.ApplyError+". Authway Server tries again every few seconds.")
	}

	switch {
	case state.StatsError != "":
		add("tunnels", CheckError, "Can't read the tunnels",
			state.StatsError+". The sessions can't follow their peers, and the connections aren't recorded.")
	case state.StatsAt.IsZero():
		add("tunnels", CheckUnknown, "The tunnels aren't read yet", "Authway Server reads them every 5 seconds.")
	case now.Sub(state.StatsAt) > StaleStats:
		add("tunnels", CheckWarning, "The tunnels weren't read for a while",
			fmt.Sprintf("The latest reading is %s old: Authway Server may be stuck. Its log says more.", ageText(now.Sub(state.StatsAt))))
	default:
		read := "The tunnels were just read."
		if age := now.Sub(state.StatsAt); age >= time.Second {
			read = fmt.Sprintf("The tunnels were read %s ago.", ageText(age))
		}
		add("tunnels", CheckOK, "WireGuard answers", read)
	}

	interfaces := map[string]Interface{}
	for _, iface := range s.Interfaces {
		interfaces[iface.Name] = iface
	}
	var up, missing, down []string
	for _, server := range state.Servers {
		name := server.Interface + " (" + server.Name + ")"
		iface, ok := interfaces[server.Interface]
		switch {
		case !ok:
			missing = append(missing, name)
		case !iface.Up:
			down = append(down, name)
		default:
			up = append(up, name)
		}
	}
	switch {
	case len(state.Servers) == 0:
		add("interfaces", CheckOK, "No server is enabled", "There is no interface to check.")
	case len(missing)+len(down) > 0:
		var parts []string
		if len(missing) > 0 {
			parts = append(parts, "missing: "+strings.Join(missing, ", "))
		}
		if len(down) > 0 {
			parts = append(parts, "down: "+strings.Join(down, ", "))
		}
		add("interfaces", CheckError, "An interface of a server isn't up",
			capitalize(strings.Join(parts, "; "))+". The peers of that server can't connect.")
	case len(up) == 1:
		add("interfaces", CheckOK, "The interface of the enabled server is up", up[0]+".")
	default:
		add("interfaces", CheckOK, fmt.Sprintf("The interfaces of the %d enabled servers are up", len(up)), strings.Join(up, ", ")+".")
	}

	switch {
	case s.IPForward == nil:
		add("forwarding", CheckUnknown, "Can't read IP forwarding", "Without it, the peers reach only this server.")
	case *s.IPForward:
		add("forwarding", CheckOK, "IP forwarding is on", "The peers reach the networks of their server.")
	default:
		add("forwarding", CheckError, "IP forwarding is off",
			"The peers reach only this server. Set the sysctl net.ipv4.ip_forward=1 on the container, as compose.yaml does.")
	}

	// only when a server carries IPv6: the others drop it
	if count := len(state.IPv6Servers); count > 0 {
		servers := "The server " + state.IPv6Servers[0] + " has"
		if count > 1 {
			servers = "The servers " + strings.Join(state.IPv6Servers, ", ") + " have"
		}
		switch {
		case s.IPv6On != nil && !*s.IPv6On:
			add("ipv6", CheckError, "IPv6 is off in the container",
				servers+" an IPv6 network, but the tunnels can't get IPv6 addresses: they carry IPv4 only. Turn on IPv6 on the Docker network of the container, as compose.yaml does, and create the container again.")
		case s.IPv6Forward == nil || s.IPv6Route == nil:
			add("ipv6", CheckUnknown, "Can't read the state of IPv6", servers+" an IPv6 network.")
		case !*s.IPv6Forward:
			add("ipv6", CheckError, "IPv6 forwarding is off",
				"The peers reach only this server over IPv6. Set the sysctl net.ipv6.conf.all.forwarding=1 on the container, as compose.yaml does.")
		case !*s.IPv6Route:
			add("ipv6", CheckWarning, "No IPv6 route out of the container",
				"The peers reach the tunnels over IPv6, not the networks behind the server nor the internet. Turn on IPv6 on the Docker network of the container, as compose.yaml does; the host needs IPv6 too.")
		default:
			add("ipv6", CheckOK, "IPv6 is on", servers+" an IPv6 network: forwarding is on, with a route out of the container.")
		}
	}

	// only with a routed server: the router of its networks sends the tunnels back to the container. On macvlan to
	// its own address; on the Docker bridge to the address of the Docker host, whose helper sends them on
	if len(state.Routed) > 0 {
		var ipvlan, off, stopped, pending, failed, unknown, routes, moved []string
		throughHost := false
		for _, server := range state.Routed {
			for _, route := range server.Routes {
				switch {
				case route.Uplink.Interface == "":
					unknown = append(unknown, route.Network+" ("+server.Name+")")
				case route.Uplink.Driver == DriverIPvlan:
					ipvlan = appendOnce(ipvlan, server.Name)
				case route.Uplink.Driver == DriverVeth:
					switch route.Host.State {
					case HostRouted:
						throughHost = true
						via := route.Host.Address
						if via == "" {
							via = "the address of the Docker host"
						}
						routes = append(routes, route.Tunnel+" via "+via+" ("+server.Name+")")
						if route.Host.Error != "" {
							failed = append(failed, server.Name+", "+route.Tunnel+": "+route.Host.Error)
						}
						if route.Host.Previous != "" {
							moved = append(moved, route.Tunnel+" via "+via+" instead of via "+route.Host.Previous+" ("+server.Name+")")
						}
					case HostStopped:
						stopped = appendOnce(stopped, server.Name)
					case HostPending:
						pending = appendOnce(pending, server.Name)
					case HostFailed:
						failed = append(failed, server.Name+", "+route.Tunnel+": "+route.Host.Error)
					default:
						off = appendOnce(off, server.Name)
					}
				default:
					via := route.Uplink.Address
					if via == "" {
						via = "the address of the container on " + route.Uplink.Interface
					}
					routes = append(routes, route.Tunnel+" via "+via+" ("+server.Name+")")
				}
			}
		}
		switch {
		case len(ipvlan) > 0:
			add("routing", CheckError, "A routed server can't work on ipvlan",
				serversAre(ipvlan)+" routed, but the container is on an ipvlan network: the kernel gives the packets for the tunnels to the host, not to the container. Use the Docker bridge with compose.host-routes.yaml, or macvlan with compose.macvlan.yaml.")
		case len(off) > 0:
			add("routing", CheckWarning, "A routed server needs routes on the Docker host",
				serversAre(off)+" routed, but the container is on the Docker bridge and the Docker host doesn't send the tunnels on to it: the networks get no answer. Add compose.host-routes.yaml to COMPOSE_FILE in the file .env, then docker compose up -d: its helper adds the routes on the Docker host, and the router needs only a route to the address of the host. Or give the container an address of its own in the network with compose.macvlan.yaml.")
		case len(stopped) > 0:
			add("routing", CheckWarning, "The helper of the Docker host isn't running",
				serversAre(stopped)+" routed through the Docker host, but the helper of compose.host-routes.yaml hasn't written for 30 seconds: the networks get no answer. docker compose up -d starts it again, and docker compose logs host-routes tells what's wrong.")
		case len(failed) > 0:
			add("routing", CheckError, "The Docker host can't route a server",
				strings.Join(failed, "; ")+".")
		case len(moved) > 0:
			add("routing", CheckWarning, "The address of the Docker host changed",
				"The router of the networks still sends the tunnels to the address of before, so the networks don't answer the peers. Change its routes: "+strings.Join(moved, "; ")+". Then say it's done in the warning at the top of the page. Give the Docker host a fixed address, a DHCP reservation for example, so it doesn't change again.")
		case len(pending) > 0:
			add("routing", CheckUnknown, "The Docker host is adding the routes",
				"The helper of compose.host-routes.yaml adds the routes of "+strings.Join(pending, ", ")+" in a few seconds.")
		case len(unknown) > 0:
			add("routing", CheckUnknown, "Can't read the routes of the container",
				"A routed server needs a route to its networks, and the container has none to "+strings.Join(unknown, ", ")+".")
		case throughHost:
			add("routing", CheckOK, "The routed servers reach their networks through the Docker host",
				"The router of the networks needs these routes: "+strings.Join(routes, "; ")+". The Docker host sends them on to the container.")
		default:
			add("routing", CheckOK, "The routed servers reach their networks directly",
				"The router of the networks needs these routes: "+strings.Join(routes, "; ")+".")
		}
	}

	switch {
	case s.Host.ClockSynced == nil:
		add("clock", CheckUnknown, "Can't tell whether the clock is synchronized",
			"Authenticator codes fail when the clock is off by more than 30 seconds. Time zone: "+s.Host.Timezone+".")
	case *s.Host.ClockSynced:
		add("clock", CheckOK, "The clock is synchronized", "A time service keeps it right. Time zone: "+s.Host.Timezone+".")
	default:
		add("clock", CheckWarning, "The clock may not be synchronized",
			"The kernel says no time service keeps it right, and authenticator codes fail when it's off by more than 30 seconds. "+
				"Check the time service of the host: timedatectl.")
	}

	diskStatus, diskTitle := CheckOK, "Enough disk space"
	var diskDetails []string
	for _, disk := range s.Disks {
		if disk.Total == 0 {
			continue
		}
		free := percent(disk.Available, disk.Used+disk.Available)
		status := CheckOK
		switch {
		case free < NoSpace:
			status = CheckError
		case free < LowSpace:
			status = CheckWarning
		}
		text := fmt.Sprintf("%s: %s available of %s", diskName(disk), bytesText(disk.Available), bytesText(disk.Total))
		if disk.Inodes > 0 && percent(disk.InodesFree, disk.Inodes) < NoSpace {
			status = worse(status, CheckWarning)
			text += fmt.Sprintf(", but only %d files can still be created", disk.InodesFree)
		}
		diskDetails = append(diskDetails, text)
		diskStatus = worse(diskStatus, status)
	}
	switch diskStatus {
	case CheckError:
		diskTitle = "The disk is almost full"
		diskDetails = append(diskDetails, "When it's full, the database can't save the logins and the changes")
	case CheckWarning:
		diskTitle = "Little disk space left"
	}
	if len(diskDetails) == 0 {
		add("disk", CheckUnknown, "Can't read the disk space", "")
	} else {
		add("disk", diskStatus, diskTitle, strings.Join(diskDetails, ". ")+".")
	}

	if s.Host.MemoryTotal == 0 {
		add("memory", CheckUnknown, "Can't read the memory", readErr)
	} else {
		free := percent(s.Host.MemoryAvailable, s.Host.MemoryTotal)
		detail := fmt.Sprintf("%s available of %s.", bytesText(s.Host.MemoryAvailable), bytesText(s.Host.MemoryTotal))
		switch {
		case free < NoSpace:
			add("memory", CheckError, "The memory is almost exhausted", detail+" The kernel stops programs when none is left.")
		case free < LowSpace:
			add("memory", CheckWarning, "Little memory left", detail)
		case s.Own.MemoryLimit > 0 && percent(s.Own.Memory, s.Own.MemoryLimit) > 100-LowSpace:
			add("memory", CheckWarning, "Authway Server is near its memory limit",
				fmt.Sprintf("It uses %s of the %s of its container: past it, the container stops.", bytesText(s.Own.Memory), bytesText(s.Own.MemoryLimit)))
		default:
			add("memory", CheckOK, "Enough memory", detail)
		}
	}

	if processors := s.Host.Processors; processors > 0 {
		detail := fmt.Sprintf("Load %.2f over 5 minutes, for %s.", s.Host.Load[1], plural(processors, "processor"))
		if s.Host.Load[1] > Overload*float64(processors) {
			add("processors", CheckWarning, "The processors are overloaded", detail+" Programs wait for their turn: the tunnels slow down.")
		} else {
			add("processors", CheckOK, "The processors keep up", detail)
		}
	}

	if s.Conntrack.Max > 0 {
		used := percent(uint64(s.Conntrack.Count), uint64(s.Conntrack.Max))
		detail := fmt.Sprintf("%d of %d entries.", s.Conntrack.Count, s.Conntrack.Max)
		switch {
		case used > ConntrackFull:
			add("conntrack", CheckError, "The connection tracking table is almost full",
				detail+" When it's full, new connections are dropped: raise net.netfilter.nf_conntrack_max on the host.")
		case used > ConntrackBusy:
			add("conntrack", CheckWarning, "The connection tracking table fills up", detail)
		default:
			add("conntrack", CheckOK, "Connection tracking has room", detail)
		}
	}

	if c := s.Certificate; c != nil {
		until := time.Unix(c.NotAfter, 0)
		left := until.Sub(now)
		replace := "Replace tls/cert.pem and tls/key.pem in the data folder: Authway Server loads them within a minute, without a restart."
		if c.SelfSigned {
			replace = "Authway Server couldn't make a new one: its log says why."
		}
		switch {
		case c.Error != "":
			add("certificate", CheckError, "The new certificate of the web UI can't be loaded",
				c.Error+". The one before is still in use: check tls/cert.pem and tls/key.pem in the data folder.")
		case left <= 0:
			add("certificate", CheckError, "The certificate of the web UI has expired", "It ended on "+dateText(until)+". "+replace)
		case left < RenewBefore:
			add("certificate", CheckWarning, fmt.Sprintf("The certificate of the web UI expires in %s", plural(int(left.Hours()/24), "day")),
				"On "+dateText(until)+". "+replace)
		case c.SelfSigned:
			add("certificate", CheckOK, "The certificate of the web UI is valid",
				"Self-signed, until "+dateText(until)+": Authway Server makes a new one 30 days before.")
		default:
			add("certificate", CheckOK, "The certificate of the web UI is valid",
				"Until "+dateText(until)+", for "+strings.Join(c.Names, ", ")+".")
		}
	}

	if count, latest := log.Errors(now.Add(-time.Hour)); count == 0 {
		add("log", CheckOK, "No error in the log for the last hour", "")
	} else {
		detail := "The latest: " + latest.Message
		if latest.Attrs != "" {
			detail += " (" + latest.Attrs + ")"
		}
		if runes := []rune(detail); len(runes) > 300 {
			detail = string(runes[:297]) + "..."
		}
		add("log", CheckWarning, plural(count, "error")+" in the log in the last hour", detail)
	}
	return list
}

var severity = map[string]int{CheckOK: 0, CheckUnknown: 1, CheckWarning: 2, CheckError: 3}

func worse(a, b string) string {
	if severity[b] > severity[a] {
		return b
	}
	return a
}

func diskName(disk Disk) string {
	if disk.Name == "data" {
		return "The data folder"
	}
	return "The system of the container"
}

func percent(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", count, noun)
}

func serversAre(names []string) string {
	if len(names) == 1 {
		return "The server " + names[0] + " is"
	}
	return "The servers " + strings.Join(names, ", ") + " are"
}

func appendOnce(list []string, value string) []string {
	for _, item := range list {
		if item == value {
			return list
		}
	}
	return append(list, value)
}

func capitalize(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func dateText(at time.Time) string {
	return at.UTC().Format("2 January 2006")
}

func ageText(age time.Duration) string {
	if age < time.Minute {
		return fmt.Sprintf("%d s", int(age.Seconds()))
	}
	if age < time.Hour {
		return fmt.Sprintf("%d min", int(age.Minutes()))
	}
	return fmt.Sprintf("%d h", int(age.Hours()))
}

// bytesText is the size as the web UI writes it, in units of 1024
func bytesText(bytes uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(bytes)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if value < 10 && unit > 0 {
		return fmt.Sprintf("%.1f %s", value, units[unit])
	}
	return fmt.Sprintf("%.0f %s", value, units[unit])
}
