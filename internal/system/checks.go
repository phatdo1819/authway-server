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

	switch {
	case state.ApplyError != "":
		add("configuration", CheckError, "The configuration couldn't be applied",
			state.ApplyError+". Authway Server retries every few seconds.")
	case state.ApplyWarning != "":
		add("configuration", CheckWarning, "Configuration applied with warnings",
			state.ApplyWarning+". The tunnels still carry traffic. Authway Server tries again when a server changes or when it restarts.")
	default:
		add("configuration", CheckOK, "Configuration applied", "Interfaces and firewall rules match the servers.")
	}

	switch {
	case state.StatsError != "":
		add("tunnels", CheckError, "Can't read WireGuard status",
			state.StatsError+". Sessions can't track their peers, and connections aren't being recorded.")
	case state.StatsAt.IsZero():
		add("tunnels", CheckUnknown, "WireGuard status not read yet", "Authway Server reads it every 5 seconds.")
	case now.Sub(state.StatsAt) > StaleStats:
		add("tunnels", CheckWarning, "WireGuard status is out of date",
			fmt.Sprintf("Last read %s ago. Authway Server may be stuck; check its log.", ageText(now.Sub(state.StatsAt))))
	default:
		read := "Just read."
		if age := now.Sub(state.StatsAt); age >= time.Second {
			read = fmt.Sprintf("Read %s ago.", ageText(age))
		}
		add("tunnels", CheckOK, "WireGuard is responding", read)
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
		add("interfaces", CheckOK, "No servers are enabled", "There are no interfaces to check.")
	case len(missing)+len(down) > 0:
		var parts []string
		if len(missing) > 0 {
			parts = append(parts, "missing: "+strings.Join(missing, ", "))
		}
		if len(down) > 0 {
			parts = append(parts, "down: "+strings.Join(down, ", "))
		}
		add("interfaces", CheckError, "A server's interface isn't up",
			capitalize(strings.Join(parts, "; "))+". Peers on that server can't connect.")
	case len(up) == 1:
		add("interfaces", CheckOK, "The enabled server's interface is up", up[0]+".")
	default:
		add("interfaces", CheckOK, "Interfaces are up on all enabled servers", strings.Join(up, ", ")+".")
	}

	switch {
	case s.IPForward == nil:
		add("forwarding", CheckUnknown, "Can't read IP forwarding", "Without it, peers can only reach this server.")
	case *s.IPForward:
		add("forwarding", CheckOK, "IP forwarding is on", "Peers can reach their server's networks.")
	default:
		add("forwarding", CheckError, "IP forwarding is off",
			"Peers can only reach this server. Set the sysctl net.ipv4.ip_forward=1 on the container, as compose.yaml does.")
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
				servers+" an IPv6 network, but peers can't get IPv6 addresses, so the VPN carries IPv4 only. Enable IPv6 on the container's Docker network as compose.yaml does, then recreate the container.")
		case s.IPv6Forward == nil || s.IPv6Route == nil:
			add("ipv6", CheckUnknown, "Can't read the IPv6 status", servers+" an IPv6 network.")
		case !*s.IPv6Forward:
			add("ipv6", CheckError, "IPv6 forwarding is off",
				"Peers can only reach this server over IPv6. Set the sysctl net.ipv6.conf.all.forwarding=1 on the container, as compose.yaml does.")
		case !*s.IPv6Route:
			add("ipv6", CheckWarning, "No IPv6 route out of the container",
				"Peers can use IPv6 inside the VPN, but can't reach the networks behind the server or the internet over IPv6. Enable IPv6 on the container's Docker network as compose.yaml does; the host needs IPv6 too.")
		default:
			add("ipv6", CheckOK, "IPv6 is on", servers+" an IPv6 network. Forwarding is on, and the container has an IPv6 route out.")
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
							via = "the Docker host's address"
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
						via = "the container's address on " + route.Uplink.Interface
					}
					routes = append(routes, route.Tunnel+" via "+via+" ("+server.Name+")")
				}
			}
		}
		switch {
		case len(ipvlan) > 0:
			add("routing", CheckError, "A routed server can't work on ipvlan",
				serversAre(ipvlan)+" routed, but the container is on an ipvlan network, where the kernel delivers VPN traffic to the host instead of the container. Use the Docker bridge with compose.host-routes.yaml, or macvlan with compose.macvlan.yaml.")
		case len(off) > 0:
			add("routing", CheckWarning, "A routed server needs routes on the Docker host",
				serversAre(off)+" routed, but the container is on the Docker bridge and the Docker host doesn't forward VPN traffic to it, so your networks get no replies. Add compose.host-routes.yaml to COMPOSE_FILE in the .env file, then run docker compose up -d. Its helper adds the routes on the Docker host, and your router only needs a route to the host's address. Alternatively, give the container its own address on the network with compose.macvlan.yaml.")
		case len(stopped) > 0:
			add("routing", CheckWarning, "The Docker host helper isn't running",
				serversAre(stopped)+" routed through the Docker host, but the compose.host-routes.yaml helper hasn't reported in for 30 seconds, so your networks get no replies. Run docker compose up -d to restart it, and docker compose logs host-routes to see what's wrong.")
		case len(failed) > 0:
			add("routing", CheckError, "The Docker host can't route a server",
				strings.Join(failed, "; ")+".")
		case len(moved) > 0:
			add("routing", CheckWarning, "The Docker host's address changed",
				"Your router still sends VPN traffic to the old address, so your networks can't reach the peers. Update its routes: "+strings.Join(moved, "; ")+". Then confirm it in the warning at the top of the page. Give the Docker host a fixed address (a DHCP reservation, for example) so this doesn't happen again.")
		case len(pending) > 0:
			add("routing", CheckUnknown, "The Docker host is adding the routes",
				"The compose.host-routes.yaml helper will add the routes for "+strings.Join(pending, ", ")+" in a few seconds.")
		case len(unknown) > 0:
			// the routes of the container were read and none goes there: on an internal Docker network, which has no
			// gateway, say
			reach, fix := "it", "a route to it"
			if len(unknown) > 1 {
				reach, fix = "them", "routes to them"
			}
			add("routing", CheckWarning, "A routed server can't reach its networks",
				"The container has no route to "+strings.Join(unknown, ", ")+", so peers can't reach "+reach+
					". Give the container's Docker network a gateway (an internal network has none), or add "+fix+".")
		case throughHost:
			add("routing", CheckOK, "Routed servers reach their networks through the Docker host",
				"Your router needs these routes: "+strings.Join(routes, "; ")+". The Docker host forwards the traffic to the container.")
		default:
			add("routing", CheckOK, "Routed servers reach their networks directly",
				"Your router needs these routes: "+strings.Join(routes, "; ")+".")
		}
	}

	// only when the users of Active Directory are synced
	if d := state.Directory; d != nil {
		switch {
		case d.At.IsZero():
			add("directory", CheckUnknown, "Active Directory hasn't synced yet", "The first sync runs within a minute.")
		case d.Error != "":
			add("directory", CheckError, "Can't sync with Active Directory",
				capitalize(d.Error)+". Authway Server tries again at the next sync. Until then, changes in Active Directory don't reach its users.")
		case d.Held > 0:
			users := fmt.Sprintf("%d users", d.Held)
			add("directory", CheckWarning, "An Active Directory sync is waiting for you",
				"It would disable "+users+" at once, so it disabled no one. Check them in Settings › Active Directory, and confirm there if it's right.")
		default:
			members := fmt.Sprintf("%d members", d.Members)
			if d.Members == 1 {
				members = "1 member"
			}
			synced := "Just synced."
			if age := now.Sub(d.At); age >= time.Second {
				synced = "Last synced " + ageText(age) + " ago."
			}
			add("directory", CheckOK, "Synced with Active Directory", "The group has "+members+". "+synced)
		}
		if len(d.Unanswered) > 0 {
			add("directory_servers", CheckWarning, "A domain controller doesn't answer",
				"At the latest sync: "+strings.Join(d.Unanswered, "; ")+". The next one in the list answered instead.")
		}
		if !d.PasswordExpires.IsZero() {
			switch left := d.PasswordExpires.Sub(now); {
			case left <= 0:
				add("directory_password", CheckError, "The service account's password has expired",
					"It expired on "+dateText(d.PasswordExpires)+". Set a new one in Active Directory, then in Settings › Active Directory.")
			case left <= DirectoryPasswordWarning:
				add("directory_password", CheckWarning, "The service account's password expires soon",
					"On "+dateText(d.PasswordExpires)+", in "+daysText(left)+". Set a new one in Active Directory, then in Settings › Active Directory, or users of Active Directory won't be able to log in.")
			default:
				add("directory_password", CheckOK, "The service account's password is valid",
					"Until "+dateText(d.PasswordExpires)+".")
			}
		}
	}

	switch {
	case s.Host.ClockSynced == nil:
		add("clock", CheckUnknown, "Can't tell whether the clock is synchronized",
			"Authenticator codes fail if the clock is off by more than 30 seconds. Time zone: "+s.Host.Timezone+".")
	case *s.Host.ClockSynced:
		add("clock", CheckOK, "The clock is synchronized", "A time service keeps it accurate. Time zone: "+s.Host.Timezone+".")
	default:
		add("clock", CheckWarning, "The clock may not be synchronized",
			"The kernel reports no time service keeping it accurate, and authenticator codes fail if it's off by more than 30 seconds. "+
				"Check the host's time service with timedatectl.")
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
		diskDetails = append(diskDetails, "When it's full, the database can't save logins or changes")
	case CheckWarning:
		diskTitle = "Disk space is running low"
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
			add("memory", CheckError, "Memory is almost exhausted", detail+" The kernel stops programs when memory runs out.")
		case free < LowSpace:
			add("memory", CheckWarning, "Memory is running low", detail)
		case s.Own.MemoryLimit > 0 && percent(s.Own.Memory, s.Own.MemoryLimit) > 100-LowSpace:
			add("memory", CheckWarning, "Authway Server is near its memory limit",
				fmt.Sprintf("It uses %s of its container's %s limit. Beyond that, the container is stopped.", bytesText(s.Own.Memory), bytesText(s.Own.MemoryLimit)))
		default:
			add("memory", CheckOK, "Enough memory", detail)
		}
	}

	if processors := s.Host.Processors; processors > 0 {
		detail := fmt.Sprintf("Load %.2f over 5 minutes, across %s.", s.Host.Load[1], plural(processors, "processor"))
		if s.Host.Load[1] > Overload*float64(processors) {
			add("processors", CheckWarning, "The processors are overloaded", detail+" Programs are waiting for CPU time, which slows down the VPN.")
		} else {
			add("processors", CheckOK, "The processors are keeping up", detail)
		}
	}

	if s.Conntrack.Max > 0 {
		used := percent(uint64(s.Conntrack.Count), uint64(s.Conntrack.Max))
		detail := fmt.Sprintf("%d of %d entries.", s.Conntrack.Count, s.Conntrack.Max)
		switch {
		case used > ConntrackFull:
			add("conntrack", CheckError, "The connection tracking table is almost full",
				detail+" When it's full, new connections are dropped. Raise net.netfilter.nf_conntrack_max on the host.")
		case used > ConntrackBusy:
			add("conntrack", CheckWarning, "The connection tracking table is filling up", detail)
		default:
			add("conntrack", CheckOK, "Connection tracking has room", detail)
		}
	}

	if c := s.Certificate; c != nil {
		until := time.Unix(c.NotAfter, 0)
		left := until.Sub(now)
		replace := "Replace tls/cert.pem and tls/key.pem in the data folder. Authway Server picks them up within a minute, without a restart."
		if c.SelfSigned {
			replace = "Authway Server couldn't create a new one; its log explains why."
		}
		switch {
		case c.Error != "":
			add("certificate", CheckError, "The web UI's new certificate can't be loaded",
				c.Error+". The previous one is still in use. Check tls/cert.pem and tls/key.pem in the data folder.")
		case left <= 0:
			add("certificate", CheckError, "The web UI's certificate has expired", "It expired on "+dateText(until)+". "+replace)
		case left < RenewBefore:
			add("certificate", CheckWarning, "The web UI's certificate expires in "+daysText(left), "On "+dateText(until)+". "+replace)
		case c.SelfSigned:
			add("certificate", CheckOK, "The web UI's certificate is valid",
				"Self-signed, until "+dateText(until)+". Authway Server creates a new one 30 days before it expires.")
		default:
			add("certificate", CheckOK, "The web UI's certificate is valid",
				"Until "+dateText(until)+", for "+strings.Join(c.Names, ", ")+".")
		}
	}

	if count, latest := log.Errors(now.Add(-time.Hour)); count == 0 {
		add("log", CheckOK, "No errors in the log in the last hour", "")
	} else {
		detail := "Latest: " + latest.Message
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
	return "The container's system disk"
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

// DirectoryPasswordWarning is how long before the password of the service account of Active Directory expires the
// warnings start
const DirectoryPasswordWarning = 14 * 24 * time.Hour

// daysText is a time left in days: "1 day", "3 days", "less than a day"
func daysText(left time.Duration) string {
	days := int(left / (24 * time.Hour))
	switch days {
	case 0:
		return "less than a day"
	case 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
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
