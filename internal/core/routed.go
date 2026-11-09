package core

import (
	"net/netip"
	"reflect"

	"github.com/phatdo1819/authway-server/internal/hostroute"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

// RouteView is a route that the router of the networks of a routed server needs: its tunnel network through the
// address of the container, or of the Docker host when the container is on a Docker bridge.
type RouteView struct {
	Tunnel  string `json:"tunnel"`
	Network string `json:"network"`
	// the address of the container towards the network, "" when it can't be read
	Via string `json:"via"`
	// the driver of the network of the container: macvlan works; veth, a Docker bridge, needs the routes of the
	// Docker host, ipvlan doesn't work
	Driver string `json:"driver"`
	// on a Docker bridge: the route of the Docker host to the container, and its address for the router
	Host *system.HostRoute `json:"host,omitempty"`
}

// uplinkRoutes are the routes of a routed server, one for each version of its networks: the tunnel through the
// address of the container towards the first network of that version. Nil when it isn't routed, or without the
// System page that reads them. It reads the routes of the container: no lock needed.
func (s *Service) uplinkRoutes(server *store.Server) []system.Route {
	if s.opts.System == nil || !server.Routed {
		return nil
	}
	var routes []system.Route
	add := func(tunnel string, ipv6 bool) {
		for _, text := range server.Networks {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is6() != ipv6 {
				continue
			}
			route := system.Route{Tunnel: tunnel, Network: prefix.String()}
			route.Uplink, _ = s.opts.System.Uplink(prefix.Masked().Addr())
			routes = append(routes, route)
			return
		}
	}
	add(server.Network, false)
	if server.Network6 != "" {
		add(server.Network6, true)
	}
	return routes
}

// routesOf are the uplinkRoutes with, on a Docker bridge, what the helper of the Docker host did for them. No lock
// needed either.
func (s *Service) routesOf(server *store.Server) []system.Route {
	routes := s.uplinkRoutes(server)
	for index := range routes {
		if routes[index].Uplink.Driver == system.DriverVeth {
			routes[index].Host = s.hostRoute(routes[index])
		}
	}
	return routes
}

func (s *Service) hostRoute(route system.Route) system.HostRoute {
	if s.hostReader == nil {
		return system.HostRoute{State: system.HostOff}
	}
	report, running := s.hostReader.Get(s.now())
	if !running {
		return system.HostRoute{State: system.HostStopped}
	}
	state, ok := report.Find(route.Tunnel, route.Uplink.Address)
	switch {
	case ok && state.Routed:
		return system.HostRoute{State: system.HostRouted, Address: state.Host,
			Previous: s.routerAddress(route.Tunnel, state.Host), Error: state.Error}
	case ok && state.Error != "":
		return system.HostRoute{State: system.HostFailed, Error: state.Error}
	}
	// asked a moment ago
	return system.HostRoute{State: system.HostPending}
}

func routeViews(routes []system.Route) []RouteView {
	if len(routes) == 0 {
		return nil
	}
	views := make([]RouteView, 0, len(routes))
	for _, route := range routes {
		view := RouteView{Tunnel: route.Tunnel, Network: route.Network, Via: route.Uplink.Address, Driver: route.Uplink.Driver}
		if route.Uplink.Driver == system.DriverVeth {
			host := route.Host
			view.Host = &host
		}
		views = append(views, view)
	}
	return views
}

// the addresses that tell the default routes of the container: its addresses on the Docker network
var defaultProbes = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}

// syncHostRoutesLocked tells the helper of the Docker host the routes of the routed servers on a Docker bridge,
// after each change and at each Tick: the file changes only when they do, or when it's gone.
func (s *Service) syncHostRoutesLocked() {
	if s.opts.HostRoutes == "" || s.opts.System == nil {
		return
	}
	servers, err := s.db.Q().Servers()
	if err != nil {
		return
	}
	wanted := hostroute.Wanted{Addresses: []string{}, Routes: []hostroute.Want{}}
	for _, probe := range defaultProbes {
		if uplink, ok := s.opts.System.Uplink(probe); ok && uplink.Driver == system.DriverVeth && uplink.Address != "" {
			wanted.Addresses = append(wanted.Addresses, uplink.Address)
		}
	}
	for index := range servers {
		server := &servers[index]
		if !server.Enabled {
			continue
		}
		for _, route := range s.uplinkRoutes(server) {
			if route.Uplink.Driver == system.DriverVeth && route.Uplink.Address != "" {
				wanted.Routes = append(wanted.Routes, hostroute.Want{Server: server.Name, Tunnel: route.Tunnel,
					Via: route.Uplink.Address, Network: route.Network, Inbound: server.Inbound})
			}
		}
	}
	if s.hostWanted != nil && reflect.DeepEqual(*s.hostWanted, wanted) && hostroute.WantedExists(s.opts.HostRoutes) {
		return
	}
	if err := hostroute.WriteWanted(s.opts.HostRoutes, wanted); err != nil {
		if s.hostWriteError != err.Error() {
			s.log.Error("can't tell the helper of the Docker host the routes", "error", err)
		}
		s.hostWriteError = err.Error()
		return
	}
	s.hostWriteError = ""
	s.hostWanted = &wanted
}
