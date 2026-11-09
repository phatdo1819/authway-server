package core

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/phatdo1819/authway-server/internal/store"
)

// hostAddressesKey is the key of the meta table that keeps the addresses of the Docker host for the routers.
const hostAddressesKey = "host_addresses"

// hostAddress is the address of the Docker host towards the networks of a routed server, for one of its tunnel
// networks: the next hop of the route on their router. It's kept in the database, so a change while Authway Server
// was stopped shows too: a host that starts again with another address from DHCP.
type hostAddress struct {
	Server  string `json:"server"`
	Address string `json:"address"`
	// the address the router has, as far as Authway Server knows: set when Address changed, until an administrator
	// says the router has the new route, or Address comes back to it
	Previous  string `json:"previous,omitempty"`
	ChangedAt int64  `json:"changed_at,omitempty"`
}

// HostAddressChange is a route to change on the router of the networks of a routed server: the address of the
// Docker host changed.
type HostAddressChange struct {
	Server   string `json:"server"`
	Tunnel   string `json:"tunnel"`
	Address  string `json:"address"`
	Previous string `json:"previous"`
	At       int64  `json:"at"`
}

// loadHostAddressesLocked returns the addresses known, read from the database the first time. With mu and hostMu.
func (s *Service) loadHostAddressesLocked() map[string]hostAddress {
	if s.hostAddresses != nil {
		return s.hostAddresses
	}
	known := map[string]hostAddress{}
	text, err := s.db.Q().Meta(hostAddressesKey)
	if err != nil {
		s.log.Error("can't read the addresses of the Docker host", "error", err)
	} else if text != "" {
		if err := json.Unmarshal([]byte(text), &known); err != nil {
			s.log.Error("can't read the addresses of the Docker host", "error", err)
			known = map[string]hostAddress{}
		}
	}
	s.hostAddresses = known
	return known
}

func (s *Service) saveHostAddressesLocked(addresses map[string]hostAddress) {
	data, err := json.Marshal(addresses)
	if err == nil {
		err = s.db.Q().SetMeta(hostAddressesKey, string(data))
	}
	if err != nil {
		s.log.Error("can't save the addresses of the Docker host", "error", err)
	}
	s.hostAddresses = addresses
}

// watchHostAddressesLocked follows the address of the Docker host that the router of the networks of each routed
// server sends its tunnel to. When it changes, the route on the router is wrong, and nothing here can change it: an
// event says it, and the web UI shows the route to change until an administrator says the router has it.
func (s *Service) watchHostAddressesLocked() {
	if s.hostReader == nil || s.hostWanted == nil {
		return
	}
	report, running := s.hostReader.Get(s.now())
	if !running {
		return
	}
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	known := s.loadHostAddressesLocked()
	next := make(map[string]hostAddress, len(s.hostWanted.Routes))
	for _, want := range s.hostWanted.Routes {
		old, had := known[want.Tunnel]
		state, ok := report.Find(want.Tunnel, want.Via)
		if !ok || !state.Routed || state.Host == "" {
			// not routed this moment, or the container moved: what was known stays
			if had {
				next[want.Tunnel] = old
			}
			continue
		}
		entry := hostAddress{Server: want.Server, Address: state.Host, Previous: old.Previous, ChangedAt: old.ChangedAt}
		if had && old.Address != state.Host {
			// the router has the first address, whatever came between
			if entry.Previous == "" {
				entry.Previous = old.Address
			}
			entry.ChangedAt = s.now().Unix()
			if entry.Previous == state.Host {
				// back to the address of the router: nothing to change there any more
				entry.Previous, entry.ChangedAt = "", 0
				s.log.Info("the address of the Docker host came back", "server", want.Server, "tunnel", want.Tunnel,
					"address", state.Host)
			} else {
				s.log.Warn("the address of the Docker host changed: the router of the networks needs the new route",
					"server", want.Server, "route", want.Tunnel+" via "+state.Host, "before", old.Address)
			}
			s.eventLocked(store.Event{Kind: "host_address_changed", ServerName: want.Server,
				Detail: "address of the Docker host for " + want.Tunnel + ": " + old.Address + " → " + state.Host})
		}
		next[want.Tunnel] = entry
	}
	if !reflect.DeepEqual(next, known) {
		s.saveHostAddressesLocked(next)
	}
}

// routerAddress is the address the router still has for a tunnel, when the one of the Docker host changed: "" when
// the router is up to date, as far as Authway Server knows. Without mu.
func (s *Service) routerAddress(tunnel, address string) string {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	if entry, ok := s.hostAddresses[tunnel]; ok && entry.Address == address {
		return entry.Previous
	}
	return ""
}

// hostChangesLocked are the routes to change on the routers, by server and tunnel. With mu.
func (s *Service) hostChangesLocked() []HostAddressChange {
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	changes := []HostAddressChange{}
	for tunnel, entry := range s.loadHostAddressesLocked() {
		if entry.Previous != "" {
			changes = append(changes, HostAddressChange{Server: entry.Server, Tunnel: tunnel, Address: entry.Address,
				Previous: entry.Previous, At: entry.ChangedAt})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Server != changes[j].Server {
			return changes[i].Server < changes[j].Server
		}
		return changes[i].Tunnel < changes[j].Tunnel
	})
	return changes
}

// ConfirmHostAddresses says that the routers have the routes through the new addresses of the Docker host: the web
// UI stops asking for them.
func (s *Service) ConfirmHostAddresses(by Actor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostMu.Lock()
	defer s.hostMu.Unlock()
	known := s.loadHostAddressesLocked()
	next := make(map[string]hostAddress, len(known))
	var done []string
	for tunnel, entry := range known {
		if entry.Previous != "" {
			done = append(done, tunnel+" via "+entry.Address+" ("+entry.Server+")")
			entry.Previous, entry.ChangedAt = "", 0
		}
		next[tunnel] = entry
	}
	if len(done) == 0 {
		return nil
	}
	sort.Strings(done)
	s.saveHostAddressesLocked(next)
	s.changeLocked(by, store.Event{Kind: "router_routes_updated", Detail: "routes on the router: " + strings.Join(done, ", ")})
	return nil
}
