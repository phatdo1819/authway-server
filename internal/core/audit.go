package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/phatdo1819/authway-server/internal/store"
)

// Actor is the administrator who acts in the web UI. The events of the changes say who, and from which address.
type Actor struct {
	ID       int64
	Username string
	From     string
}

// changeLocked records a change made in the web UI
func (s *Service) changeLocked(by Actor, event store.Event) {
	event.Actor, event.Source = by.Username, by.From
	s.eventLocked(event)
}

// webKinds are the events of the web UI: the logins of the administrators and the changes. The others are the events
// of the peers: their logins, sessions, copies and devices.
var webKinds = []string{
	"admin_login", "admin_login_failed", "admin_added", "admin_changed", "admin_deleted", "admin_password_reset",
	"admin_password_changed", "admin_mfa_on", "admin_mfa_removed", "settings_changed", "backup_made", "backup_restored",
	"server_added", "server_changed", "server_deleted", "router_routes_updated",
	"peer_added", "peer_changed", "peer_deleted", "peer_keys", "peer_config", "session_ended", "alerts_cleared",
	"device_allowed", "device_revoked",
	"user_added", "user_changed", "user_deleted", "user_mfa_on", "user_mfa_removed",
}

// EventTypes are the values of the type filter of the events: web, the events of the web UI, or vpn, the others
const (
	EventsWeb = "web"
	EventsVPN = "vpn"
)

// Filter narrows the history lists of the Activity page.
type Filter = store.Filter

// MaxPage is the largest page of a history list; a CSV file takes up to MaxExport rows.
const (
	MaxPage   = 1000
	MaxExport = 100000
)

// Page is a page of a history list, and how many rows match the filter in all.
type Page[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

func (s *Service) HistoryPage(f Filter) (Page[SessionView], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sessions, total, err := s.db.Q().HistoryPage(f)
	if err != nil {
		return Page[SessionView]{}, err
	}
	page := Page[SessionView]{Items: make([]SessionView, 0, len(sessions)), Total: total}
	for _, session := range sessions {
		page.Items = append(page.Items, *sessionView(session))
	}
	return page, nil
}

func (s *Service) ConnectionsPage(f Filter) (Page[ConnectionView], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	connections, total, err := s.db.Q().ConnectionsPage(f)
	if err != nil {
		return Page[ConnectionView]{}, err
	}
	page := Page[ConnectionView]{Items: make([]ConnectionView, 0, len(connections)), Total: total}
	for _, c := range connections {
		page.Items = append(page.Items, connectionView(c))
	}
	return page, nil
}

// EventsPage takes the type of events, EventsWeb or EventsVPN ("" for all), and a server by id: the events keep the
// name of their server.
func (s *Service) EventsPage(f Filter, kinds string) (Page[EventView], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.ServerID != 0 {
		server, err := s.db.Q().Server(f.ServerID)
		if err != nil {
			return Page[EventView]{Items: []EventView{}}, nil
		}
		f.ServerName, f.ServerID = server.Name, 0
	}
	switch kinds {
	case EventsWeb:
		f.Kinds = webKinds
	case EventsVPN:
		f.Kinds, f.ExceptKinds = webKinds, true
	}
	events, total, err := s.db.Q().EventsPage(f)
	if err != nil {
		return Page[EventView]{}, err
	}
	page := Page[EventView]{Items: make([]EventView, 0, len(events)), Total: total}
	for _, event := range events {
		page.Items = append(page.Items, eventView(event))
	}
	return page, nil
}

// changes lists what changed between two values of something, in words for the events
type changes []string

func (c *changes) text(label, before, after string) {
	if before != after {
		*c = append(*c, fmt.Sprintf("%s: %s → %s", label, orNone(before), orNone(after)))
	}
}

func (c *changes) number(label string, before, after int, unit string) {
	if before != after {
		*c = append(*c, fmt.Sprintf("%s: %s → %s", label, withUnit(before, unit), withUnit(after, unit)))
	}
}

// toggle says "label on" or "label off"
func (c *changes) toggle(label string, before, after bool) {
	if before != after {
		*c = append(*c, label+" "+onOff(after))
	}
}

func (c *changes) list(label string, before, after []string) {
	if strings.Join(before, ",") != strings.Join(after, ",") {
		c.text(label, strings.Join(before, ", "), strings.Join(after, ", "))
	}
}

func (c changes) String() string {
	return strings.Join(c, ", ")
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func withUnit(value int, unit string) string {
	if value == 0 && unit != "" {
		return "default"
	}
	return strings.TrimSpace(strconv.Itoa(value) + " " + unit)
}

var authModeNames = map[string]string{
	store.AuthKey: "WireGuard key only", store.AuthPassword: "password", store.AuthPasswordOTP: "password and code",
}

// hoursText is a length of time in hours, or in minutes when it isn't a number of hours
func hoursText(seconds int) string {
	if seconds%3600 == 0 {
		return strconv.Itoa(seconds/3600) + " h"
	}
	return strconv.Itoa(seconds/60) + " min"
}

func serverNames(servers []store.Server) map[int64]string {
	names := make(map[int64]string, len(servers))
	for _, server := range servers {
		names[server.ID] = server.Name
	}
	return names
}

// serverChanges are the changes of a server, for its event
func serverChanges(before, after *store.Server, names map[int64]string) changes {
	var c changes
	c.text("name", before.Name, after.Name)
	if before.Enabled != after.Enabled {
		c = append(c, map[bool]string{true: "enabled", false: "disabled"}[after.Enabled])
	}
	c.text("public address", before.PublicHost, after.PublicHost)
	c.number("UDP port", before.ListenPort, after.ListenPort, "")
	c.number("public port", before.PublicPort, after.PublicPort, "")
	c.list("fallback addresses", before.FallbackEndpoints, after.FallbackEndpoints)
	c.text("tunnel network", before.Network, after.Network)
	c.text("IPv6 network", before.Network6, after.Network6)
	c.list("networks", before.Networks, after.Networks)
	c.list("DNS", before.DNS, after.DNS)
	c.number("MTU", before.MTU, after.MTU, "")
	c.number("keepalive", before.Keepalive, after.Keepalive, "s")
	c.text("login", authModeNames[before.AuthMode], authModeNames[after.AuthMode])
	if before.SessionTimeout != after.SessionTimeout {
		c.text("session length", hoursText(before.SessionTimeout), hoursText(after.SessionTimeout))
	}
	c.text("lock to the public IP", before.LockEndpoint, after.LockEndpoint)
	c.toggle("copy detection", before.DetectCopies, after.DetectCopies)
	c.toggle("block copies", before.BlockCopies, after.BlockCopies)
	c.toggle("lead to the login page", before.Redirect, after.Redirect)
	c.toggle("device binding", before.DeviceBinding, after.DeviceBinding)
	c.toggle("machine ID", before.MachineID, after.MachineID)
	c.toggle("traffic between its peers", before.ClientToClient, after.ClientToClient)
	routing := map[bool]string{false: "NAT", true: "routed"}
	c.text("to the networks", routing[before.Routed], routing[after.Routed])
	c.toggle("connections from the networks", before.Inbound, after.Inbound)
	serverNames := func(ids []int64) []string {
		list := make([]string, 0, len(ids))
		for _, id := range ids {
			list = append(list, names[id])
		}
		return list
	}
	c.list("reaches the peers of", serverNames(before.ReachableServers), serverNames(after.ReachableServers))
	return c
}
