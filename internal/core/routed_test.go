package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/hostroute"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

// On the Docker bridge the helper of the Docker host gets the routes of the routed servers, and the view shows what
// it did: the address of the host for the router.
func TestHostRoutes(t *testing.T) {
	f := setup(t)
	// the made-up eth0 of a Docker bridge, 172.18.0.2
	f.s.opts.System = system.New(system.Options{Probe: system.Simulated(), Now: f.clock.Now})
	office := f.server(store.AuthPassword)
	input := inputOf(office)
	input.Routed, input.Inbound = true, true
	view, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	// no helper: said so, and no file
	if len(view.Routes) != 1 || view.Routes[0].Host == nil || view.Routes[0].Host.State != system.HostOff {
		t.Fatalf("without the helper: %+v", view.Routes)
	}

	dir := t.TempDir()
	f.s.opts.HostRoutes, f.s.hostReader = dir, hostroute.NewReader(dir)
	f.s.Tick()
	wanted, err := hostroute.ReadWanted(dir)
	expected := hostroute.Want{Server: office.Name, Tunnel: office.Network, Via: "172.18.0.2", Network: "192.168.1.0/24", Inbound: true}
	if err != nil || len(wanted.Routes) != 1 || wanted.Routes[0] != expected || strings.Join(wanted.Addresses, ",") != "172.18.0.2" {
		t.Fatalf("wanted: %+v %v", wanted, err)
	}
	if view, _ = f.s.Server(office.ID); view.Routes[0].Host.State != system.HostStopped {
		t.Errorf("no report yet: %+v", view.Routes[0].Host)
	}

	report := func(states ...hostroute.State) {
		data, _ := json.Marshal(hostroute.Report{At: f.clock.Now().Unix(), Routes: states})
		if err := os.WriteFile(filepath.Join(dir, hostroute.ReportFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		// the reader reads again after a second
		f.clock.advance(2 * time.Second)
	}
	report()
	if view, _ = f.s.Server(office.ID); view.Routes[0].Host.State != system.HostPending {
		t.Errorf("asked: %+v", view.Routes[0].Host)
	}
	report(hostroute.State{Tunnel: office.Network, Via: "172.18.0.2", Bridge: "br-1", Host: "192.168.1.10", Routed: true, Inbound: true})
	if view, _ = f.s.Server(office.ID); *view.Routes[0].Host != (system.HostRoute{State: system.HostRouted, Address: "192.168.1.10"}) {
		t.Errorf("routed: %+v", view.Routes[0].Host)
	}
	snapshot, err := f.s.System()
	if err != nil {
		t.Fatal(err)
	}
	if check := checkOf(t, snapshot, "routing"); check.Status != system.CheckOK ||
		!strings.Contains(check.Detail, office.Network+" via 192.168.1.10 ("+office.Name+")") {
		t.Errorf("System page: %+v", check)
	}
	report(hostroute.State{Tunnel: office.Network, Via: "172.18.0.2", Error: "the Docker host already has a route"})
	if view, _ = f.s.Server(office.ID); view.Routes[0].Host.State != system.HostFailed || view.Routes[0].Host.Error == "" {
		t.Errorf("refused: %+v", view.Routes[0].Host)
	}
	// the helper stopped
	f.clock.advance(hostroute.StaleAfter)
	if view, _ = f.s.Server(office.ID); view.Routes[0].Host.State != system.HostStopped {
		t.Errorf("stopped: %+v", view.Routes[0].Host)
	}

	// the file isn't written again while nothing changes; gone, it is
	path := filepath.Join(dir, hostroute.WantedFile)
	before, _ := os.Stat(path)
	f.s.Tick()
	if after, _ := os.Stat(path); !after.ModTime().Equal(before.ModTime()) {
		t.Error("written again without a change")
	}
	os.Remove(path)
	f.s.Tick()
	if !hostroute.WantedExists(dir) {
		t.Error("not written again once gone")
	}

	// back to NAT: nothing asked, the address of the container stays for the helper to take its route away
	input.Routed = false
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	if wanted, err = hostroute.ReadWanted(dir); err != nil || len(wanted.Routes) != 0 || len(wanted.Addresses) != 1 {
		t.Errorf("NAT: %+v %v", wanted, err)
	}
}

// a routed server needs networks; the connections from the networks need it routed; the state, the view, the
// event and the backup carry both
func TestRoutedServer(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	if office.Routed || office.Inbound {
		t.Fatalf("a new server is routed: %+v", office)
	}

	input := inputOf(office)
	input.Routed, input.Networks = true, nil
	if _, err := f.s.UpdateServer(testActor, office.ID, input); fields(t, err)["routed"] != "no_networks" {
		t.Errorf("routed without networks: %v", err)
	}
	// a wrong network says so, not that there's none
	input.Networks = []string{"nonsense"}
	if got := fields(t, func() error { _, err := f.s.UpdateServer(testActor, office.ID, input); return err }()); got["routed"] != "" || got["networks"] != "invalid" {
		t.Errorf("fields: %v", got)
	}

	// Inbound alone stays off: the networks can't tell the peers of a translated server apart
	input = inputOf(office)
	input.Inbound = true
	view, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil || view.Routed || view.Inbound {
		t.Fatalf("inbound without routed: %+v %v", view, err)
	}

	input.Routed = true
	if view, err = f.s.UpdateServer(testActor, office.ID, input); err != nil || !view.Routed || !view.Inbound {
		t.Fatalf("routed: %+v %v", view, err)
	}
	state := f.net.State.Servers[0]
	if !state.Routed || !state.Inbound {
		t.Errorf("state: %+v", state)
	}
	if e := f.lastEvent("server_changed"); e.Detail != "to the networks: NAT → routed, connections from the networks on" {
		t.Errorf("event: %+v", e)
	}

	// disabled, the server isn't applied; enabled again, it's routed again
	input.Enabled = false
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	if len(f.net.State.Servers) != 0 {
		t.Errorf("a disabled server applied: %+v", f.net.State.Servers)
	}
	input.Enabled = true
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}

	before := f.snapshot()
	data := f.sealed(adminID, func(c *backupContent) {
		if c.Version < 4 || !c.Servers[0].Routed || !c.Servers[0].Inbound {
			t.Fatalf("content: %d %+v", c.Version, c.Servers[0])
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if after := f.snapshot(); !after.Servers[0].Routed || !after.Servers[0].Inbound || len(after.Servers) != len(before.Servers) {
		t.Fatalf("restored: %+v", after.Servers)
	}
	if state := f.net.State.Servers[0]; !state.Routed || !state.Inbound {
		t.Errorf("state after the restore: %+v", state)
	}

	// a version 3 backup has no routed server: translated, as before
	older := f.sealed(adminID, func(c *backupContent) {
		c.Version = 3
		for index := range c.Servers {
			c.Servers[index].Routed, c.Servers[index].Inbound = false, false
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", older, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if servers, _ := f.db.Q().Servers(); servers[0].Routed || servers[0].Inbound {
		t.Errorf("version 3: %+v", servers[0])
	}

	// a backup can't make a server routed without networks, nor open the networks to a translated one
	bad := f.sealed(adminID, func(c *backupContent) { c.Servers[0].Routed, c.Servers[0].Networks = true, nil })
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", bad, testPassphrase); err == nil ||
		!strings.Contains(err.Error(), "routed") {
		t.Errorf("routed without networks restores: %v", err)
	}
	inbound := f.sealed(adminID, func(c *backupContent) { c.Servers[0].Inbound = true })
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", inbound, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if servers, _ := f.db.Q().Servers(); servers[0].Inbound {
		t.Errorf("inbound without routed restored: %+v", servers[0])
	}
}

// When the address of the Docker host changes, the route on the router is wrong: the status, the view, the System page
// and an event say it until an administrator says the router has the new route, or the address comes back. The
// address known is in the database, so a change while Authway Server was stopped shows too.
func TestHostAddressChange(t *testing.T) {
	f := setup(t)
	f.s.opts.System = system.New(system.Options{Probe: system.Simulated(), Now: f.clock.Now})
	office := f.server(store.AuthPassword)
	input := inputOf(office)
	input.Routed = true
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f.s.opts.HostRoutes, f.s.hostReader = dir, hostroute.NewReader(dir)
	routedAt := func(host string) {
		state := hostroute.State{Tunnel: office.Network, Via: "172.18.0.2", Bridge: "br-1", Host: host, Routed: true}
		data, _ := json.Marshal(hostroute.Report{At: f.clock.Now().Unix(), Routes: []hostroute.State{state}})
		if err := os.WriteFile(filepath.Join(dir, hostroute.ReportFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
		f.clock.advance(2 * time.Second)
		f.s.Tick()
	}
	changes := func() []HostAddressChange {
		t.Helper()
		status, err := f.s.Status()
		if err != nil {
			t.Fatal(err)
		}
		return status.HostChanges
	}
	moves := func() int {
		page, err := f.s.EventsPage(Filter{Limit: 100}, EventsVPN)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, event := range page.Items {
			if event.Kind == "host_address_changed" {
				count++
			}
		}
		return count
	}

	// the first address: nothing to change
	f.s.Tick()
	routedAt("192.168.1.10")
	if c := changes(); c == nil || len(c) != 0 || moves() != 0 {
		t.Fatalf("first address: %+v, %d events", c, moves())
	}

	// another one: the router has the first
	routedAt("192.168.1.20")
	expected := HostAddressChange{Server: office.Name, Tunnel: office.Network, Address: "192.168.1.20",
		Previous: "192.168.1.10", At: f.clock.Now().Unix()}
	if c := changes(); len(c) != 1 || c[0] != expected || moves() != 1 {
		t.Fatalf("changed: %+v, %d events", c, moves())
	}
	if view, _ := f.s.Server(office.ID); view.Routes[0].Host.Address != "192.168.1.20" || view.Routes[0].Host.Previous != "192.168.1.10" {
		t.Errorf("view: %+v", view.Routes[0].Host)
	}
	snapshot, err := f.s.System()
	if err != nil {
		t.Fatal(err)
	}
	if check := checkOf(t, snapshot, "routing"); check.Status != system.CheckWarning ||
		!strings.Contains(check.Detail, office.Network+" via 192.168.1.20 instead of via 192.168.1.10 ("+office.Name+")") {
		t.Errorf("System page: %+v", check)
	}
	// the same address: no new event; read again from the database, the change stays
	routedAt("192.168.1.20")
	f.s.hostAddresses = nil
	if c := changes(); len(c) != 1 || moves() != 1 {
		t.Fatalf("read again: %+v, %d events", c, moves())
	}
	// a third: the router still has the first
	routedAt("192.168.1.30")
	if c := changes(); len(c) != 1 || c[0].Previous != "192.168.1.10" || c[0].Address != "192.168.1.30" || moves() != 2 {
		t.Fatalf("third: %+v", c)
	}
	// back to the first: nothing to change any more
	routedAt("192.168.1.10")
	if c := changes(); len(c) != 0 || moves() != 3 {
		t.Fatalf("back: %+v", c)
	}
	if view, _ := f.s.Server(office.ID); view.Routes[0].Host.Previous != "" {
		t.Errorf("view once back: %+v", view.Routes[0].Host)
	}

	// changed again, and the administrator says the router has the new route
	routedAt("192.168.1.20")
	if err := f.s.ConfirmHostAddresses(testActor); err != nil {
		t.Fatal(err)
	}
	if c := changes(); len(c) != 0 {
		t.Fatalf("confirmed: %+v", c)
	}
	if e := f.lastEvent("router_routes_updated"); e.By != "tester" ||
		e.Detail != "routes on the router: "+office.Network+" via 192.168.1.20 ("+office.Name+")" {
		t.Errorf("event: %+v", e)
	}
	// nothing left to confirm: no event
	before := len(f.webEvents())
	if err := f.s.ConfirmHostAddresses(testActor); err != nil || len(f.webEvents()) != before {
		t.Errorf("nothing to confirm: %v", err)
	}
	// the helper doesn't route it this moment: the address known stays, no change when it's back
	state := hostroute.State{Tunnel: office.Network, Via: "172.18.0.2", Error: "the Docker host already has a route"}
	data, _ := json.Marshal(hostroute.Report{At: f.clock.Now().Unix(), Routes: []hostroute.State{state}})
	if err := os.WriteFile(filepath.Join(dir, hostroute.ReportFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(2 * time.Second)
	f.s.Tick()
	routedAt("192.168.1.20")
	if c := changes(); len(c) != 0 || moves() != 4 {
		t.Fatalf("after a refusal: %+v, %d events", c, moves())
	}

	// back to NAT: forgotten
	input.Routed = false
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	routedAt("192.168.1.20")
	if text, _ := f.db.Q().Meta(hostAddressesKey); text != "{}" {
		t.Errorf("NAT: %s", text)
	}
}
