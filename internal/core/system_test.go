package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

func checkOf(t *testing.T, snapshot system.Snapshot, id string) system.Check {
	t.Helper()
	for _, check := range snapshot.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("no check %s in %+v", id, snapshot.Checks)
	return system.Check{}
}

// The System page knows what the core knows: the configuration applied or not, the tunnels read or not, the
// interfaces of the enabled servers only.
func TestSystemChecks(t *testing.T) {
	f := setup(t)
	if _, err := f.s.System(); !errors.Is(err, ErrNotFound) {
		t.Errorf("without a monitor: %v", err)
	}
	// the made-up values have the interfaces wg0, wg1 and wg2
	f.s.opts.System = system.New(system.Options{Probe: system.Simulated(), Now: f.clock.Now})
	var servers []*ServerView
	for range 4 {
		servers = append(servers, f.server(store.AuthKey))
	}
	if servers[3].Interface != "wg3" {
		t.Fatalf("interfaces: %s", servers[3].Interface)
	}
	input := inputOf(servers[2])
	input.Enabled = false
	if _, err := f.s.UpdateServer(testActor, servers[2].ID, input); err != nil {
		t.Fatal(err)
	}
	f.s.Tick()
	snapshot, err := f.s.System()
	if err != nil {
		t.Fatal(err)
	}
	if check := checkOf(t, snapshot, "configuration"); check.Status != system.CheckOK {
		t.Errorf("configuration: %+v", check)
	}
	if check := checkOf(t, snapshot, "tunnels"); check.Status != system.CheckOK {
		t.Errorf("tunnels: %+v", check)
	}
	// the disabled server has no interface, and isn't missed
	if check := checkOf(t, snapshot, "interfaces"); check.Status != system.CheckError ||
		check.Detail != "Missing: wg3 ("+servers[3].Name+"). Peers on that server can't connect." {
		t.Errorf("interfaces: %+v", check)
	}

	f.net.ApplyError = errors.New("nft: no such table")
	f.net.StatsError = errors.New("netlink: permission denied")
	if err := f.s.DeleteServer(testActor, servers[3].ID); err != nil {
		t.Fatal(err)
	}
	f.s.Tick()
	snapshot, _ = f.s.System()
	if check := checkOf(t, snapshot, "configuration"); check.Status != system.CheckError || !strings.HasPrefix(check.Detail, "nft: no such table.") {
		t.Errorf("configuration: %+v", check)
	}
	if check := checkOf(t, snapshot, "tunnels"); check.Status != system.CheckError || !strings.HasPrefix(check.Detail, "netlink: permission denied.") {
		t.Errorf("tunnels: %+v", check)
	}
	if check := checkOf(t, snapshot, "interfaces"); check.Status != system.CheckOK || check.Title != "Interfaces are up on all enabled servers" {
		t.Errorf("interfaces: %+v", check)
	}
	f.net.StatsError = nil
	f.s.Tick()
	if snapshot, _ := f.s.System(); checkOf(t, snapshot, "tunnels").Status != system.CheckOK {
		t.Errorf("tunnels read again: %+v", checkOf(t, snapshot, "tunnels"))
	}
}

// A tunnel that works less well, with an MTU or an IPv6 address that can't be set, is a warning: on the System page
// only. Authway Server stays healthy, the web UI has no failure to show, the peers are set, and the configuration
// isn't applied again at every pass of the monitor as a failure is.
func TestApplyWarning(t *testing.T) {
	f := setup(t)
	f.s.opts.System = system.New(system.Options{Probe: system.Simulated(), Now: f.clock.Now})
	f.net.ApplyError = &network.Warning{Err: errors.New("wg0: its MTU can't be set: RTNETLINK answers: Invalid argument")}
	f.server(store.AuthKey)
	f.s.Tick()
	if status, _ := f.s.Status(); status.ApplyError != "" {
		t.Errorf("a failure for the web UI: %q", status.ApplyError)
	}
	if failing := f.s.Health(); len(failing) != 0 {
		t.Errorf("unhealthy: %v", failing)
	}
	if len(f.net.State.Servers) != 1 {
		t.Errorf("not set: %+v", f.net.State)
	}
	applied := f.net.Applied
	f.s.Tick()
	f.s.Tick()
	if f.net.Applied != applied {
		t.Errorf("applied again at each pass: %d, then %d", applied, f.net.Applied)
	}
	snapshot, _ := f.s.System()
	if check := checkOf(t, snapshot, "configuration"); check.Status != system.CheckWarning ||
		check.Title != "Configuration applied with warnings" || !strings.HasPrefix(check.Detail, "wg0: its MTU can't be set") {
		t.Errorf("configuration: %+v", check)
	}
	// set right at the next change: no warning left
	f.net.ApplyError = nil
	f.server(store.AuthKey)
	snapshot, _ = f.s.System()
	if check := checkOf(t, snapshot, "configuration"); check.Status != system.CheckOK {
		t.Errorf("configuration after the change: %+v", check)
	}
}
