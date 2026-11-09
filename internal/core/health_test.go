package core

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/store"
)

// Healthy, until the configuration isn't applied, the tunnels aren't read, the loop stops or the lock is held.
func TestHealth(t *testing.T) {
	f := setup(t)
	f.s.Tick()
	if failing := f.s.Health(); len(failing) != 0 {
		t.Fatalf("healthy: %v", failing)
	}
	f.net.ApplyError = errors.New("nft: no such table")
	f.net.StatsError = errors.New("netlink: permission denied")
	f.server(store.AuthKey)
	f.s.Tick()
	if failing := f.s.Health(); !slices.Equal(failing, []string{"configuration", "tunnels"}) {
		t.Errorf("failing: %v", failing)
	}
	f.net.ApplyError, f.net.StatsError = nil, nil
	f.s.Tick()
	if failing := f.s.Health(); len(failing) != 0 {
		t.Errorf("healthy again: %v", failing)
	}
	// no pass of the loop for half a minute
	f.clock.advance(StuckAfter + time.Second)
	if failing := f.s.Health(); !slices.Equal(failing, []string{"stuck"}) {
		t.Errorf("loop stopped: %v", failing)
	}
	// the lock held
	f.s.Tick()
	f.s.mu.Lock()
	start := time.Now()
	failing := f.s.Health()
	f.s.mu.Unlock()
	if !slices.Equal(failing, []string{"stuck"}) || time.Since(start) > healthWait+time.Second {
		t.Errorf("lock held: %v after %v", failing, time.Since(start))
	}
	if failing := f.s.Health(); len(failing) != 0 {
		t.Errorf("after the lock: %v", failing)
	}
}

// The days of the history are a setting: checked, an event, used at the next pass when fewer, in the backups.
func TestHistoryDays(t *testing.T) {
	f := setup(t)
	if settings, _ := f.s.Settings(); settings.HistoryDays != DefaultHistoryDays {
		t.Fatalf("default: %d", settings.HistoryDays)
	}
	for _, days := range []int{0, -1, MaxHistoryDays + 1} {
		if _, err := f.s.SetSettings(Actor{ID: f.admin()}, SettingsInput{HistoryDays: &days}); err == nil {
			t.Errorf("%d days accepted", days)
		}
	}
	// an event of 10 days ago, then 7 days kept: it goes at the next pass, not in an hour
	f.s.Tick()
	q := f.db.Q()
	if err := q.AddEvent(&store.Event{At: f.clock.now.AddDate(0, 0, -10).Unix(), Kind: "login_failed", Detail: "old"}); err != nil {
		t.Fatal(err)
	}
	days := 7
	settings, err := f.s.SetSettings(Actor{ID: f.admin()}, SettingsInput{HistoryDays: &days})
	if err != nil || settings.HistoryDays != 7 {
		t.Fatalf("7 days: %+v %v", settings, err)
	}
	if e := f.lastEvent("settings_changed"); e.Detail != "history kept 7 days, was 90" {
		t.Errorf("event: %q", e.Detail)
	}
	f.s.Tick()
	events, _ := f.s.EventsPage(Filter{Limit: 100, Search: "old"}, "")
	if events.Total != 0 {
		t.Errorf("the old event stayed: %+v", events.Items)
	}

	// in the backup, and back with a restore; a backup without it restores the default
	content, err := f.s.backupContentLocked(f.clock.now)
	if err != nil || content.Settings.HistoryDays != 7 {
		t.Fatalf("backup: %+v %v", content.Settings, err)
	}
	content.Settings.HistoryDays = MaxHistoryDays + 1
	if _, err := f.s.checkBackup(content, "admin"); err == nil || !strings.Contains(err.Error(), "days of the history") {
		t.Errorf("bad days in a backup: %v", err)
	}
}
