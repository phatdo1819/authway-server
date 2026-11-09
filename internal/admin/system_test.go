package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

// The System page: the resources and the checks, the history in steps, the points after since only, the latest
// lines of the log; and nothing without a login.
func TestSystemAPI(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ring := system.NewLogRing()
	log := slog.New(ring.Handler(slog.NewTextHandler(io.Discard, nil)))
	monitor := system.New(system.Options{Probe: system.Simulated(), Version: "1.2.3", Log: ring})
	fake := network.NewFake()
	service, err := core.New(db, fake, core.Options{PublicHost: "vpn.example.com", Log: log, System: monitor, Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnsureAdmin("admin", "Admin password 1"); err != nil {
		t.Fatal(err)
	}
	monitor.Sample()
	h := New(service, Options{Log: log}).Handler()
	anonymous := &client{t: t, h: h}
	if w, _ := anonymous.do("GET", "/api/system", "", true); w.Code != 401 {
		t.Errorf("without a login: %d", w.Code)
	}
	// the health check of the container: no login, no header, nothing but codes
	service.Tick()
	if w, data := anonymous.do("GET", "/healthz", "", false); w.Code != 200 || data["status"] != "ok" || len(data) != 1 {
		t.Errorf("healthy: %d %v", w.Code, data)
	}
	fake.ApplyError = errors.New("nft: no such table")
	if _, err := service.CreateServer(core.Actor{ID: 1, Username: "admin"}, defaultsOf(t, service)); err != nil {
		t.Fatal(err)
	}
	w, data := anonymous.do("GET", "/healthz", "", false)
	if w.Code != 503 || data["status"] != "unhealthy" || fmt.Sprint(data["failing"]) != "[configuration]" || strings.Contains(w.Body.String(), "nft") {
		t.Errorf("unhealthy: %d %s", w.Code, w.Body.String())
	}
	fake.ApplyError = nil
	service.Tick()
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	get := func(path string, into any) {
		t.Helper()
		w, _ := admin.do("GET", path, "", true)
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), into) != nil {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}

	var status core.Status
	if get("/api/status", &status); status.Version != "1.2.3" {
		t.Errorf("status: %+v", status)
	}
	var snapshot system.Snapshot
	get("/api/system", &snapshot)
	if !snapshot.Simulated || snapshot.Own.Version != "1.2.3" || snapshot.Host.Processors != 4 || len(snapshot.Interfaces) != 5 ||
		len(snapshot.Disks) != 1 || len(snapshot.Checks) < 9 {
		t.Errorf("snapshot: %+v", snapshot)
	}

	var hour, day system.History
	get("/api/system/history?range=3600", &hour)
	get("/api/system/history?range=86400", &day)
	if hour.Step != 5 || len(hour.Points) < system.RecentPoints-2 || day.Step != 60 || len(day.Points) < system.DayPoints-2 {
		t.Errorf("history: %d points of %d s, %d of %d s", len(hour.Points), hour.Step, len(day.Points), day.Step)
	}
	var after system.History
	get("/api/system/history?range=3600&since="+strconv.FormatInt(hour.Points[len(hour.Points)-2].At, 10), &after)
	if len(after.Points) != 1 || after.Points[0].At != hour.Points[len(hour.Points)-1].At {
		t.Errorf("since: %+v", after.Points)
	}

	log.Info("administrator logged in", "user", "admin")
	log.Error("can't apply the configuration", "error", "nft: syntax error")
	var problems, all []system.LogEntry
	get("/api/system/log", &problems)
	get("/api/system/log?level=all", &all)
	// the newest first: this one, then the one of the health check above
	if len(problems) != 2 || problems[0].Attrs != `error="nft: syntax error"` || len(all) < 4 {
		t.Errorf("log: %+v / %+v", problems, all)
	}
	get("/api/system", &snapshot)
	for _, check := range snapshot.Checks {
		if check.ID == "log" && check.Status != system.CheckWarning {
			t.Errorf("an error in the log: %+v", check)
		}
	}
}

func defaultsOf(t *testing.T, service *core.Service) core.ServerInput {
	t.Helper()
	suggestion, err := service.ServerDefaults(0)
	input := suggestion.ServerInput
	if err != nil {
		t.Fatal(err)
	}
	input.Name = "Office"
	return input
}
