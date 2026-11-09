package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/backup"
	"github.com/phatdo1819/authway-server/internal/store"
)

const testPassphrase = "correct horse battery staple"

type configSnapshot struct {
	Servers []store.Server
	Peers   []store.Peer
	Users   []store.User
	Admins  []store.Admin
	Devices map[int64]store.Device
	Meta    map[string]string
}

func (f *fixture) snapshot() configSnapshot {
	f.t.Helper()
	q := f.db.Q()
	var snap configSnapshot
	var err1, err2, err3, err4, err5 error
	snap.Servers, err1 = q.Servers()
	snap.Peers, err2 = q.Peers(0)
	snap.Users, err3 = q.Users()
	snap.Admins, err4 = q.Admins()
	snap.Devices, err5 = q.Devices()
	for _, err := range []error{err1, err2, err3, err4, err5} {
		if err != nil {
			f.t.Fatal(err)
		}
	}
	snap.Meta = map[string]string{}
	for _, key := range []string{"public_host", "password_policy", "require_admin_mfa", "enroll_hours"} {
		snap.Meta[key], _ = q.Meta(key)
	}
	return snap
}

func TestBackupRestore(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	alice := f.user("alice")
	if _, err := f.s.SetupTOTP(testActor, alice.ID); err != nil {
		t.Fatal(err)
	}
	laptop := f.peer(office, alice)
	lab := f.server(store.AuthKey)
	printer, err := f.s.CreatePeer(testActor, lab.ID, PeerInput{Name: "printer", Enabled: true, RouteAll: true})
	if err != nil {
		t.Fatal(err)
	}
	host := "vpn2.example.com"
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{PublicHost: &host, PasswordPolicy: &PasswordPolicy{MinLength: 14, RequireDigit: true}}); err != nil {
		t.Fatal(err)
	}

	_, _, err = f.s.Backup(Actor{ID: adminID}, "wrong", "short")
	if got := fields(t, err); got["password"] != "wrong" || got["passphrase"] != "too_short" {
		t.Fatalf("checks: %v", got)
	}
	name, data, err := f.s.Backup(Actor{ID: adminID}, "Admin password 1", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "authway-backup-20261106-") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("name %q", name)
	}
	stored, _ := f.db.Q().Peer(laptop.ID)
	if strings.Contains(string(data), stored.PrivateKey) || strings.Contains(string(data), "alice") {
		t.Fatal("the backup isn't encrypted")
	}
	before := f.snapshot()

	// changes after the backup, and a session
	if err := f.s.DeleteServer(testActor, lab.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CreateUser(testActor, UserInput{Username: "bob", Password: "A much longer one 1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CreateAdmin(Actor{ID: adminID}, AdminInput{Username: "olga", Role: store.RoleOperator, Password: "Orange tree 4521x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RegeneratePeerKeys(testActor, laptop.ID); err != nil {
		t.Fatal(err)
	}
	if a := f.login(laptop, "203.0.113.5"); a.Status != 200 {
		t.Fatalf("login: %+v", a)
	}

	summary, err := f.s.CheckBackup(Actor{ID: adminID}, data, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	want := BackupSummary{CreatedAt: f.clock.now.Unix(), MadeBy: "Authway Server dev", Servers: 2, Peers: 2, Users: 1,
		Administrators: 1, AdminUsernames: []string{"admin"}, IncludesYou: true}
	if !reflect.DeepEqual(*summary, want) {
		t.Fatalf("summary %+v", *summary)
	}
	if _, err := f.s.CheckBackup(Actor{ID: adminID}, data, "another passphrase"); fields(t, err)["passphrase"] != "wrong" {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := f.s.CheckBackup(Actor{ID: adminID}, []byte(`{"hello":1}`), testPassphrase); fields(t, err)["backup"] != "not_backup" {
		t.Fatalf("not a backup: %v", err)
	}
	if f.snapshot().Servers[0].ID != office.ID || len(f.snapshot().Servers) != 1 {
		t.Fatal("a check changed something")
	}
	if _, err := f.s.Restore(Actor{ID: adminID}, "wrong", data, testPassphrase); fields(t, err)["password"] != "wrong" {
		t.Fatalf("wrong password: %v", err)
	}

	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	after := f.snapshot()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("restored:\n%s", snapDiff(after, before))
	}
	if sessions, _ := f.s.OpenSessions(); len(sessions) != 0 {
		t.Fatalf("sessions still open: %+v", sessions)
	}
	history, _ := f.s.History(10)
	if len(history) != 1 || history[0].EndReason != EndRestored {
		t.Fatalf("history %+v", history)
	}
	if len(f.net.State.Servers) != 2 || len(f.net.State.Servers[1].Peers) != 1 || !f.net.State.Servers[1].Peers[0].RouteAll {
		t.Fatalf("not applied: %+v", f.net.State)
	}
	if _, _, err := f.s.PeerConfig(testActor, printer.ID); err != nil {
		t.Fatal(err)
	}
	// the keys of the backup work again, the password of the user too
	if a := f.login(laptop, "203.0.113.5"); a.Status != 200 {
		t.Fatalf("login after the restore: %+v", a)
	}
	events, _ := f.s.Events(20)
	var kinds []string
	for _, event := range events {
		if strings.HasPrefix(event.Kind, "backup_") {
			kinds = append(kinds, event.Kind+": "+event.Detail)
		}
	}
	if len(kinds) != 2 || !strings.HasPrefix(kinds[0], "backup_restored: backup of 2026-11-06 10:00 UTC: 2 servers, 2 peers, 1 user, 1 administrator") ||
		kinds[1] != "backup_made: 2 servers, 2 peers, 1 user, 1 administrator" {
		t.Fatalf("events %q", kinds)
	}
}

// sealed makes a backup of the fixture, changes its content and seals it again: a file edited by someone who has
// the passphrase
func (f *fixture) sealed(adminID int64, change func(*backupContent)) []byte {
	f.t.Helper()
	f.s.mu.Lock()
	content, err := f.s.backupContentLocked(f.clock.now)
	f.s.mu.Unlock()
	if err != nil {
		f.t.Fatal(err)
	}
	change(content)
	data, _ := json.Marshal(content)
	sealed, err := backup.Seal(data, testPassphrase, f.clock.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

func TestRestoreChecks(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	office := f.server(store.AuthPassword)
	f.peer(office, f.user("alice"))
	before := f.snapshot()
	deviceKey := newDevice(t).public
	private, _ := wgtypes.GeneratePrivateKey()
	otherKey := private.PublicKey().String()
	for _, test := range []struct {
		name   string
		change func(*backupContent)
		detail string
	}{
		{"newer", func(c *backupContent) { c.Version = BackupVersion + 1 }, ""},
		{"no admin", func(c *backupContent) { c.Admins[0].Disabled = true }, "no enabled administrator"},
		{"role", func(c *backupContent) { c.Admins[0].Role = "root" }, "role of the administrator"},
		{"hash", func(c *backupContent) { c.Users[0].PasswordHash = "plain" }, "password hash of the user"},
		{"1 GiB hash", func(c *backupContent) {
			c.Admins[0].PasswordHash = strings.Replace(c.Admins[0].PasswordHash, "m=65536,", "m=1048576,", 1)
		}, "password hash of the administrator"},
		{"totp", func(c *backupContent) { c.Users[0].TOTPSecret = "!!" }, "authenticator of the user"},
		{"interface", func(c *backupContent) { c.Servers[0].Interface = "eth0; drop" }, "interface"},
		{"network", func(c *backupContent) { c.Servers[0].Networks = []string{"10.8.0.0/16"} }, "overlaps_tunnel"},
		{"peer address", func(c *backupContent) { c.Peers[0].Address = "10.8.0.1" }, "address of the peer"},
		{"peer keys", func(c *backupContent) { c.Peers[0].PublicKey = c.Servers[0].PrivateKey }, "keys of the peer"},
		{"peer user", func(c *backupContent) { c.Peers[0].UserID = 99 }, "user of the peer"},
		{"peer server", func(c *backupContent) { c.Peers[0].ServerID = 99 }, "has no server"},
		{"two servers", func(c *backupContent) {
			other := c.Servers[0]
			other.ID, other.Interface, other.Name = 2, "wg1", "Other"
			c.Servers = append(c.Servers, other)
		}, "listen_port: taken"},
		{"reachable", func(c *backupContent) { c.Servers[0].ReachableServers = []int64{42} }, "the servers that"},
		{"reaches itself", func(c *backupContent) { c.Servers[0].ReachableServers = []int64{c.Servers[0].ID} }, "the servers that"},
		{"enroll hours", func(c *backupContent) { c.Settings.EnrollHours = MaxEnrollHours + 1 }, "device enrollment"},
		{"device of nobody", func(c *backupContent) { c.Devices = []backupDevice{{PeerID: 99}} }, "a device has no peer"},
		{"device key", func(c *backupContent) {
			c.Devices = []backupDevice{{PeerID: c.Peers[0].ID, Key: "MFkw"}}
		}, "the key of the device"},
		{"two devices", func(c *backupContent) {
			c.Devices = []backupDevice{{PeerID: c.Peers[0].ID}, {PeerID: c.Peers[0].ID}}
		}, "has two devices"},
		{"device name", func(c *backupContent) {
			c.Devices = []backupDevice{{PeerID: c.Peers[0].ID, Key: deviceKey, Name: "evil\nname"}}
		}, "the device of the peer"},
		{"device WireGuard key of the file", func(c *backupContent) {
			c.Devices = []backupDevice{{PeerID: c.Peers[0].ID, Key: deviceKey, WireGuardKey: c.Peers[0].PublicKey}}
		}, "the WireGuard key of the device"},
		{"device WireGuard key without a device", func(c *backupContent) {
			c.Devices = []backupDevice{{PeerID: c.Peers[0].ID, WireGuardKey: otherKey}}
		}, "the WireGuard key of the device"},
	} {
		_, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", f.sealed(adminID, test.change), testPassphrase)
		var validation *ValidationError
		if !errors.As(err, &validation) {
			t.Fatalf("%s: %v", test.name, err)
		}
		if test.detail == "" && validation.Fields["backup"] != "newer_version" ||
			test.detail != "" && (validation.Fields["backup"] != "invalid_content" || !strings.Contains(validation.Detail, test.detail)) {
			t.Fatalf("%s: %v", test.name, err)
		}
	}
	if !reflect.DeepEqual(before, f.snapshot()) {
		t.Fatal("a refused restore changed something")
	}
}

func TestRestoreOtherAdmins(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	backupFile := f.sealed(adminID, func(c *backupContent) {
		c.Admins[0].Username = "root"
	})
	summary, err := f.s.CheckBackup(Actor{ID: adminID}, backupFile, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.IncludesYou || !reflect.DeepEqual(summary.AdminUsernames, []string{"root"}) {
		t.Fatalf("summary %+v", summary)
	}
	generation := f.s.Generation()
	if _, _, err := f.s.AdminAccessSince(adminID, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", backupFile, testPassphrase); err != nil {
		t.Fatal(err)
	}
	// a session of before has the same id as root: it must not act as root
	if _, _, err := f.s.AdminAccessSince(adminID, generation); !errors.Is(err, ErrStale) {
		t.Fatalf("a session of before the restore: %v", err)
	}
	if admin, _, err := f.s.AdminAccessSince(adminID, f.s.Generation()); err != nil || admin.Username != "root" {
		t.Fatalf("a session of after the restore: %v %v", admin, err)
	}
	if _, ok := f.s.AdminLogin("admin", "Admin password 1"); ok {
		t.Fatal("the administrator of before is still there")
	}
	if _, ok := f.s.AdminLogin("root", "Admin password 1"); !ok {
		t.Fatal("the administrator of the backup can't log in")
	}
}

func TestBackupDevices(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	hours := 24
	policy := PasswordPolicy{MinLength: 10, RequireLower: true}
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{EnrollHours: &hours, PasswordPolicy: &policy}); err != nil {
		t.Fatal(err)
	}
	office := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DeviceBinding, input.MachineID = true, true })
	lab := f.server(store.AuthKey)
	input := inputOf(office)
	input.ClientToClient, input.ReachableServers = true, []int64{lab.ID}
	office, err := f.s.UpdateServer(testActor, office.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	alice := f.peer(office, f.user("alice"))
	f.peer(office, f.user("bob"))
	laptop := newDevice(t)
	machine := strings.Repeat("ab", 32)
	if a := f.deviceLogin(office, alice, laptop, "203.0.113.5", machine); a.Status != 200 {
		t.Fatalf("enrollment: %+v", a)
	}
	private, _ := wgtypes.GeneratePrivateKey()
	newKey := private.PublicKey().String()
	challenge := f.challenge(alice)
	request := DeviceKeyRequest{Challenge: challenge, WireGuardKey: newKey,
		Signature: laptop.sign(keyMessage(challenge, office.PublicKey, alice.PublicKey, alice.Address, newKey))}
	if a := f.s.DeviceKey(netip.MustParseAddr(alice.Address), "10.8.0.1", request); a.Status != 200 {
		t.Fatalf("the key of the device: %+v", a)
	}
	f.runTimers()
	_, data, err := f.s.Backup(Actor{ID: adminID}, "Admin password 1", testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	before := f.snapshot()
	if len(before.Devices) != 2 {
		t.Fatalf("devices %+v", before.Devices)
	}

	if _, err := f.s.RevokeDevice(testActor, alice.ID); err != nil {
		t.Fatal(err)
	}
	input.ClientToClient, input.ReachableServers = false, nil
	if _, err := f.s.UpdateServer(testActor, office.ID, input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if after := f.snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("restored:\n%s", snapDiff(after, before))
	}
	if peers := f.net.State.Servers[0].Peers; peers[0].PublicKey.String() != newKey {
		t.Fatalf("the key of the device isn't on the interface: %+v", peers)
	}
	if !f.net.State.Servers[0].ClientToClient || strings.Join(f.net.State.Servers[0].Reaches, ",") != "wg1" {
		t.Fatalf("the traffic between peers: %+v", f.net.State.Servers[0])
	}
	if a := f.deviceLogin(office, alice, laptop, "203.0.113.5", machine); a.Status != 200 {
		t.Fatalf("the device after the restore: %+v", a)
	}

	// version 1 had no devices: the peers of a server with binding enroll at their next login
	old := f.sealed(adminID, func(c *backupContent) {
		c.Version, c.Devices, c.Settings.EnrollHours = 1, nil, 0
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", old, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if device := f.peerView(alice.ID).Device; device.State != DeviceWaiting || device.EnrollmentUntil != f.clock.now.Add(72*time.Hour).Unix() {
		t.Fatalf("after a backup of version 1: %+v", device)
	}
	if f.net.State.Servers[0].Peers[0].PublicKey.String() != alice.PublicKey {
		t.Fatal("after a backup of version 1, the configuration file connects")
	}
}

// snapDiff says which parts of two snapshots differ
func snapDiff(a, b configSnapshot) string {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	out := ""
	for index := 0; index < va.NumField(); index++ {
		if !reflect.DeepEqual(va.Field(index).Interface(), vb.Field(index).Interface()) {
			out += fmt.Sprintf("%s:\n  %+v\n  %+v\n", va.Type().Field(index).Name, va.Field(index).Interface(),
				vb.Field(index).Interface())
		}
	}
	return out
}
