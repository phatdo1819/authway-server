package core

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/directory"
	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

// fakeDirectory is Active Directory in memory: its members, their passwords by ID
type fakeDirectory struct {
	mu        sync.Mutex
	members   []directory.User
	passwords map[string]string
	// returned by every call when set: a directory that doesn't answer
	err error
	// the passwords asked
	checks int
	// the accounts whose password has to be changed
	expired map[string]bool
	// what a sync reads besides the members
	passwordExpires time.Time
	unanswered      []string
}

func (d *fakeDirectory) Members(cfg directory.Config) (directory.Group, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return directory.Group{}, d.err
	}
	return directory.Group{Members: append([]directory.User{}, d.members...), PasswordExpires: d.passwordExpires,
		Unanswered: d.unanswered}, nil
}

func (d *fakeDirectory) Authenticate(cfg directory.Config, id, password string) (directory.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.checks++
	if d.err != nil {
		return directory.User{}, d.err
	}
	for _, member := range d.members {
		switch {
		case member.ID != id:
		case member.Disabled:
			return member, directory.ErrDisabled
		case d.passwords[id] != password:
			return member, directory.ErrWrongPassword
		case d.expired[id]:
			return member, directory.ErrPasswordExpired
		default:
			return member, nil
		}
	}
	return directory.User{}, directory.ErrNotMember
}

func (d *fakeDirectory) set(members ...directory.User) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.members = members
}

const (
	aliceID = "00112233445566778899aabbccddee01"
	bobID   = "00112233445566778899aabbccddee02"
	carolID = "00112233445566778899aabbccddee03"
)

// withDirectory gives the service a fake directory, turned on with valid settings, and the administrator who set them
func (f *fixture) withDirectory(members ...directory.User) (*fakeDirectory, Actor) {
	f.t.Helper()
	fake := &fakeDirectory{members: members, passwords: map[string]string{aliceID: "Secret,1234", bobID: "Secret,1234", carolID: "Secret,1234"}}
	f.s.opts.Directory = fake
	by := Actor{ID: f.admin(), Username: "admin"}
	if _, err := f.s.SetDirectory(by, directoryInput()); err != nil {
		f.t.Fatal(err)
	}
	return fake, by
}

func directoryInput() DirectorySettings {
	return DirectorySettings{
		Enabled: true, Servers: []string{"dc1.example.com"}, BindUser: "svc-authway@example.com", BindPassword: "Service pass 1",
		BaseDN: "DC=example,DC=com", Group: "CN=VPN Users,OU=Groups,DC=example,DC=com",
	}
}

func (f *fixture) sync() DirectoryStatus {
	f.t.Helper()
	status, err := f.s.SyncDirectory(Actor{Username: DirectoryActor}, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return status
}

func (f *fixture) userNamed(name string) *store.User {
	f.t.Helper()
	user, err := f.db.Q().UserByName(name)
	if err != nil {
		f.t.Fatalf("no user %s: %v", name, err)
	}
	return user
}

func (f *fixture) userViewNamed(name string) *UserView {
	f.t.Helper()
	view := f.userView(f.userNamed(name).ID)
	return &view
}

// stalledDirectory waits, at every call, until release closes: a directory that doesn't answer
type stalledDirectory struct {
	*fakeDirectory
	entered chan string
	release chan struct{}
	members atomic.Int32
}

func (d *stalledDirectory) Members(cfg directory.Config) (directory.Group, error) {
	d.members.Add(1)
	d.entered <- "members"
	<-d.release
	return d.fakeDirectory.Members(cfg)
}

func (d *stalledDirectory) Authenticate(cfg directory.Config, id, password string) (directory.User, error) {
	d.entered <- "login"
	<-d.release
	return d.fakeDirectory.Authenticate(cfg, id, password)
}

// A directory that doesn't answer slows down only what asks it, the logins of its users and the sync: the web UI, the
// sessions and the logins of the local users go on. Sync now during a sync answers with that sync.
func TestDirectoryDoesntBlock(t *testing.T) {
	f := setup(t)
	fake, _ := f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
	f.sync()
	server := f.server(store.AuthPassword)
	alice := f.peer(server, f.userViewNamed("alice"))
	bob := f.peer(server, f.user("bob"))
	stalled := &stalledDirectory{fakeDirectory: fake, entered: make(chan string, 8), release: make(chan struct{})}
	f.s.opts.Directory = stalled
	var released sync.Once
	free := func() { released.Do(func() { close(stalled.release) }) }
	defer free()

	f.handshake(alice, "203.0.113.5")
	logged := make(chan Answer, 1)
	go func() {
		logged <- f.s.Login(netip.MustParseAddr(alice.Address), "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234"})
	}()
	synced := make(chan DirectoryStatus, 2)
	go func() {
		status, _ := f.s.SyncDirectory(Actor{Username: DirectoryActor}, 0)
		synced <- status
	}()
	for range 2 {
		select {
		case <-stalled.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the login and the sync don't reach the directory")
		}
	}

	// meanwhile, everything else answers at once
	quick := func(name string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			fn()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waits for the directory", name)
		}
	}
	quick("the servers", func() { f.s.Servers() })
	quick("the status", func() { f.s.Status() })
	quick("the users", func() { f.s.Users() })
	quick("the settings of the directory", func() { f.s.Directory() })
	quick("a tick", f.s.Tick)
	quick("the health check", func() {
		if failing := f.s.Health(); len(failing) != 0 {
			t.Errorf("unhealthy: %v", failing)
		}
	})
	f.handshake(bob, "198.51.100.9")
	quick("a local user's login", func() {
		if answer := f.s.Login(netip.MustParseAddr(bob.Address), "10.8.0.1", LoginRequest{Username: "bob", Password: "Secret,1234"}); answer.Status != 200 {
			t.Errorf("bob: %+v", answer)
		}
	})

	// Sync now during the sync waits for it, and doesn't ask the directory again
	go func() {
		status, _ := f.s.SyncDirectory(Actor{Username: DirectoryActor}, 0)
		synced <- status
	}()
	time.Sleep(200 * time.Millisecond)
	free()
	if answer := <-logged; answer.Status != 200 {
		t.Errorf("alice, once the directory answers: %+v", answer)
	}
	first, second := <-synced, <-synced
	if first.Error != "" || first.At == 0 || second.At != first.At || second.Members != first.Members || stalled.members.Load() != 1 {
		t.Errorf("syncs: %+v %+v, %d reads of the group", first, second, stalled.members.Load())
	}
}

// The settings are checked as the form sends them; the password of the service account never goes back.
func TestDirectorySettings(t *testing.T) {
	f := setup(t)
	f.s.opts.Directory = &fakeDirectory{}
	by := Actor{ID: f.admin(), Username: "admin"}
	view := f.s.Directory()
	if view.Enabled || view.Security != directory.SecurityLDAPS || view.UsernameAttribute != directory.AttributeAccountName ||
		view.SyncMinutes != DefaultSyncMinutes {
		t.Fatalf("defaults: %+v", view)
	}
	_, err := f.s.SetDirectory(by, DirectorySettings{Enabled: true})
	for _, field := range []string{"servers", "bind_user", "bind_password", "base_dn", "group"} {
		if fieldCode(t, err, field) != "required" {
			t.Errorf("%s: %v", field, err)
		}
	}
	bad := directoryInput()
	bad.Servers = []string{"ldaps://dc1"}
	bad.Security = "plain"
	bad.Group = "VPN Users"
	bad.CACertificates = "not a certificate"
	bad.SyncMinutes = 1
	_, err = f.s.SetDirectory(by, bad)
	for _, field := range []string{"servers", "security", "group", "ca_certificates", "sync_minutes"} {
		if fieldCode(t, err, field) != "invalid" {
			t.Errorf("%s: %v", field, err)
		}
	}
	view, err = f.s.SetDirectory(by, directoryInput())
	if err != nil || !view.Enabled || !view.BindPasswordSet || view.BindPassword != "" {
		t.Fatalf("saved: %+v %v", view, err)
	}
	// an empty password keeps the one saved
	input := directoryInput()
	input.BindPassword = ""
	input.SyncMinutes = 30
	if view, err = f.s.SetDirectory(by, input); err != nil || !view.BindPasswordSet || view.SyncMinutes != 30 {
		t.Fatalf("without the password: %+v %v", view, err)
	}
	f.s.mu.Lock()
	saved := f.s.directorySettingsLocked().BindPassword
	f.s.mu.Unlock()
	if saved != "Service pass 1" {
		t.Errorf("the password saved: %q", saved)
	}
	event := f.lastEvent("settings_changed")
	if !strings.Contains(event.Detail, "Active Directory: sync every: 15 min → 30 min") || strings.Contains(event.Detail, "Service pass") {
		t.Errorf("event: %+v", event)
	}
}

func fieldCode(t *testing.T, err error, field string) string {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		return ""
	}
	return validation.Fields[field]
}

// The members of the group become users, follow their account, and are disabled when they leave the group.
func TestDirectorySync(t *testing.T) {
	f := setup(t)
	fake, _ := f.withDirectory(
		directory.User{ID: aliceID, Username: "alice", FullName: "Alice Liddell"},
		directory.User{ID: bobID, Username: "bob", FullName: "Bob", Disabled: true},
		directory.User{ID: carolID, Username: "carol smith"},
	)
	status := f.sync()
	if status.Error != "" || status.Members != 3 || status.Added != 2 || len(status.Skipped) != 1 ||
		status.Skipped[0] != (DirectorySkip{Username: "carol smith", Reason: "invalid_username"}) {
		t.Fatalf("first sync: %+v", status)
	}
	alice, bob := f.userNamed("alice"), f.userNamed("bob")
	if alice.DirectoryID != aliceID || alice.PasswordHash != "" || alice.FullName != "Alice Liddell" || alice.Disabled ||
		bob.DirectoryID != bobID || !bob.Disabled || alice.UpdatedBy != DirectoryActor {
		t.Fatalf("users: %+v %+v", alice, bob)
	}
	if view := f.userViewNamed("alice"); !view.Directory {
		t.Errorf("view: %+v", view)
	}
	if event := f.lastEvent("user_added"); event.By != DirectoryActor || event.Detail != "from Active Directory, disabled" {
		t.Errorf("event: %+v", event)
	}
	// nothing changed: nothing saved
	if status := f.sync(); status.Added+status.Updated+status.Disabled != 0 {
		t.Fatalf("again: %+v", status)
	}

	// alice renamed, bob enabled
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.userViewNamed("alice"))
	if answer := f.login(peer, "203.0.113.5"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	fake.set(directory.User{ID: aliceID, Username: "alice.l", FullName: "Alice Liddell"}, directory.User{ID: bobID, Username: "bob"})
	status = f.sync()
	if status.Updated != 2 || f.userNamed("alice.l").ID != alice.ID || f.userNamed("bob").Disabled {
		t.Fatalf("renamed: %+v", status)
	}
	if f.session(peer.ID) == nil {
		t.Error("a rename ended the session")
	}

	// alice out of the group: disabled, logged out
	fake.set(directory.User{ID: bobID, Username: "bob"})
	if status = f.sync(); status.Disabled != 1 || !f.userNamed("alice.l").Disabled || f.session(peer.ID) != nil {
		t.Fatalf("out of the group: %+v", status)
	}
	if event := f.lastEvent("user_changed"); event.Username != "alice.l" || event.Detail != "disabled: no longer in the Active Directory group" {
		t.Errorf("event: %+v", event)
	}

	// an empty group is a mistake rather than everybody gone
	fake.set()
	if status = f.sync(); status.Error == "" || f.userNamed("bob").Disabled {
		t.Fatalf("empty group: %+v", status)
	}
	// a directory that doesn't answer changes nothing
	fake.err = errors.New("can't connect to the directory: dc1.example.com:636: i/o timeout")
	if status = f.sync(); !strings.Contains(status.Error, "i/o timeout") || f.s.Directory().Status.Error != status.Error {
		t.Fatalf("no answer: %+v", status)
	}
}

// A local user with the username of a member is left alone, unless the settings link the local users: then the
// directory checks its password, and its peers and authenticator stay.
func TestDirectoryLocalUsers(t *testing.T) {
	f := setup(t)
	server := f.server(store.AuthPassword)
	local := f.user("alice")
	peer := f.peer(server, local)
	if answer := f.login(peer, "203.0.113.5"); answer.Status != 200 {
		t.Fatalf("local login: %+v", answer)
	}
	_, by := f.withDirectory(directory.User{ID: aliceID, Username: "Alice", FullName: "Alice Liddell"})
	if status := f.sync(); len(status.Skipped) != 1 || status.Skipped[0].Reason != "local_user" || f.userNamed("alice").FromDirectory() {
		t.Fatalf("not linked: %+v", status)
	}
	input := directoryInput()
	input.LinkLocalUsers = true
	if _, err := f.s.SetDirectory(by, input); err != nil {
		t.Fatal(err)
	}
	status := f.sync()
	user := f.userNamed("alice")
	if status.Updated != 1 || user.ID != local.ID || user.DirectoryID != aliceID || user.PasswordHash != "" || user.Username != "Alice" {
		t.Fatalf("linked: %+v %+v", status, user)
	}
	// the password of before no longer counts: logged out, and the directory's password works
	if f.session(peer.ID) != nil {
		t.Error("still logged in")
	}
	if answer := f.login(peer, "203.0.113.5"); answer.Status != 200 {
		t.Fatalf("login with the directory: %+v", answer)
	}

	// another account of the directory with the same username: left out
	f.s.opts.Directory.(*fakeDirectory).set(directory.User{ID: bobID, Username: "alice"})
	if status := f.sync(); len(status.Skipped) != 1 || status.Skipped[0].Reason != "other_account" {
		t.Fatalf("another account: %+v", status)
	}
}

// The directory checks the password of its users; Authway Server keeps counting the failures, never asks it for an
// empty password, and doesn't count the logins it can't check.
func TestDirectoryLogin(t *testing.T) {
	f := setup(t)
	fake, by := f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
	f.sync()
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.userViewNamed("alice"))
	login := func(username, password, from string) Answer {
		f.handshake(peer, from)
		return f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: username, Password: password})
	}
	for _, name := range []string{"alice", "ALICE", `EXAMPLE\alice`, "alice@example.com"} {
		if answer := login(name, "Secret,1234", "203.0.113.5"); answer.Status != 200 {
			t.Fatalf("%s: %+v", name, answer)
		}
	}
	checks := fake.checks
	if answer := login("alice", "", "203.0.113.5"); answer.Status != 401 || fake.checks != checks {
		t.Fatalf("empty password: %+v, %d checks", answer, fake.checks-checks)
	}
	if answer := login("bob", "Secret,1234", "203.0.113.5"); answer.Status != 401 || fake.checks != checks {
		t.Fatalf("another username: %+v", answer)
	}
	if answer := login("alice", "wrong", "203.0.113.5"); answer.Status != 401 || answer.Body["error"] != "invalid_credentials" {
		t.Fatalf("wrong password: %+v", answer)
	}

	// a directory that doesn't answer: unavailable, and no failure counted
	fake.err = errors.New("can't connect to the directory: connection refused")
	for range MaxFailures + 1 {
		if answer := login("alice", "Secret,1234", "198.51.100.1"); answer.Status != 503 || answer.Body["error"] != "unavailable" {
			t.Fatalf("no directory: %+v", answer)
		}
	}
	fake.err = nil

	// disabled in the directory since the latest sync: refused, the event says why
	fake.set(directory.User{ID: aliceID, Username: "alice", Disabled: true})
	if answer := login("alice", "Secret,1234", "198.51.100.1"); answer.Status != 401 {
		t.Fatalf("disabled: %+v", answer)
	}
	if events := f.vpnEvents(1); len(events) != 1 || events[0].Kind != "login_failed" || events[0].Detail != "disabled in Active Directory" {
		t.Fatalf("event: %+v", events)
	}
	fake.set(directory.User{ID: aliceID, Username: "alice"})

	// turned off: nobody of the directory logs in, and it doesn't count either
	input := directoryInput()
	input.Enabled = false
	if _, err := f.s.SetDirectory(by, input); err != nil {
		t.Fatal(err)
	}
	if answer := login("alice", "Secret,1234", "198.51.100.1"); answer.Status != 503 {
		t.Fatalf("turned off: %+v", answer)
	}
}

// A copy of a configuration from other networks can't lock the account out in the directory: after 5 failures from
// IPs other than the one of the latest login, Authway Server stops asking.
func TestDirectoryLockout(t *testing.T) {
	f := setup(t)
	fake, _ := f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
	f.sync()
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.userViewNamed("alice"))
	if answer := f.login(peer, "203.0.113.5"); answer.Status != 200 {
		t.Fatalf("login: %+v", answer)
	}
	login := func(from string) Answer {
		f.handshake(peer, from)
		return f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: "alice", Password: "guess"})
	}
	for index := range DirectoryPeerFailures {
		if answer := login("198.51.100." + string(rune('1'+index))); answer.Status != 401 {
			t.Fatalf("guess %d: %+v", index, answer)
		}
	}
	checks := fake.checks
	if answer := login("192.0.2.77"); answer.Status != 429 || fake.checks != checks {
		t.Fatalf("after %d guesses from other networks: %+v", DirectoryPeerFailures, answer)
	}
	// the IP of the latest login still can
	if answer := f.login(peer, "203.0.113.5"); answer.Status != 200 {
		t.Fatalf("from the IP of the latest login: %+v", answer)
	}
}

// What comes from the directory can't be changed here: the next sync would undo it. The authenticator can.
func TestDirectoryUserEdits(t *testing.T) {
	f := setup(t)
	f.withDirectory(directory.User{ID: aliceID, Username: "alice", FullName: "Alice"})
	f.sync()
	alice := f.userNamed("alice")
	for field, input := range map[string]UserInput{
		"username":  {Username: "alice2", FullName: "Alice"},
		"full_name": {Username: "alice", FullName: "Someone else"},
		"disabled":  {Username: "alice", FullName: "Alice", Disabled: true},
		"password":  {Username: "alice", FullName: "Alice", Password: "Another,1234"},
	} {
		if _, err := f.s.UpdateUser(testActor, alice.ID, input); fieldCode(t, err, field) != "directory" {
			t.Errorf("%s: %v", field, err)
		}
	}
	if _, err := f.s.UpdateUser(testActor, alice.ID, UserInput{Username: "alice", FullName: "Alice"}); err != nil {
		t.Errorf("saved unchanged: %v", err)
	}
	if _, err := f.s.SetupTOTP(testActor, alice.ID); err != nil {
		t.Errorf("authenticator: %v", err)
	}
}

// A backup has the settings of the directory, with the password of the service account, and its users without a
// password hash.
func TestDirectoryBackup(t *testing.T) {
	f := setup(t)
	f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
	f.sync()
	admin, err := f.s.Admin(f.admin())
	if err != nil {
		t.Fatal(err)
	}
	data := f.sealed(admin.ID, func(*backupContent) {})
	f.s.opts.Directory.(*fakeDirectory).set()
	if _, err := f.s.Restore(as(admin, testActor), "Admin password 1", data, testPassphrase); err != nil {
		t.Fatal(err)
	}
	user := f.userNamed("alice")
	view := f.s.Directory()
	if user.DirectoryID != aliceID || user.PasswordHash != "" || !view.Enabled || !view.BindPasswordSet {
		t.Fatalf("restored: %+v %+v", user, view)
	}

	// a user of the directory with a password hash, or a local one without, isn't a valid backup
	hash, _ := secret.HashPassword("Secret,1234")
	for name, change := range map[string]func(*backupContent){
		"hash":    func(c *backupContent) { c.Users[0].PasswordHash = hash },
		"no hash": func(c *backupContent) { c.Users[0].DirectoryID = "" },
		"id":      func(c *backupContent) { c.Users[0].DirectoryID = "not hex" },
		"settings": func(c *backupContent) {
			c.Settings.Directory.Group = "VPN Users"
		},
	} {
		if _, err := f.s.CheckBackup(as(admin, testActor), f.sealed(admin.ID, change), testPassphrase); fieldCode(t, err, "backup") != "invalid_content" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A username typed at a login: the user's, or as Windows writes it; for a user principal name, the name before the @
// is enough.
func TestSameUser(t *testing.T) {
	local := &store.User{Username: "alice"}
	logon := &store.User{Username: "alice", DirectoryID: aliceID}
	principal := &store.User{Username: "alice@example.com", DirectoryID: aliceID}
	for _, test := range []struct {
		typed string
		user  *store.User
		same  bool
	}{
		{"alice", local, true},
		{" ALICE ", local, true},
		{`EXAMPLE\alice`, local, false},
		{"alice@example.com", local, false},
		{"alice", logon, true},
		{`EXAMPLE\alice`, logon, true},
		{"alice@example.com", logon, true},
		{"alice@other.example", logon, true},
		{"bob", logon, false},
		{`EXAMPLE\bob`, logon, false},
		{"alice@example.com", principal, true},
		{"Alice", principal, true},
		{`EXAMPLE\alice`, principal, true},
		{`EXAMPLE\alice@example.com`, principal, true},
		{"alice@other.example", principal, false},
		{"alic", principal, false},
		{"@example.com", principal, false},
		{"", principal, false},
	} {
		if got := sameUser(test.typed, test.user); got != test.same {
			t.Errorf("%q for %s (directory %v): %v", test.typed, test.user.Username, test.user.FromDirectory(), got)
		}
	}
}

// A user whose password Active Directory says has to be changed is told so, once the code is right too: without it,
// the answer is the one of a wrong password.
func TestDirectoryPasswordExpired(t *testing.T) {
	for _, mode := range []string{store.AuthPassword, store.AuthPasswordOTP} {
		f := setup(t)
		fake, _ := f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
		f.sync()
		fake.expired = map[string]bool{aliceID: true}
		alice := f.userViewNamed("alice")
		code := ""
		if mode == store.AuthPasswordOTP {
			setup, err := f.s.SetupTOTP(testActor, alice.ID)
			if err != nil {
				t.Fatal(err)
			}
			code, _ = totp.Code(setup.Secret, uint64(f.clock.now.Unix())/totp.Period)
		}
		peer := f.peer(f.server(mode), alice)
		login := func(password, code string) Answer {
			f.handshake(peer, "203.0.113.5")
			return f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: "alice", Password: password, OTP: code})
		}
		if answer := login("wrong", code); answer.Body["error"] != "invalid_credentials" {
			t.Fatalf("%s, a wrong password: %+v", mode, answer)
		}
		if mode == store.AuthPasswordOTP {
			if answer := login("Secret,1234", "000000"); answer.Body["error"] != "invalid_credentials" {
				t.Fatalf("%s, a wrong code: %+v", mode, answer)
			}
		}
		if answer := login("Secret,1234", code); answer.Status != 401 || answer.Body["error"] != "password_expired" {
			t.Fatalf("%s: %+v", mode, answer)
		}
		if events := f.vpnEvents(1); len(events) != 1 || events[0].Detail != "password expired in Active Directory" {
			t.Errorf("%s, event: %+v", mode, events)
		}
		// changed: the same code works, it wasn't used
		fake.expired = nil
		if answer := login("Secret,1234", code); answer.Status != 200 {
			t.Fatalf("%s, changed: %+v", mode, answer)
		}
	}
}

// A user principal name logs in with the name before the @ too.
func TestDirectoryPrincipalNames(t *testing.T) {
	f := setup(t)
	_, by := f.withDirectory(directory.User{ID: aliceID, Username: "alice@example.com"})
	input := directoryInput()
	input.UsernameAttribute = directory.AttributePrincipal
	if _, err := f.s.SetDirectory(by, input); err != nil {
		t.Fatal(err)
	}
	f.sync()
	server := f.server(store.AuthPassword)
	peer := f.peer(server, f.userViewNamed("alice@example.com"))
	for name, status := range map[string]int{"alice": 200, `EXAMPLE\alice`: 200, "alice@example.com": 200, "alice@other.example": 401} {
		f.handshake(peer, "203.0.113.5")
		if answer := f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1", LoginRequest{Username: name, Password: "Secret,1234"}); answer.Status != status {
			t.Errorf("%s: %+v", name, answer)
		}
	}
}

// directoryUsers are n members of the group, user1 to usern
func directoryUsers(n int) []directory.User {
	var members []directory.User
	for index := 1; index <= n; index++ {
		members = append(members, directory.User{ID: fmt.Sprintf("00112233445566778899aabbccdd%04x", index), Username: fmt.Sprintf("user%d", index)})
	}
	return members
}

// A sync that would disable more than 5 users, and more than a quarter of them, at once disables none until an
// administrator confirms how many.
func TestDirectoryHold(t *testing.T) {
	f := setup(t)
	members := directoryUsers(20)
	fake, by := f.withDirectory(members...)
	f.sync()

	// 5 leave: below the limit
	fake.set(members[5:]...)
	if status := f.sync(); status.Disabled != 5 || len(status.Held) != 0 {
		t.Fatalf("5 leave: %+v", status)
	}
	// 4 more leave and 2 are disabled: 6 of 15, more than a quarter
	rest := append([]directory.User{}, members[9:]...)
	rest[0].Disabled, rest[1].Disabled = true, true
	fake.set(rest...)
	status := f.sync()
	want := []string{"user10", "user11", "user6", "user7", "user8", "user9"}
	if status.Disabled != 0 || strings.Join(status.Held, ",") != strings.Join(want, ",") || f.userNamed("user6").Disabled || f.userNamed("user10").Disabled {
		t.Fatalf("6 at once: %+v", status)
	}
	if event := f.lastEvent("directory_held"); event.By != DirectoryActor || !strings.Contains(event.Detail, "would disable 6 users at once") {
		t.Errorf("event: %+v", event)
	}
	if current, _ := f.s.Status(); current.Directory == nil || current.Directory.Held != 6 {
		t.Errorf("warning: %+v", current.Directory)
	}
	// the other changes go on
	rest[2].Username = "user12b"
	fake.set(rest...)
	if status := f.sync(); status.Updated != 1 || len(status.Held) != 6 || f.userNamed("user12b") == nil {
		t.Fatalf("a rename while held: %+v", status)
	}
	if events := f.webEvents(); countKind(events, "directory_held") != 1 {
		t.Errorf("the same users held twice: %d events", countKind(events, "directory_held"))
	}
	// confirmed for fewer: held again; for as many: disabled, the administrator's confirmation in the events
	if status, _ := f.s.SyncDirectory(by, 5); status.Disabled != 0 || len(status.Held) != 6 {
		t.Fatalf("confirmed for 5: %+v", status)
	}
	if status, _ := f.s.SyncDirectory(by, 6); status.Disabled != 6 || len(status.Held) != 0 || !f.userNamed("user6").Disabled || !f.userNamed("user10").Disabled {
		t.Fatalf("confirmed for 6: %+v", status)
	}
	if event := f.lastEvent("directory_confirmed"); event.By != "admin" || event.Detail != "disabled 6 users that a sync had held" {
		t.Errorf("event: %+v", event)
	}
	if current, _ := f.s.Status(); current.Directory != nil {
		t.Errorf("warning after: %+v", current.Directory)
	}

	// many users: 6 of 30 is less than a quarter
	f2 := setup(t)
	many := directoryUsers(30)
	fake2, _ := f2.withDirectory(many...)
	f2.sync()
	fake2.set(many[6:]...)
	if status := f2.sync(); status.Disabled != 6 || len(status.Held) != 0 {
		t.Fatalf("6 of 30: %+v", status)
	}
}

func countKind(events []EventView, kind string) int {
	count := 0
	for _, event := range events {
		if event.Kind == kind {
			count++
		}
	}
	return count
}

// The warning at the top of the web UI: syncs that fail twice in a row, and the password of the service account that
// expires within 14 days. The events say when the syncs start failing and work again.
func TestDirectoryAlerts(t *testing.T) {
	f := setup(t)
	fake, _ := f.withDirectory(directory.User{ID: aliceID, Username: "alice"})
	f.sync()
	alert := func() *DirectoryAlert {
		status, err := f.s.Status()
		if err != nil {
			t.Fatal(err)
		}
		return status.Directory
	}
	if got := alert(); got != nil {
		t.Fatalf("all well: %+v", got)
	}
	fake.err = errors.New("can't connect to the directory: dc1.example.com:636: i/o timeout")
	first := f.sync()
	if got := alert(); got != nil || first.Failures != 1 {
		t.Fatalf("one failure: %+v %+v", got, first)
	}
	f.clock.now = f.clock.now.Add(5 * time.Minute)
	second := f.sync()
	if got := alert(); got == nil || got.Error != second.Error || got.FailingSince != first.At || second.Failures != 2 {
		t.Fatalf("two failures: %+v %+v", got, second)
	}
	if events := f.webEvents(); countKind(events, "directory_failed") != 1 {
		t.Errorf("failed events: %d", countKind(events, "directory_failed"))
	}
	fake.err = nil
	if status := f.sync(); status.Failures != 0 || alert() != nil {
		t.Fatalf("working again: %+v %+v", status, alert())
	}
	if event := f.lastEvent("directory_restored"); event.Detail != "after 2 failed syncs" || event.By != DirectoryActor {
		t.Errorf("event: %+v", event)
	}

	// the password of the service account: a warning from 14 days before; a sync that fails keeps what was read
	fake.passwordExpires = f.clock.now.Add(20 * 24 * time.Hour)
	if status := f.sync(); status.PasswordExpires != fake.passwordExpires.Unix() || alert() != nil {
		t.Fatalf("in 20 days: %+v %+v", status, alert())
	}
	fake.passwordExpires = f.clock.now.Add(10 * 24 * time.Hour)
	f.sync()
	fake.err = errors.New("no answer")
	f.sync()
	if got := alert(); got == nil || got.PasswordExpires != fake.passwordExpires.Unix() || got.Error != "" {
		t.Fatalf("in 10 days: %+v", got)
	}
	fake.err = nil

	// the domain controllers that didn't answer: in the status, for the System page
	fake.unanswered = []string{"dc1.example.com:636: i/o timeout"}
	if status := f.sync(); len(status.Unanswered) != 1 || len(f.s.Directory().Status.Unanswered) != 1 {
		t.Fatalf("unanswered: %+v", status)
	}
	// turned off: no warning
	input := directoryInput()
	input.Enabled = false
	if _, err := f.s.SetDirectory(Actor{ID: f.admin(), Username: "admin"}, input); err != nil {
		t.Fatal(err)
	}
	if got := alert(); got != nil {
		t.Errorf("turned off: %+v", got)
	}
}
