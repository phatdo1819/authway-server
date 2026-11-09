package core

import (
	"errors"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

func refusedCode(t *testing.T, err error) string {
	t.Helper()
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("not refused: %v", err)
	}
	return refused.Code
}

func TestPasswordPolicy(t *testing.T) {
	policy := PasswordPolicy{MinLength: 10, RequireLower: true, RequireUpper: true, RequireDigit: true, RequireSymbol: true}
	for _, test := range []struct{ password, username, code string }{
		{"Short,1a", "bob", "too_short"},
		{"NOLOWER,1234", "bob", "needs_lower"},
		{"noupper,1234", "bob", "needs_upper"},
		{"NoDigits,abc", "bob", "needs_digit"},
		{"NoSymbol1234", "bob", "needs_symbol"},
		{"Xx,1alice2345", "alice", "contains_username"},
		{"Xx,1ALICE2345", "Alice", "contains_username"},
		// two letters are not a username to look for
		{"Xx,1al2345678", "al", ""},
		{"Mật,khẩu1234", "bob", ""},
		{"Secret,1234", "alice", ""},
	} {
		if code := policy.check(test.password, test.username, 0); code != test.code {
			t.Errorf("%q: %q, not %q", test.password, code, test.code)
		}
	}
	if code := policy.check("Secret,1234", "bob", AdminMinPassword); code != "too_short" {
		t.Errorf("an administrator with 11 characters: %q", code)
	}

	f := setup(t)
	admin := f.admin()
	if _, err := f.s.CreateUser(testActor, UserInput{Username: "bob", Password: "lowercase only"}); fields(t, err)["password"] != "needs_upper" {
		t.Fatalf("the default policy: %v", err)
	}
	minimum := 7
	if _, err := f.s.SetSettings(Actor{ID: admin}, SettingsInput{PasswordPolicy: &PasswordPolicy{MinLength: minimum}}); fields(t, err)["min_length"] != "invalid" {
		t.Fatalf("a policy below 8: %v", err)
	}
	settings, err := f.s.SetSettings(Actor{ID: admin}, SettingsInput{PasswordPolicy: &PasswordPolicy{MinLength: 14, RequireSymbol: true}})
	if err != nil || settings.PasswordPolicy.MinLength != 14 || settings.PasswordPolicy.RequireUpper || settings.PublicHost != "vpn.example.com" {
		t.Fatalf("saved: %+v %v", settings, err)
	}
	if _, err := f.s.CreateUser(testActor, UserInput{Username: "bob", Password: "only lowercase but long"}); err != nil {
		t.Fatalf("the new policy: %v", err)
	}
	if _, err := f.s.CreateUser(testActor, UserInput{Username: "carol", Password: "no symbol at all1"}); err != nil {
		t.Fatalf("a space is a symbol: %v", err)
	}
	if _, err := f.s.CreateUser(testActor, UserInput{Username: "dave", Password: "nosymbolatall12"}); fields(t, err)["password"] != "needs_symbol" {
		t.Fatalf("no symbol: %v", err)
	}
}

// admin returns the first administrator, with the password "Admin password 1"
func (f *fixture) admin() int64 {
	f.t.Helper()
	if _, err := f.s.EnsureAdmin("admin", "Admin password 1"); err != nil {
		f.t.Fatal(err)
	}
	admin, ok := f.s.AdminLogin("admin", "Admin password 1")
	if !ok {
		f.t.Fatal("no first administrator")
	}
	return admin.ID
}

func TestAdminRoles(t *testing.T) {
	f := setup(t)
	first := f.admin()
	if _, setup, _ := f.s.AdminAccess(first); setup != "" {
		t.Fatalf("a password given in the environment must change: %q", setup)
	}
	if _, err := f.s.CreateAdmin(Actor{ID: first}, AdminInput{Username: "bob", Role: "root", Password: "Blue river 1234"}); fields(t, err)["role"] != "invalid" {
		t.Fatalf("a role that doesn't exist: %v", err)
	}
	if _, err := f.s.CreateAdmin(Actor{ID: first}, AdminInput{Username: "bob", Role: store.RoleOperator, Password: "Bob,pass1"}); fields(t, err)["password"] != "too_short" {
		t.Fatalf("an administrator with less than 12 characters: %v", err)
	}
	bob, err := f.s.CreateAdmin(Actor{ID: first}, AdminInput{Username: "bob", FullName: "Bob", Role: store.RoleOperator, Password: "Blue river 1234"})
	if err != nil || !bob.MustChangePassword || bob.Role != store.RoleOperator {
		t.Fatalf("add: %+v %v", bob, err)
	}
	if _, err := f.s.CreateAdmin(Actor{ID: first}, AdminInput{Username: "BOB", Role: store.RoleViewer, Password: "Blue river 1234"}); fields(t, err)["username"] != "taken" {
		t.Fatalf("the same name: %v", err)
	}
	if _, setup, _ := f.s.AdminAccess(bob.ID); setup != SetupPassword {
		t.Fatalf("a password chosen by another: %q", setup)
	}
	if err := f.s.ChangeAdminPassword(Actor{ID: bob.ID}, "Blue river 1234", "Blue river 1234"); fields(t, err)["password"] != "same" {
		t.Fatalf("the same password again: %v", err)
	}
	if err := f.s.ChangeAdminPassword(Actor{ID: bob.ID}, "Blue river 1234", "Blue river 12345"); err != nil {
		t.Fatal(err)
	}
	if _, setup, _ := f.s.AdminAccess(bob.ID); setup != "" {
		t.Fatalf("after the change: %q", setup)
	}

	// the last administrator stays, and nobody changes their own role
	if _, err := f.s.UpdateAdmin(Actor{ID: first}, first, AdminInput{Role: store.RoleViewer}); fields(t, err)["role"] != "own_account" {
		t.Fatalf("its own role: %v", err)
	}
	if _, err := f.s.UpdateAdmin(Actor{ID: first}, first, AdminInput{Role: store.RoleAdmin, Disabled: true}); fields(t, err)["disabled"] != "own_account" {
		t.Fatalf("disables itself: %v", err)
	}
	if err := f.s.DeleteAdmin(Actor{ID: first}, first); refusedCode(t, err) != "own_account" {
		t.Fatalf("deletes itself: %v", err)
	}
	if _, err := f.s.UpdateAdmin(Actor{ID: first}, bob.ID, AdminInput{Role: store.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.UpdateAdmin(Actor{ID: bob.ID}, first, AdminInput{Role: store.RoleViewer}); err != nil {
		t.Fatalf("another administrator is left: %v", err)
	}
	if _, err := f.s.UpdateAdmin(Actor{ID: bob.ID}, first, AdminInput{Role: store.RoleAdmin, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.AdminAccess(first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a disabled administrator gets in: %v", err)
	}
	if err := f.s.DeleteAdmin(Actor{ID: first}, bob.ID); refusedCode(t, err) != "last_admin" {
		t.Fatalf("deletes the last active administrator: %v", err)
	}
	if err := f.s.ResetAdminPassword(Actor{ID: bob.ID}, first, "Reset password 1"); err != nil {
		t.Fatal(err)
	}
	if admin, setup, _ := f.s.AdminAccess(bob.ID); setup != "" || admin.Role != store.RoleAdmin {
		t.Fatalf("bob: %q %+v", setup, admin)
	}
	if err := f.s.DeleteAdmin(Actor{ID: bob.ID}, first); err != nil {
		t.Fatal(err)
	}
	list, _ := f.s.Admins()
	if len(list) != 1 || list[0].Username != "bob" {
		t.Fatalf("left: %+v", list)
	}
	events, _ := f.s.Events(50)
	kinds := map[string]int{}
	for _, event := range events {
		kinds[event.Kind]++
	}
	if kinds["admin_added"] != 1 || kinds["admin_changed"] != 3 || kinds["admin_deleted"] != 1 || kinds["admin_password_reset"] != 1 {
		t.Fatalf("events: %v", kinds)
	}
}

func TestAdminTOTP(t *testing.T) {
	f := setup(t)
	admin := f.admin()
	required := true
	if _, err := f.s.SetSettings(Actor{ID: admin}, SettingsInput{RequireAdminMFA: &required}); fields(t, err)["require_admin_mfa"] != "enroll_first" {
		t.Fatalf("required by an administrator without one: %v", err)
	}
	if err := f.s.ConfirmAdminTOTP(Actor{ID: admin}, "123456"); refusedCode(t, err) != "setup_expired" {
		t.Fatalf("a confirmation without a setup: %v", err)
	}
	// a session alone can't put an authenticator on the account: the password is asked
	if _, err := f.s.StartAdminTOTP(admin, "wrong password"); fields(t, err)["password"] != "wrong" {
		t.Fatalf("a setup without the password: %v", err)
	}
	setup, err := f.s.StartAdminTOTP(admin, "Admin password 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.ConfirmAdminTOTP(Actor{ID: admin}, "000000"); fields(t, err)["code"] != "wrong_code" {
		t.Fatalf("a wrong code: %v", err)
	}
	code, _ := totp.Code(setup.Secret, uint64(f.clock.now.Unix()/30))
	if err := f.s.ConfirmAdminTOTP(Actor{ID: admin}, code); err != nil {
		t.Fatal(err)
	}
	if f.s.CheckAdminCode(admin, code) {
		t.Fatal("the code of the setup works again at login")
	}
	f.clock.advance(30 * time.Second)
	code, _ = totp.Code(setup.Secret, uint64(f.clock.now.Unix()/30))
	if !f.s.CheckAdminCode(admin, code) || f.s.CheckAdminCode(admin, code) {
		t.Fatal("a code works not once")
	}
	if _, err := f.s.SetSettings(Actor{ID: admin}, SettingsInput{RequireAdminMFA: &required}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.RemoveOwnAdminTOTP(Actor{ID: admin}, "Admin password 1"); refusedCode(t, err) != "mfa_required" {
		t.Fatalf("removed while required: %v", err)
	}
	bob, err := f.s.CreateAdmin(Actor{ID: admin}, AdminInput{Username: "bob", Role: store.RoleViewer, Password: "Blue river 1234"})
	if err != nil {
		t.Fatal(err)
	}
	f.s.ChangeAdminPassword(Actor{ID: bob.ID}, "Blue river 1234", "Blue river 12345")
	if _, setup, _ := f.s.AdminAccess(bob.ID); setup != SetupMFA {
		t.Fatalf("without an authenticator while required: %q", setup)
	}
	if err := f.s.RemoveAdminTOTP(Actor{ID: admin}, admin); refusedCode(t, err) != "own_account" {
		t.Fatalf("removes its own one the other way: %v", err)
	}
	if err := f.s.RemoveAdminTOTP(Actor{ID: bob.ID}, admin); err != nil {
		t.Fatal(err)
	}
	if _, setup, _ := f.s.AdminAccess(admin); setup != SetupMFA {
		t.Fatalf("after the removal: %q", setup)
	}
	// a setup is good for 10 minutes
	if _, err := f.s.StartAdminTOTP(admin, "Admin password 1"); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(11 * time.Minute)
	if err := f.s.ConfirmAdminTOTP(Actor{ID: admin}, "123456"); refusedCode(t, err) != "setup_expired" {
		t.Fatalf("an old setup: %v", err)
	}
}

// The failed logins keep a username only when it's the one of an administrator: what's typed can be a password, and
// every role reads the events.
func TestAdminLoginFailedEvent(t *testing.T) {
	f := setup(t)
	f.admin()
	if known := f.s.AdminLoginFailed("Admin password 1", "192.0.2.1", "wrong username or password"); known != "" {
		t.Fatalf("an unknown username is kept: %q", known)
	}
	if known := f.s.AdminLoginFailed(" ADMIN ", "192.0.2.1", "wrong username or password"); known != "admin" {
		t.Fatalf("the username of an administrator: %q", known)
	}
	events, _ := f.s.Events(10)
	if len(events) != 2 || events[0].Username != "admin" || events[1].Username != "" || events[1].Detail != "unknown username" {
		t.Fatalf("events: %+v", events)
	}
	for _, event := range events {
		if event.Detail == "Admin password 1" || event.Username == "Admin password 1" {
			t.Fatalf("the typed text is in the events: %+v", event)
		}
	}
}
