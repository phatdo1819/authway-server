package core

import (
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/totp"
)

// adminWithTOTP is the first administrator, with an authenticator.
func (f *fixture) adminWithTOTP() int64 {
	f.t.Helper()
	id := f.admin()
	setup, err := f.s.StartAdminTOTP(id, "Admin password 1")
	if err != nil {
		f.t.Fatal(err)
	}
	code, _ := totp.Code(setup.Secret, uint64(f.clock.now.Unix()/30))
	if err := f.s.ConfirmAdminTOTP(Actor{ID: id}, code); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) adminDevices(id int64) int {
	f.t.Helper()
	count, err := f.db.Q().CountAdminDevices(id)
	if err != nil {
		f.t.Fatal(err)
	}
	return count
}

// A remembered browser logs in without a code for the days of the setting, until the password or the authenticator
// changes.
func TestRememberAdminDevice(t *testing.T) {
	f := setup(t)
	plain := f.admin()
	if token, _ := f.s.RememberAdminDevice(plain, "198.51.100.1"); token != "" {
		t.Fatal("remembered without an authenticator")
	}
	id := f.adminWithTOTP()
	token, life := f.s.RememberAdminDevice(id, "198.51.100.1")
	if token == "" || life != DefaultAdminRememberDays*24*time.Hour {
		t.Fatalf("remember: %q %v", token, life)
	}
	if !f.s.RememberedAdmin(id, token, "198.51.100.2") {
		t.Fatal("a remembered device refused")
	}
	if f.s.RememberedAdmin(id+1, token, "198.51.100.2") || f.s.RememberedAdmin(id, "made-up", "198.51.100.2") ||
		f.s.RememberedAdmin(id, "", "198.51.100.2") {
		t.Fatal("another administrator or a made-up token accepted")
	}
	if device, _ := f.db.Q().AdminDevice(secret.Fingerprint(token)); device.LastUsedFrom != "198.51.100.2" {
		t.Fatalf("last use: %+v", device)
	}
	// the days run out
	f.clock.advance(DefaultAdminRememberDays*24*time.Hour - time.Minute)
	if !f.s.RememberedAdmin(id, token, "198.51.100.2") {
		t.Fatal("refused before its days ran out")
	}
	f.clock.advance(time.Minute)
	if f.s.RememberedAdmin(id, token, "198.51.100.2") || f.adminDevices(id) != 0 {
		t.Fatal("accepted after its days ran out")
	}

	// a shorter setting applies to the devices already remembered
	token, _ = f.s.RememberAdminDevice(id, "198.51.100.1")
	one := 1
	if _, err := f.s.SetSettings(Actor{ID: id}, SettingsInput{AdminRememberDays: &one}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(25 * time.Hour)
	if f.s.RememberedAdmin(id, token, "198.51.100.1") {
		t.Fatal("accepted after the setting got shorter")
	}
	// off: nothing is remembered
	off := 0
	if settings, err := f.s.SetSettings(Actor{ID: id}, SettingsInput{AdminRememberDays: &off}); err != nil || settings.AdminRememberDays != 0 {
		t.Fatalf("off: %+v %v", settings, err)
	}
	if token, _ := f.s.RememberAdminDevice(id, "198.51.100.1"); token != "" {
		t.Fatal("remembered while off")
	}
	for _, days := range []int{-1, MaxAdminRememberDays + 1} {
		if _, err := f.s.SetSettings(Actor{ID: id}, SettingsInput{AdminRememberDays: &days}); fields(t, err)["admin_remember_days"] != "invalid" {
			t.Fatalf("%d days: %v", days, err)
		}
	}
	thirty := 30
	if _, err := f.s.SetSettings(Actor{ID: id}, SettingsInput{AdminRememberDays: &thirty}); err != nil {
		t.Fatal(err)
	}

	// a new password ends it
	token, _ = f.s.RememberAdminDevice(id, "198.51.100.1")
	if err := f.s.ChangeAdminPassword(Actor{ID: id}, "Admin password 1", "Green valley 2026x"); err != nil {
		t.Fatal(err)
	}
	if f.s.RememberedAdmin(id, token, "198.51.100.1") {
		t.Fatal("accepted after a new password")
	}
	// and so does removing the authenticator
	token, _ = f.s.RememberAdminDevice(id, "198.51.100.1")
	if err := f.s.RemoveOwnAdminTOTP(Actor{ID: id}, "Green valley 2026x"); err != nil {
		t.Fatal(err)
	}
	if f.s.RememberedAdmin(id, token, "198.51.100.1") {
		t.Fatal("accepted after the authenticator was removed")
	}
}

// An administrator keeps the latest maxAdminDevices devices.
func TestAdminDevicesKept(t *testing.T) {
	f := setup(t)
	id := f.adminWithTOTP()
	first, _ := f.s.RememberAdminDevice(id, "198.51.100.1")
	for range maxAdminDevices + 2 {
		f.clock.advance(time.Second)
		f.s.RememberAdminDevice(id, "198.51.100.1")
	}
	if count := f.adminDevices(id); count != maxAdminDevices {
		t.Fatalf("%d devices kept", count)
	}
	if f.s.RememberedAdmin(id, first, "198.51.100.1") {
		t.Fatal("the oldest device still works")
	}
}
