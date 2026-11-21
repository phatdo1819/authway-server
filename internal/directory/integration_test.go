package directory

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestAgainstDirectory runs against a real Active Directory, or Samba, when these are set; otherwise it's skipped.
//
//	AUTHWAY_TEST_AD_SERVERS        dc1.example.com, or several separated by commas
//	AUTHWAY_TEST_AD_SECURITY       ldaps (default) or starttls
//	AUTHWAY_TEST_AD_CA             a PEM file of the CA of the domain controllers, when the system doesn't trust it
//	AUTHWAY_TEST_AD_BIND_USER      the service account, and AUTHWAY_TEST_AD_BIND_PASSWORD
//	AUTHWAY_TEST_AD_BASE           DC=example,DC=com
//	AUTHWAY_TEST_AD_GROUP          CN=VPN Users,OU=Groups,DC=example,DC=com
//	AUTHWAY_TEST_AD_USER           an enabled member of the group, and AUTHWAY_TEST_AD_PASSWORD
//
// A domain controller that stops answering is always put in front of the ones of AUTHWAY_TEST_AD_SERVERS once, to
// check that the next one answers in time.
//
// Optional, each checked when set: AUTHWAY_TEST_AD_DEAD (an address nothing answers at, put in front too),
// AUTHWAY_TEST_AD_NESTED (a member through a group in the group),
// AUTHWAY_TEST_AD_DISABLED (a disabled member), AUTHWAY_TEST_AD_OUTSIDE (an account outside the group),
// AUTHWAY_TEST_AD_MUST_CHANGE with AUTHWAY_TEST_AD_MUST_CHANGE_PASSWORD (a member who must change their password), and
// AUTHWAY_TEST_AD_LOCK with AUTHWAY_TEST_AD_LOCK_TRIES (a member this test locks out with that many wrong passwords:
// never a real person's account).
func TestAgainstDirectory(t *testing.T) {
	servers := os.Getenv("AUTHWAY_TEST_AD_SERVERS")
	if servers == "" {
		t.Skip("set AUTHWAY_TEST_AD_SERVERS and the others to test against a directory")
	}
	cfg := Config{
		Servers: strings.Split(servers, ","), Security: os.Getenv("AUTHWAY_TEST_AD_SECURITY"),
		BindUser: os.Getenv("AUTHWAY_TEST_AD_BIND_USER"), BindPassword: os.Getenv("AUTHWAY_TEST_AD_BIND_PASSWORD"),
		BaseDN: os.Getenv("AUTHWAY_TEST_AD_BASE"), Group: os.Getenv("AUTHWAY_TEST_AD_GROUP"),
	}
	if cfg.Security == "" {
		cfg.Security = SecurityLDAPS
	}
	if path := os.Getenv("AUTHWAY_TEST_AD_CA"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg.CACertificates = string(data)
	}
	group, err := LDAP{}.Members(cfg)
	if err != nil {
		t.Fatalf("members: %v", err)
	}
	t.Logf("the service account's password expires: %v", group.PasswordExpires)
	if len(group.Unanswered) != 0 {
		t.Errorf("domain controllers that didn't answer: %v", group.Unanswered)
	}
	byName := map[string]User{}
	for _, member := range group.Members {
		t.Logf("member %s (%s) %q disabled=%v", member.Username, member.ID, member.FullName, member.Disabled)
		byName[strings.ToLower(member.Username)] = member
	}
	find := func(env string) (User, bool) {
		name := os.Getenv(env)
		if name == "" {
			return User{}, false
		}
		user, ok := byName[strings.ToLower(name)]
		if !ok {
			t.Fatalf("%s %s isn't among the members", env, name)
		}
		return user, true
	}

	user, ok := find("AUTHWAY_TEST_AD_USER")
	if !ok || user.Disabled || len(user.ID) != 32 {
		t.Fatalf("the member: %+v", user)
	}
	password := os.Getenv("AUTHWAY_TEST_AD_PASSWORD")
	if got, err := (LDAP{}).Authenticate(cfg, user.ID, password); err != nil || got.ID != user.ID {
		t.Fatalf("the right password: %+v %v", got, err)
	}
	if _, err := (LDAP{}).Authenticate(cfg, user.ID, password+"x"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("a wrong password: %v", err)
	}
	if _, err := (LDAP{}).Authenticate(cfg, user.ID, ""); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("an empty password: %v", err)
	}
	if _, err := (LDAP{}).Authenticate(cfg, "00000000000000000000000000000000", password); !errors.Is(err, ErrNotMember) {
		t.Errorf("an unknown account: %v", err)
	}

	if nested, ok := find("AUTHWAY_TEST_AD_NESTED"); ok && nested.Disabled {
		t.Errorf("the nested member: %+v", nested)
	}
	if disabled, ok := find("AUTHWAY_TEST_AD_DISABLED"); ok {
		if !disabled.Disabled {
			t.Errorf("the disabled member: %+v", disabled)
		}
		if _, err := (LDAP{}).Authenticate(cfg, disabled.ID, password); !errors.Is(err, ErrDisabled) {
			t.Errorf("the disabled member logs in: %v", err)
		}
	}
	if outside := os.Getenv("AUTHWAY_TEST_AD_OUTSIDE"); outside != "" {
		if _, ok := byName[strings.ToLower(outside)]; ok {
			t.Errorf("%s, outside the group, is a member", outside)
		}
	}
	if member, ok := find("AUTHWAY_TEST_AD_MUST_CHANGE"); ok {
		_, err := (LDAP{}).Authenticate(cfg, member.ID, os.Getenv("AUTHWAY_TEST_AD_MUST_CHANGE_PASSWORD"))
		if !errors.Is(err, ErrPasswordExpired) {
			t.Errorf("a password to change: %v", err)
		}
	}
	if member, ok := find("AUTHWAY_TEST_AD_LOCK"); ok {
		tries, _ := strconv.Atoi(os.Getenv("AUTHWAY_TEST_AD_LOCK_TRIES"))
		for range tries {
			(LDAP{}).Authenticate(cfg, member.ID, "a wrong password")
		}
		if _, err := (LDAP{}).Authenticate(cfg, member.ID, "a wrong password"); !errors.Is(err, ErrLocked) {
			t.Errorf("after %d wrong passwords: %v", tries, err)
		}
	}

	// a domain controller in front that accepts the connection and then stops answering, or one that doesn't exist
	// (AUTHWAY_TEST_AD_DEAD, an address nothing answers at): the next one answers, after the connect timeout at most.
	// The next login goes straight to the one that answers, and a sync says which one didn't.
	fronts := []string{stallingServer(t, cfg.Security == SecurityStartTLS)}
	if dead := os.Getenv("AUTHWAY_TEST_AD_DEAD"); dead != "" {
		fronts = append(fronts, dead)
	}
	for _, front := range fronts {
		failover := cfg
		failover.Servers = append([]string{front}, cfg.Servers...)
		for _, login := range []string{"first", "second"} {
			start := time.Now()
			if _, err := (LDAP{}).Authenticate(failover, user.ID, password); err != nil {
				t.Errorf("after %s: %v", front, err)
			}
			took := time.Since(start)
			t.Logf("after %s, which doesn't answer: %s login in %s", front, login, took.Round(time.Millisecond))
			if took > DefaultConnectTimeout+3*time.Second || (login == "second" && took > 2*time.Second) {
				t.Errorf("after %s, %s login: %s", front, login, took)
			}
		}
		group, err := LDAP{}.Members(failover)
		if err != nil || len(group.Members) == 0 || len(group.Unanswered) != 1 || !strings.Contains(group.Unanswered[0], front) {
			t.Errorf("sync after %s: %v %v", front, group.Unanswered, err)
		}
	}

	// a wrong service password: the directory can't be read, it's not a wrong password of a user
	wrong := cfg
	wrong.BindPassword += "x"
	if _, err := (LDAP{}).Members(wrong); err == nil || !strings.Contains(err.Error(), "service account") {
		t.Errorf("a wrong service password: %v", err)
	}
	if _, err := (LDAP{}).Authenticate(wrong, user.ID, password); err == nil || errors.Is(err, ErrWrongPassword) {
		t.Errorf("a wrong service password at a login: %v", err)
	}
	// without the CA, the certificate isn't trusted
	if cfg.CACertificates != "" {
		untrusted := cfg
		untrusted.CACertificates = ""
		if _, err := (LDAP{}).Members(untrusted); err == nil {
			t.Error("a certificate of an unknown CA is trusted")
		}
	}
}
