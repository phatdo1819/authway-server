package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

func newTestAPI(t *testing.T) http.Handler {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := core.New(db, network.NewFake(), core.Options{PublicHost: "vpn.example.com", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	// a password given in the environment: no change at the first login
	if _, err := service.EnsureAdmin("admin", "Admin password 1"); err != nil {
		t.Fatal(err)
	}
	return New(service, Options{Log: log}).Handler()
}

func (c *client) login(username, password, otp string) (int, map[string]any) {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password, "otp": otp})
	w, data := c.do("POST", "/api/login", string(body), true)
	return w.Code, data
}

func TestRoles(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 || data["setup"] != "" {
		t.Fatalf("login: %d %v", code, data)
	}
	for _, account := range []string{
		`{"username":"olga","role":"operator","password":"Orange tree 4521"}`,
		`{"username":"vic","role":"viewer","password":"Violet sky 98765"}`,
	} {
		if w, data := admin.do("POST", "/api/admins", account, true); w.Code != 200 {
			t.Fatalf("add: %d %v", w.Code, data)
		}
	}
	server := `{"name":"Office","enabled":true,"public_host":"vpn.example.com","listen_port":51820,"network":"10.8.0.0/24","auth_mode":"password","session_timeout":3600,"keepalive":25}`
	if w, data := admin.do("POST", "/api/servers", server, true); w.Code != 200 {
		t.Fatalf("server: %d %v", w.Code, data)
	}
	login := func(name, first, next string) *client {
		c := &client{t: t, h: h}
		if code, data := c.login(name, first, ""); code != 200 || data["setup"] != "password" {
			t.Fatalf("%s: %d %v", name, code, data)
		}
		if w, data := c.do("GET", "/api/users", "", true); w.Code != 403 || data["error"] != "setup_required" {
			t.Fatalf("%s before the new password: %d %v", name, w.Code, data)
		}
		if w, data := c.do("PUT", "/api/me/password", `{"current":"`+first+`","password":"`+next+`"}`, true); w.Code != 200 {
			t.Fatalf("%s new password: %d %v", name, w.Code, data)
		}
		return c
	}
	operator := login("olga", "Orange tree 4521", "Orange tree 45222")
	viewer := login("vic", "Violet sky 98765", "Violet sky 987654")

	for _, test := range []struct {
		c                  *client
		method, path, body string
		code               int
	}{
		{viewer, "GET", "/api/servers", "", 200},
		{viewer, "GET", "/api/users", "", 200},
		{viewer, "GET", "/api/settings", "", 200},
		{viewer, "POST", "/api/users", `{"username":"vicuser","password":"Secret,1234"}`, 403},
		{viewer, "GET", "/api/admins", "", 403},
		{operator, "POST", "/api/users", `{"username":"alice","password":"Secret,1234"}`, 200},
		{operator, "POST", "/api/servers/1/peers", `{"name":"laptop","enabled":true,"user_id":1}`, 200},
		{viewer, "GET", "/api/peers/1/config", "", 403},
		{viewer, "POST", "/api/peers/1/logout", "", 403},
		{operator, "GET", "/api/peers/1/config", "", 200},
		{operator, "PUT", "/api/servers/1", `{"name":"Renamed"}`, 403},
		{operator, "DELETE", "/api/servers/1", "", 403},
		{operator, "PUT", "/api/settings", `{"public_host":"other.example.com"}`, 403},
		{operator, "GET", "/api/admins", "", 403},
		{operator, "PUT", "/api/admins/2", `{"role":"admin"}`, 403},
		{viewer, "GET", "/api/connections", "", 200},
		{viewer, "POST", "/api/peers/1/device", `{"hours":2}`, 403},
		{viewer, "DELETE", "/api/peers/1/device", "", 403},
		// the server has no device binding
		{operator, "POST", "/api/peers/1/device", `{"hours":2}`, 400},
		{operator, "DELETE", "/api/peers/1/device", "", 400},
		{operator, "PUT", "/api/settings", `{"enroll_hours":24}`, 403},
		// the routes on the router: a change of the network
		{viewer, "POST", "/api/host-addresses/confirm", "", 403},
		{operator, "POST", "/api/host-addresses/confirm", "", 403},
		{admin, "POST", "/api/host-addresses/confirm", "", 200},
		{admin, "PUT", "/api/settings", `{"public_host":"other.example.com"}`, 200},
		{admin, "PUT", "/api/settings", `{"enroll_hours":24}`, 200},
		{admin, "DELETE", "/api/admins/1", "", 409},
		{admin, "PUT", "/api/admins/1", `{"role":"viewer"}`, 400},
		{admin, "PUT", "/api/admins/1/password", `{"password":"Some password 1"}`, 409},
	} {
		if w, _ := test.c.do(test.method, test.path, test.body, true); w.Code != test.code {
			t.Errorf("%s %s: %d, not %d: %s", test.method, test.path, w.Code, test.code, w.Body.String())
		}
	}

	// a role taken away applies at once; a disabled administrator is logged out
	if w, data := admin.do("PUT", "/api/admins/2", `{"role":"viewer"}`, true); w.Code != 200 {
		t.Fatalf("operator to viewer: %d %v", w.Code, data)
	}
	if w, _ := operator.do("POST", "/api/users", `{"username":"bob","password":"Secret,1234"}`, true); w.Code != 403 {
		t.Fatalf("an old role: %d", w.Code)
	}
	if w, _ := admin.do("PUT", "/api/admins/3", `{"role":"viewer","disabled":true}`, true); w.Code != 200 {
		t.Fatalf("disable: %d", w.Code)
	}
	if w, _ := viewer.do("GET", "/api/servers", "", true); w.Code != 401 {
		t.Fatalf("a disabled administrator: %d", w.Code)
	}
	if code, data := (&client{t: t, h: h}).login("vic", "Violet sky 987654", ""); code != 403 || data["error"] != "disabled" {
		t.Fatalf("login of a disabled administrator: %d %v", code, data)
	}
	// a password reset by another administrator logs out, and changes at the next login
	if w, _ := admin.do("PUT", "/api/admins/2/password", `{"password":"Reset password 12"}`, true); w.Code != 200 {
		t.Fatalf("reset: %d", w.Code)
	}
	if w, _ := operator.do("GET", "/api/servers", "", true); w.Code != 401 {
		t.Fatalf("after a reset: %d", w.Code)
	}
}

func TestAdminMFA(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	admin.login("admin", "Admin password 1", "")
	w, data := admin.do("PUT", "/api/settings", `{"require_admin_mfa":true}`, true)
	if fields, _ := data["fields"].(map[string]any); w.Code != 400 || fields["require_admin_mfa"] != "enroll_first" {
		t.Fatalf("required without one: %d %v", w.Code, data)
	}
	// a session alone can't put an authenticator on the account
	if w, data := admin.do("POST", "/api/me/totp", `{}`, true); w.Code != 400 {
		t.Fatalf("a setup without the password: %d %v", w.Code, data)
	}
	_, setup := admin.do("POST", "/api/me/totp", `{"password":"Admin password 1"}`, true)
	secretKey, _ := setup["secret"].(string)
	if secretKey == "" {
		t.Fatalf("setup: %v", setup)
	}
	period := uint64(time.Now().Unix() / 30)
	code, _ := totp.Code(secretKey, period)
	other := &client{t: t, h: h}
	other.login("admin", "Admin password 1", "")
	if w, data := admin.do("PUT", "/api/me/totp", `{"code":"`+code+`"}`, true); w.Code != 200 {
		t.Fatalf("confirm: %d %v", w.Code, data)
	}
	if w, _ := other.do("GET", "/api/me", "", true); w.Code != 401 {
		t.Fatalf("a session opened without the code stays: %d", w.Code)
	}
	if w, _ := admin.do("PUT", "/api/settings", `{"require_admin_mfa":true}`, true); w.Code != 200 {
		t.Fatalf("require: %d", w.Code)
	}

	c := &client{t: t, h: h}
	if status, data := c.login("admin", "wrong", ""); status != 401 || data["error"] != "invalid_credentials" {
		t.Fatalf("a wrong password: %d %v", status, data)
	}
	if status, data := c.login("admin", "Admin password 1", ""); status != 401 || data["error"] != "otp_required" || c.cookie != nil {
		t.Fatalf("without the code: %d %v", status, data)
	}
	if status, data := c.login("admin", "Admin password 1", code); status != 401 || data["error"] != "invalid_otp" {
		t.Fatalf("the code of the setup again: %d %v", status, data)
	}
	next, _ := totp.Code(secretKey, period+1)
	if status, data := c.login("admin", "Admin password 1", next); status != 200 || c.cookie == nil {
		t.Fatalf("with the code: %d %v", status, data)
	}
	// 5 wrong codes stop the codes of this administrator for 15 minutes, from any address
	for range 5 {
		(&client{t: t, h: h}).login("admin", "Admin password 1", "000000")
	}
	if status, data := (&client{t: t, h: h}).login("admin", "Admin password 1", "000001"); status != 429 {
		t.Fatalf("after 5 wrong codes: %d %v", status, data)
	}

	// an administrator added later sets up an authenticator before anything else
	admin.do("POST", "/api/admins", `{"username":"bob","role":"admin","password":"Blue river 1234"}`, true)
	bob := &client{t: t, h: h}
	bob.login("bob", "Blue river 1234", "")
	bob.do("PUT", "/api/me/password", `{"current":"Blue river 1234","password":"Blue river 12345"}`, true)
	if w, data := bob.do("GET", "/api/servers", "", true); w.Code != 403 || data["setup"] != "mfa" {
		t.Fatalf("bob without an authenticator: %d %v", w.Code, data)
	}
	if w, data := bob.do("DELETE", "/api/me/totp", `{"password":"Blue river 12345"}`, true); w.Code != 403 || data["error"] != "setup_required" {
		t.Fatalf("bob removes an authenticator: %d %v", w.Code, data)
	}
}

// A session can't be used to find the password of its administrator: 10 wrong passwords stop the changes of the
// account for 15 minutes, the right password too.
func TestPasswordConfirmations(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	admin.login("admin", "Admin password 1", "")
	for index := range 10 {
		body := `{"password":"Guess number ` + string(rune('a'+index)) + `"}`
		if w, data := admin.do("POST", "/api/me/totp", body, true); w.Code != 400 {
			t.Fatalf("a wrong password: %d %v", w.Code, data)
		}
	}
	if w, data := admin.do("POST", "/api/me/totp", `{"password":"Admin password 1"}`, true); w.Code != 429 || data["error"] != "too_many_attempts" {
		t.Fatalf("after 10 wrong passwords: %d %v", w.Code, data)
	}
	if w, data := admin.do("PUT", "/api/me/password", `{"current":"Admin password 1","password":"Another password 2"}`, true); w.Code != 429 {
		t.Fatalf("a new password after 10 wrong ones: %d %v", w.Code, data)
	}
	// the rest of the web UI still works
	if w, _ := admin.do("GET", "/api/servers", "", true); w.Code != 200 {
		t.Fatalf("the servers: %d", w.Code)
	}
}

// What's typed as username in a failed login isn't kept unless it's an administrator: it can be a password.
func TestFailedLoginUsername(t *testing.T) {
	h := newTestAPI(t)
	(&client{t: t, h: h}).login("Admin password 1", "admin", "")
	(&client{t: t, h: h}).login("admin", "wrong password", "")
	admin := &client{t: t, h: h}
	admin.login("admin", "Admin password 1", "")
	w, _ := admin.do("GET", "/api/events", "", true)
	if w.Code != 200 {
		t.Fatalf("events: %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Admin password 1") {
		t.Fatalf("the typed text is in the events: %s", body)
	}
	if !strings.Contains(body, "unknown username") || !strings.Contains(body, `"username":"admin"`) {
		t.Fatalf("events: %s", body)
	}
}
