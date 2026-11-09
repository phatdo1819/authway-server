package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (c *client) do(method, path, body string, csrf bool) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.168.1.10:50000"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if csrf {
		r.Header.Set(csrfHeader, csrfValue)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == cookieName {
			c.cookie = cookie
		}
	}
	var data map[string]any
	json.Unmarshal(w.Body.Bytes(), &data)
	return w, data
}

func TestAdminAPI(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := core.New(db, network.NewFake(), core.Options{PublicHost: "vpn.example.com", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	password, err := service.EnsureAdmin("admin", "")
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, h: New(service, Options{Log: log, Secure: true}).Handler()}

	if w, _ := c.do("GET", "/api/servers", "", true); w.Code != 401 {
		t.Fatalf("without login: %d", w.Code)
	}
	if w, _ := c.do("POST", "/api/login", `{"username":"admin","password":"`+password+`"}`, false); w.Code != 403 {
		t.Fatalf("a login without the header: %d", w.Code)
	}
	if w, data := c.do("POST", "/api/login", `{"username":"admin","password":"wrong"}`, true); w.Code != 401 || data["error"] != "invalid_credentials" {
		t.Fatalf("a wrong password: %d %v", w.Code, data)
	}
	w, _ := c.do("POST", "/api/login", `{"username":"admin","password":"`+password+`"}`, true)
	if w.Code != 200 || c.cookie == nil || !c.cookie.HttpOnly || !c.cookie.Secure || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login: %d %+v", w.Code, c.cookie)
	}
	if w, _ := c.do("GET", "/api/servers", "", false); w.Code != 403 {
		t.Fatalf("a request without the header: %d", w.Code)
	}
	// a random first password is in the log: it changes before anything else
	if w, data := c.do("GET", "/api/servers", "", true); w.Code != 403 || data["error"] != "setup_required" || data["setup"] != "password" {
		t.Fatalf("before the new password: %d %v", w.Code, data)
	}
	if w, data := c.do("GET", "/api/me", "", true); w.Code != 200 || data["setup"] != "password" || data["role"] != "admin" {
		t.Fatalf("me: %d %v", w.Code, data)
	}
	if w, data := c.do("PUT", "/api/me/password", `{"current":"`+password+`","password":"Fresh secret 2026"}`, true); w.Code != 200 {
		t.Fatalf("new password: %d %v", w.Code, data)
	}
	w, data := c.do("POST", "/api/servers", `{"name":"","public_host":"vpn.example.com","listen_port":51820,"network":"10.8.0.0/24","auth_mode":"password","session_timeout":3600}`, true)
	if w.Code != 400 || data["error"] != "validation" || data["fields"].(map[string]any)["name"] != "required" {
		t.Fatalf("validation: %d %v", w.Code, data)
	}
	w, data = c.do("POST", "/api/servers", `{"name":"Office","enabled":true,"public_host":"vpn.example.com","listen_port":51820,"network":"10.8.0.0/24","auth_mode":"password","session_timeout":3600,"keepalive":25}`, true)
	if w.Code != 200 || data["name"] != "Office" || data["interface"] != "wg0" {
		t.Fatalf("create: %d %v", w.Code, data)
	}
	w, data = c.do("POST", "/api/users", `{"username":"alice","password":"Secret,1234"}`, true)
	if w.Code != 200 {
		t.Fatalf("user: %d %v", w.Code, data)
	}
	w, data = c.do("POST", "/api/servers/1/peers", `{"name":"laptop","enabled":true,"user_id":1}`, true)
	if w.Code != 200 || data["address"] != "10.8.0.2" {
		t.Fatalf("peer: %d %v", w.Code, data)
	}
	if strings.Contains(w.Body.String(), "private") {
		t.Error("a private key reaches the web UI")
	}
	w, _ = c.do("GET", "/api/peers/1/config", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "PrivateKey = ") || !strings.Contains(w.Header().Get("Content-Disposition"), `filename=Office.conf`) {
		t.Fatalf("config: %d %s %v", w.Code, w.Body.String(), w.Header())
	}
	if w, _ := c.do("DELETE", "/api/peers/99", "", true); w.Code != 404 {
		t.Fatalf("delete of a missing peer: %d", w.Code)
	}
	if w, _ := c.do("GET", "/servers/1", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("a page of the UI: %d", w.Code)
	}
	token := c.cookie
	if w, _ := c.do("POST", "/api/logout", "", true); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	// the old cookie no longer works, even sent again
	c.cookie = token
	if w, _ := c.do("GET", "/api/me", "", true); w.Code != 401 {
		t.Fatalf("after logout: %d", w.Code)
	}
}

// the failed logins count by network: the addresses of one IPv6 /64 are one
func TestFailureKey(t *testing.T) {
	for address, key := range map[string]string{
		"192.0.2.10": "192.0.2.10", "2001:db8:1:2:aaaa:bbbb:cccc:dddd": "2001:db8:1:2::", "2001:db8:1:3::1": "2001:db8:1:3::",
	} {
		if got := failureKey(netip.MustParseAddr(address)); got.String() != key {
			t.Errorf("%s: %s, want %s", address, got, key)
		}
	}
}
