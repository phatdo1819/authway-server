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
	if w.Code != 200 || !strings.Contains(w.Body.String(), "PrivateKey = ") || !strings.Contains(w.Header().Get("Content-Disposition"), `filename=Office-laptop.conf`) {
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

// Behind a trusted reverse proxy, the address of the browser is the nearest one it forwards, and the cookie follows
// the HTTPS of the browser. From anyone else, the headers are ignored.
func TestTrustedProxies(t *testing.T) {
	a := &Admin{proxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.0.2.1/32")}}
	request := func(remote string, headers ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for index := 0; index+1 < len(headers); index += 2 {
			r.Header.Add(headers[index], headers[index+1])
		}
		return r
	}
	for _, test := range []struct {
		r      *http.Request
		client string
		secure bool
	}{
		{request("198.51.100.7:4000", "X-Forwarded-For", "203.0.113.9", "X-Forwarded-Proto", "https"), "198.51.100.7", false},
		{request("10.0.0.5:4000"), "10.0.0.5", false},
		{request("10.0.0.5:4000", "X-Forwarded-For", "203.0.113.9", "X-Forwarded-Proto", "https"), "203.0.113.9", true},
		{request("10.0.0.5:4000", "X-Forwarded-For", "1.1.1.1, 203.0.113.9, 192.0.2.1", "X-Forwarded-Proto", "http"), "203.0.113.9", false},
		{request("10.0.0.5:4000", "X-Forwarded-For", "1.1.1.1", "X-Forwarded-For", "203.0.113.9"), "203.0.113.9", false},
		{request("10.0.0.5:4000", "X-Forwarded-For", "203.0.113.9, junk"), "10.0.0.5", false},
		{request("[::ffff:10.0.0.5]:4000", "X-Forwarded-For", "2001:db8::1", "X-Forwarded-Proto", "HTTPS"), "2001:db8::1", true},
	} {
		if got := a.client(test.r); got.String() != test.client {
			t.Errorf("%s %v: client %s, want %s", test.r.RemoteAddr, test.r.Header, got, test.client)
		}
		if got := a.secureFor(test.r); got != test.secure {
			t.Errorf("%s %v: secure %v, want %v", test.r.RemoteAddr, test.r.Header, got, test.secure)
		}
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
