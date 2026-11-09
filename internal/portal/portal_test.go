package portal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

func setup(t *testing.T) http.Handler {
	t.Helper()
	return New(setupService(t), Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler()
}

func setupService(t *testing.T) *core.Service {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := core.New(db, network.NewFake(), core.Options{LoginPort: 8181, PublicHost: "vpn.example.com", Log: log})
	if err != nil {
		t.Fatal(err)
	}
	suggestion, _ := service.ServerDefaults(0)
	input := suggestion.ServerInput
	input.Name = "Office"
	server, err := service.CreateServer(core.Actor{Username: "tester"}, input)
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(core.Actor{Username: "tester"}, core.UserInput{Username: "alice", Password: "Secret,1234"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(core.Actor{Username: "tester"}, server.ID, core.PeerInput{Name: "laptop", Enabled: true, UserID: user.ID}); err != nil {
		t.Fatal(err)
	}
	return service
}

func request(h http.Handler, method, path, host, contentType, body string) (*httptest.ResponseRecorder, map[string]any) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "10.8.0.2:50000"
	r.Host = host
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var data map[string]any
	json.Unmarshal(w.Body.Bytes(), &data)
	return w, data
}

func TestAPI(t *testing.T) {
	h := setup(t)
	w, data := request(h, "GET", "/api/status", "10.8.0.1:8181", "", "")
	if w.Code != 200 || data["authenticated"] != false || data["server"] != "Office" {
		t.Fatalf("status: %d %v", w.Code, data)
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("missing headers: %v", w.Header())
	}
	if w, _ := request(h, "GET", "/api/status", "attacker.example.com", "", ""); w.Code != 403 {
		t.Errorf("DNS rebinding: %d", w.Code)
	}
	if w, data := request(h, "POST", "/api/login", "10.8.0.1:8181", "text/plain", `{"username":"alice","password":"Secret,1234"}`); w.Code != 400 || data["error"] != "invalid_request" {
		t.Errorf("a form post: %d %v", w.Code, data)
	}
	w, data = request(h, "POST", "/api/login", "10.8.0.1:8181", "application/json", `{"username":"alice","password":"Secret,1234"}`)
	if w.Code != 200 || data["result"] != "success" || data["user"] != "alice" {
		t.Fatalf("login: %d %v", w.Code, data)
	}
	if _, data := request(h, "GET", "/api/status", "10.8.0.1", "", ""); data["authenticated"] != true {
		t.Errorf("status after login: %v", data)
	}
	if w, _ := request(h, "POST", "/api/logout", "10.8.0.1", "application/json", ""); w.Code != 200 {
		t.Errorf("logout: %d", w.Code)
	}
	if w, data := request(h, "POST", "/api/device-key", "10.8.0.1", "application/json", "{}"); w.Code != 403 || data["error"] != "device_binding_not_required" {
		t.Errorf("device key: %d %v", w.Code, data)
	}
	if w, _ := request(h, "GET", "/api/nothing", "10.8.0.1", "", ""); w.Code != 404 {
		t.Errorf("unknown path: %d", w.Code)
	}
	if w, _ := request(h, "GET", "/", "10.8.0.1", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "VPN login") {
		t.Errorf("page: %d", w.Code)
	}
}

func TestDNSAnswer(t *testing.T) {
	server := netip.MustParseAddr("10.8.0.1")
	// id 0x1234, recursion desired, one question: example.com A IN
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	server6 := netip.MustParseAddr("fd12:3456:789a:1::1")
	reply := DNSAnswer(query, server, server6)
	want := append([]byte{0x12, 0x34, 0x85, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, query[12:]...)
	want = append(want, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 8, 0, 1)
	if string(reply) != string(want) {
		t.Fatalf("A:\n got %x\nwant %x", reply, want)
	}
	// AAAA without an IPv6 network: no record, so the clients fall back to IPv4
	aaaa := append([]byte{}, query...)
	aaaa[len(aaaa)-3] = 28
	if reply := DNSAnswer(aaaa, server, netip.Addr{}); reply == nil || reply[7] != 0 || len(reply) != len(aaaa) {
		t.Fatalf("AAAA: %x", reply)
	}
	// with one: the IPv6 address of the server
	want6 := append([]byte{0x12, 0x34, 0x85, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, aaaa[12:]...)
	want6 = append(want6, 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16)
	address6 := server6.As16()
	want6 = append(want6, address6[:]...)
	if reply := DNSAnswer(aaaa, server, server6); string(reply) != string(want6) {
		t.Fatalf("AAAA:\n got %x\nwant %x", reply, want6)
	}
	// and the A queries still get IPv4 only
	if reply := DNSAnswer(query, server, server6); string(reply) != string(want) {
		t.Fatalf("A with IPv6:\n got %x", reply)
	}
	response := append([]byte{}, query...)
	response[2] |= 0x80
	compressed := append(append([]byte{}, query[:12]...), 0xC0, 0x0C, 0, 1, 0, 1)
	for name, bad := range map[string][]byte{
		"short": query[:10], "a response": response, "a compressed name": compressed, "cut": query[:len(query)-2],
	} {
		if DNSAnswer(bad, server, server6) != nil {
			t.Errorf("%s is answered", name)
		}
	}
}

func TestRedirect(t *testing.T) {
	h := New(setupService(t), Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).RedirectHandler()
	r := httptest.NewRequest("GET", "http://neverssl.com/some/page", nil)
	r.RemoteAddr = "10.8.0.2:50000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "http://10.8.0.1:8181/" {
		t.Fatalf("redirect: %d %v", w.Code, w.Header())
	}
	r.RemoteAddr = "192.168.1.5:50000"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("not a peer: %d", w.Code)
	}
}

func TestLimiter(t *testing.T) {
	h := setup(t)
	limited := 0
	for range 15 {
		if w, _ := request(h, "POST", "/api/login", "10.8.0.1", "application/json", `{"username":"alice","password":"x"}`); w.Code == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Error("15 logins at once all reach the password check")
	}
}

// Device binding over HTTP, as Authway does it: the status gives the challenge, the login carries the proof, the
// status with the key ID says which device is enrolled.
func TestDeviceBinding(t *testing.T) {
	service := setupService(t)
	servers, _ := service.Servers()
	input := core.ServerInput{
		Name: servers[0].Name, Enabled: true, PublicHost: servers[0].PublicHost, ListenPort: servers[0].ListenPort,
		Network: servers[0].Network, Keepalive: servers[0].Keepalive, AuthMode: servers[0].AuthMode,
		SessionTimeout: servers[0].SessionTimeout, LockEndpoint: servers[0].LockEndpoint, DeviceBinding: true,
	}
	if _, err := service.UpdateServer(core.Actor{Username: "tester"}, servers[0].ID, input); err != nil {
		t.Fatal(err)
	}
	peers, _ := service.Peers(servers[0].ID)
	h := New(service, Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	public := base64.StdEncoding.EncodeToString(der)
	sum := sha256.Sum256(der)
	id := hex.EncodeToString(sum[:])
	sign := func(lines ...string) string {
		digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		signature, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
		return base64.StdEncoding.EncodeToString(signature)
	}
	challenge := func() string {
		_, data := request(h, "GET", "/api/status?device=", "10.8.0.1", "", "")
		device, _ := data["device"].(map[string]any)
		text, _ := device["challenge"].(string)
		if text == "" || device["required"] != true {
			t.Fatalf("status: %v", data)
		}
		return text
	}

	if w, data := request(h, "POST", "/api/login", "10.8.0.1", "application/json", `{"username":"alice","password":"Secret,1234"}`); w.Code != 403 || data["error"] != "device_required" {
		t.Fatalf("the browser: %d %v", w.Code, data)
	}
	c := challenge()
	body, _ := json.Marshal(map[string]any{"username": "alice", "password": "Secret,1234", "device": map[string]string{
		"challenge": c, "public_key": public, "kind": "software", "name": "LAPTOP-42",
		"signature": sign(core.DeviceMessage, c, servers[0].PublicKey, peers[0].PublicKey, peers[0].Address, "alice", ""),
	}})
	if w, data := request(h, "POST", "/api/login", "10.8.0.1", "application/json", string(body)); w.Code != 200 {
		t.Fatalf("login: %d %v", w.Code, data)
	}
	for query, want := range map[string]any{"?device=" + id: true, "?device=": false, "?device=" + strings.Repeat("0", 64): false} {
		_, data := request(h, "GET", "/api/status"+query, "10.8.0.1", "", "")
		if device, _ := data["device"].(map[string]any); device["this_device"] != want || device["wireguard_key"] != "configuration" {
			t.Errorf("%s: %v", query, data)
		}
	}
	if _, data := request(h, "GET", "/api/status", "10.8.0.1", "", ""); data["device"].(map[string]any)["this_device"] != nil {
		t.Errorf("without a key ID: %v", data)
	}
	c = challenge()
	body, _ = json.Marshal(map[string]string{"challenge": c, "wireguard_key": "not a key", "signature": sign("x")})
	if w, data := request(h, "POST", "/api/device-key", "10.8.0.1", "application/json", string(body)); w.Code != 400 || data["error"] != "invalid_key" {
		t.Errorf("device key: %d %v", w.Code, data)
	}
}

// a peer opens the page from its IPv6 address, with the IPv6 address of the server, and a redirect over IPv6 leads to
// the IPv4 page
func TestIPv6(t *testing.T) {
	service := setupService(t)
	servers, _ := service.Servers()
	peers, _ := service.Peers(servers[0].ID)
	if servers[0].Address6 == "" || peers[0].Address6 == "" {
		t.Fatalf("no IPv6: %+v %+v", servers[0], peers[0])
	}
	pages := New(service, Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ask := func(h http.Handler, method, path, host, body string) (*httptest.ResponseRecorder, map[string]any) {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "[" + peers[0].Address6 + "]:50000"
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var data map[string]any
		json.Unmarshal(w.Body.Bytes(), &data)
		return w, data
	}
	host6 := "[" + servers[0].Address6 + "]:8181"
	if w, data := ask(pages.Handler(), "GET", "/api/status", host6, ""); w.Code != 200 || data["server"] != "Office" {
		t.Fatalf("status over IPv6: %d %v", w.Code, data)
	}
	if w, _ := ask(pages.Handler(), "GET", "/api/status", servers[0].Address6+":8181", ""); w.Code != 403 {
		t.Errorf("a host without brackets: %d", w.Code)
	}
	w, data := ask(pages.Handler(), "POST", "/api/login", host6, `{"username":"alice","password":"Secret,1234"}`)
	if w.Code != 200 || data["result"] != "success" {
		t.Fatalf("login over IPv6: %d %v", w.Code, data)
	}
	// the redirect answers the server of the peer, the IPv4 page: the one of the configuration files
	if w, _ := ask(pages.RedirectHandler(), "GET", "/", "example.com", ""); w.Code != 302 || w.Header().Get("Location") != "http://10.8.0.1:8181/" {
		t.Errorf("redirect over IPv6: %d %q", w.Code, w.Header().Get("Location"))
	}
}
