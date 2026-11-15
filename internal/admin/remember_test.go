package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phatdo1819/authway-server/internal/totp"
)

// loginWith sends a login from a browser that has the cookie device, nil for none.
func loginWith(t *testing.T, h http.Handler, body string, device *http.Cookie) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(body))
	r.RemoteAddr = "192.168.1.10:50000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(csrfHeader, csrfValue)
	if device != nil {
		r.AddCookie(device)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var data map[string]any
	json.Unmarshal(w.Body.Bytes(), &data)
	return w, data
}

func cookieOf(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// With "Remember this device", the next logins from the browser need the password only.
func TestRememberDevice(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	admin.login("admin", "Admin password 1", "")
	_, setup := admin.do("POST", "/api/me/totp", `{"password":"Admin password 1"}`, true)
	secretKey, _ := setup["secret"].(string)
	period := uint64(time.Now().Unix() / 30)
	code, _ := totp.Code(secretKey, period)
	if w, data := admin.do("PUT", "/api/me/totp", `{"code":"`+code+`"}`, true); w.Code != 200 {
		t.Fatalf("confirm: %d %v", w.Code, data)
	}

	password := `{"username":"admin","password":"Admin password 1"}`
	w, data := loginWith(t, h, password, nil)
	if w.Code != 401 || data["error"] != "otp_required" || data["remember_days"] != float64(30) {
		t.Fatalf("without the code: %d %v", w.Code, data)
	}
	next, _ := totp.Code(secretKey, period+1)
	w, data = loginWith(t, h, `{"username":"admin","password":"Admin password 1","otp":"`+next+`","remember":true}`, nil)
	device := cookieOf(w, deviceCookie)
	if w.Code != 200 || device == nil || device.Path != devicePath || !device.HttpOnly || device.SameSite != http.SameSiteStrictMode ||
		device.MaxAge != 30*24*3600 {
		t.Fatalf("remember: %d %v %+v", w.Code, data, device)
	}
	// the password alone, from the remembered browser
	if w, data := loginWith(t, h, password, device); w.Code != 200 || cookieOf(w, cookieName) == nil {
		t.Fatalf("from the remembered browser: %d %v", w.Code, data)
	}
	// the browser doesn't replace the password
	if w, data := loginWith(t, h, `{"username":"admin","password":"wrong"}`, device); w.Code != 401 || data["error"] != "invalid_credentials" {
		t.Fatalf("a wrong password from the remembered browser: %d %v", w.Code, data)
	}
	// a made-up cookie is no browser
	if w, data := loginWith(t, h, password, &http.Cookie{Name: deviceCookie, Value: "made-up"}); w.Code != 401 || data["error"] != "otp_required" {
		t.Fatalf("a made-up cookie: %d %v", w.Code, data)
	}
	if w, data := admin.do("PUT", "/api/settings", `{"admin_remember_days":91}`, true); w.Code != 400 {
		t.Fatalf("91 days: %d %v", w.Code, data)
	}
	// off: the code again, and no box to tick
	if w, data := admin.do("PUT", "/api/settings", `{"admin_remember_days":0}`, true); w.Code != 200 || data["admin_remember_days"] != float64(0) {
		t.Fatalf("off: %d %v", w.Code, data)
	}
	if w, data := loginWith(t, h, password, device); w.Code != 401 || data["error"] != "otp_required" || data["remember_days"] != float64(0) {
		t.Fatalf("remembered while off: %d %v", w.Code, data)
	}
}
