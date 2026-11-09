package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBackupRoutes(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	if w, data := admin.do("POST", "/api/admins", `{"username":"olga","role":"operator","password":"Orange tree 4521"}`, true); w.Code != 200 {
		t.Fatalf("add: %d %v", w.Code, data)
	}
	operator := &client{t: t, h: h}
	operator.login("olga", "Orange tree 4521", "")
	if w, data := operator.do("PUT", "/api/me/password", `{"current":"Orange tree 4521","password":"Orange tree 45222"}`, true); w.Code != 200 {
		t.Fatalf("new password: %d %v", w.Code, data)
	}
	server := `{"name":"Office","enabled":true,"public_host":"vpn.example.com","listen_port":51820,"network":"10.8.0.0/24","auth_mode":"password","session_timeout":3600,"keepalive":25}`
	if w, data := admin.do("POST", "/api/servers", server, true); w.Code != 200 {
		t.Fatalf("server: %d %v", w.Code, data)
	}

	request := `{"password":"Admin password 1","passphrase":"correct horse battery"}`
	for _, path := range []string{"/api/backup", "/api/restore/check", "/api/restore"} {
		if w, data := operator.do("POST", path, request, true); w.Code != 403 || data["error"] != "not_allowed" {
			t.Fatalf("an operator on %s: %d %v", path, w.Code, data)
		}
	}
	if w, data := admin.do("POST", "/api/backup", `{"password":"wrong","passphrase":"correct horse battery"}`, true); w.Code != 400 ||
		data["fields"].(map[string]any)["password"] != "wrong" {
		t.Fatalf("a wrong password: %d %v", w.Code, data)
	}
	w, data := admin.do("POST", "/api/backup", request, true)
	if w.Code != 200 || data["format"] != "authway-server-backup" ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), `attachment; filename=authway-backup-`) {
		t.Fatalf("backup: %d %v %v", w.Code, w.Header(), data)
	}
	file := w.Body.String()

	body := func(fields map[string]string) string {
		data, _ := json.Marshal(fields)
		return string(data)
	}
	w, data = admin.do("POST", "/api/restore/check", body(map[string]string{"passphrase": "correct horse battery", "backup": file}), true)
	if w.Code != 200 || data["servers"] != 1.0 || data["administrators"] != 2.0 || data["includes_you"] != true {
		t.Fatalf("check: %d %v", w.Code, data)
	}
	w, data = admin.do("POST", "/api/restore/check", body(map[string]string{"passphrase": "another passphrase", "backup": file}), true)
	if w.Code != 400 || data["fields"].(map[string]any)["passphrase"] != "wrong" {
		t.Fatalf("a wrong passphrase: %d %v", w.Code, data)
	}
	if w, _ := admin.do("DELETE", "/api/servers/1", "", true); w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}

	w, data = admin.do("POST", "/api/restore", body(map[string]string{"password": "Admin password 1", "passphrase": "correct horse battery", "backup": file}), true)
	if w.Code != 200 || data["servers"] != 1.0 {
		t.Fatalf("restore: %d %v", w.Code, data)
	}
	// every session of the web UI ends: the administrators can be other ones now
	for name, c := range map[string]*client{"admin": admin, "operator": operator} {
		if w, data := c.do("GET", "/api/servers", "", true); w.Code != 401 {
			t.Fatalf("%s after the restore: %d %v", name, w.Code, data)
		}
	}
	again := &client{t: t, h: h}
	if code, data := again.login("olga", "Orange tree 45222", ""); code != 200 {
		t.Fatalf("login of the backup: %d %v", code, data)
	}
	w, _ = again.do("GET", "/api/servers", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"name":"Office"`) {
		t.Fatalf("servers: %d %s", w.Code, w.Body.String())
	}
}
