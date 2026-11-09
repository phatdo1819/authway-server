package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

// The changes made through the API are events with the administrator and the address of the request; the history
// lists take filters and pages; the CSV files have every row that matches, with no formula.
func TestActivityAPI(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	for _, step := range []struct{ path, body string }{
		{"/api/servers", `{"name":"Office","enabled":true,"public_host":"vpn.example.com","listen_port":51820,"network":"10.8.0.0/24","auth_mode":"password","session_timeout":3600,"keepalive":25}`},
		{"/api/users", `{"username":"alice","password":"Secret,1234"}`},
		// a name that a spreadsheet would run as a formula, with a comma
		{"/api/servers/1/peers", `{"name":"=1+2, x","enabled":true,"user_id":1}`},
	} {
		if w, data := admin.do("POST", step.path, step.body, true); w.Code != 200 {
			t.Fatalf("%s: %d %v", step.path, w.Code, data)
		}
	}
	if w, _ := admin.do("GET", "/api/peers/1/config", "", true); w.Code != 200 {
		t.Fatalf("config: %d", w.Code)
	}

	type page struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	list := func(path string) page {
		t.Helper()
		w, _ := admin.do("GET", path, "", true)
		var p page
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return p
	}
	// admin_login, server_added, user_added, peer_added, peer_config
	web := list("/api/events?type=web")
	if web.Total != 5 || web.Items[0]["kind"] != "peer_config" || web.Items[0]["by"] != "admin" || web.Items[0]["source"] != "192.168.1.10" {
		t.Fatalf("web events: %+v", web)
	}
	if vpn := list("/api/events?type=vpn"); vpn.Total != 0 || vpn.Items == nil {
		t.Errorf("vpn events: %+v", vpn)
	}
	// server_added, peer_added, peer_config: one page of 2
	office := list("/api/events?server=1&limit=2&offset=0")
	if office.Total != 3 || len(office.Items) != 2 {
		t.Errorf("events of the server: %+v", office)
	}
	if found := list("/api/events?q=" + "%3D1%2B2"); found.Total != 2 {
		t.Errorf("search of =1+2: %+v", found)
	}
	if empty := list("/api/history?q=nobody&since=1&until=99999999999"); empty.Total != 0 || empty.Items == nil {
		t.Errorf("history: %+v", empty)
	}
	if bad := list("/api/connections?offset=-4&limit=abc&server=x"); bad.Total != 0 {
		t.Errorf("connections with bad numbers: %+v", bad)
	}

	w, _ := admin.do("GET", "/api/events/csv?server=1", "", true)
	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\r\n"), "\r\n")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "authway-events-") || len(lines) != 4 {
		t.Fatalf("events CSV: %d %v\n%s", w.Code, w.Header(), w.Body.String())
	}
	if lines[0] != "at,kind,server,peer,user,by,from,detail" || !strings.Contains(lines[1], `,peer_config,Office,"'=1+2, x",alice,admin,192.168.1.10,`) {
		t.Errorf("events CSV:\n%s", w.Body.String())
	}
	if w, _ := admin.do("GET", "/api/history/csv", "", true); w.Code != 200 || w.Body.String() != "server,peer,user,address,public_ip,started,ended,end_reason\r\n" {
		t.Errorf("history CSV: %d %q", w.Code, w.Body.String())
	}
	// without the header of the web UI, a page of another site can't download them
	if w, _ := admin.do("GET", "/api/connections/csv", "", false); w.Code != 403 {
		t.Errorf("CSV without the header: %d", w.Code)
	}
}
