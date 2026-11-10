package admin

import (
	"encoding/json"
	"testing"
)

// Two administrators save the same user: the second form, opened before the first was saved, gets 409 with the user
// as it is now and who changed it.
func TestChangedAnswer(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	w, data := admin.do("POST", "/api/users", `{"username":"alice","password":"Secret,1234"}`, true)
	if w.Code != 200 || data["version"] != float64(1) {
		t.Fatalf("user: %d %v", w.Code, data)
	}
	if w, data := admin.do("PUT", "/api/users/1", `{"username":"alice","full_name":"Alice","version":1}`, true); w.Code != 200 || data["version"] != float64(2) {
		t.Fatalf("first save: %d %v", w.Code, data)
	}
	w, data = admin.do("PUT", "/api/users/1", `{"username":"alice","disabled":true,"version":1}`, true)
	current, _ := data["current"].(map[string]any)
	if w.Code != 409 || data["error"] != "changed" || data["by"] != "admin" || current["full_name"] != "Alice" ||
		current["version"] != float64(2) || current["disabled"] != false {
		t.Fatalf("second save: %d %v", w.Code, data)
	}
}

// The import is for the roles that manage the users.
func TestImportAPI(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	if w, data := admin.do("POST", "/api/admins", `{"username":"vic","role":"viewer","password":"Violet sky 98765"}`, true); w.Code != 200 {
		t.Fatalf("viewer: %d %v", w.Code, data)
	}
	body := func(csv string, check bool) string {
		data, _ := json.Marshal(map[string]any{"csv": csv, "check": check})
		return string(data)
	}
	file := "username,full_name\nalice,Alice\nbob,Bob\n"

	w, data := admin.do("POST", "/api/import", body("username,colour\nalice,red\n", true), true)
	if w.Code != 400 || data["fields"].(map[string]any)["csv"] != "unknown_column" || data["detail"] != "colour" {
		t.Fatalf("unknown column: %d %v", w.Code, data)
	}
	if w, data := admin.do("POST", "/api/import", body(file, true), true); w.Code != 200 || data["imported"] != false || data["users"] != float64(2) {
		t.Fatalf("check: %d %v", w.Code, data)
	}
	w, data = admin.do("POST", "/api/import", body(file, false), true)
	if w.Code != 200 || data["imported"] != true || len(data["passwords"].([]any)) != 2 {
		t.Fatalf("import: %d %v", w.Code, data)
	}

	viewer := &client{t: t, h: h}
	if code, data := viewer.login("vic", "Violet sky 98765", ""); code != 200 {
		t.Fatalf("viewer login: %d %v", code, data)
	}
	viewer.do("PUT", "/api/me/password", `{"current":"Violet sky 98765","password":"Violet sky 987654"}`, true)
	if w, data := viewer.do("POST", "/api/import", body(file, true), true); w.Code != 403 || data["error"] != "not_allowed" {
		t.Fatalf("viewer import: %d %v", w.Code, data)
	}
}

// skip_existing skips the users already there instead of refusing the file.
func TestImportSkipAPI(t *testing.T) {
	h := newTestAPI(t)
	admin := &client{t: t, h: h}
	if code, data := admin.login("admin", "Admin password 1", ""); code != 200 {
		t.Fatalf("login: %d %v", code, data)
	}
	if w, data := admin.do("POST", "/api/users", `{"username":"alice","password":"Secret,1234"}`, true); w.Code != 200 {
		t.Fatalf("user: %d %v", w.Code, data)
	}
	body := func(skip bool) string {
		data, _ := json.Marshal(map[string]any{"csv": "username\nalice\nbob\n", "skip_existing": skip})
		return string(data)
	}
	if w, data := admin.do("POST", "/api/import", body(false), true); w.Code != 200 || data["imported"] != false || data["invalid"] != float64(1) {
		t.Fatalf("without skipping: %d %v", w.Code, data)
	}
	w, data := admin.do("POST", "/api/import", body(true), true)
	rows, _ := data["rows"].([]any)
	if w.Code != 200 || data["imported"] != true || data["users"] != float64(1) || data["skipped"] != float64(1) || len(rows) != 2 ||
		rows[0].(map[string]any)["skipped"] != true {
		t.Fatalf("skipping: %d %v", w.Code, data)
	}
}
