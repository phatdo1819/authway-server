package core

import (
	"reflect"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/secret"
)

// A file of a spreadsheet: a header in its own words, semicolons, the byte order mark of Excel. Users with and
// without a password, as Add user makes them.
func TestImport(t *testing.T) {
	f := setup(t)
	f.user("carol")
	bom := string(rune(0xfeff))
	file := bom + "User Name;Display name;PASSWORD\r\n" +
		"alice;Alice Martin;Sunny-Day-123\r\n" +
		"bob;;\r\n" +
		";;\r\n" +
		"dave;Dave;\r\n"
	// user name isn't a column: only username or user
	if _, err := f.s.Import(testActor, ImportInput{CSV: file, Check: true}); fields(t, err)["csv"] != "unknown_column" {
		t.Fatalf("header: %v", err)
	}
	file = strings.Replace(file, "User Name", "Username", 1)

	checked, err := f.s.Import(testActor, ImportInput{CSV: file, Check: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []ImportRow{
		{Line: 2, Username: "alice", FullName: "Alice Martin", Password: "given"},
		{Line: 3, Username: "bob", Password: "generated"},
		{Line: 5, Username: "dave", FullName: "Dave", Password: "generated"},
	}
	if !reflect.DeepEqual(checked.Rows, want) || checked.Users != 3 || checked.Invalid != 0 || checked.Imported {
		t.Fatalf("check: %+v", checked)
	}
	// a check adds nothing
	if users, _ := f.s.Users(); len(users) != 1 {
		t.Fatalf("users after the check: %d", len(users))
	}

	result, err := f.s.Import(testActor, ImportInput{CSV: file})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported || result.Users != 3 || len(result.Passwords) != 2 || result.Passwords[0].Username != "bob" ||
		result.Passwords[1].Username != "dave" {
		t.Fatalf("import: %+v", result)
	}
	// the passwords made, shown once, follow the policy and are the ones saved
	for _, entry := range result.Passwords {
		user, err := f.db.Q().UserByName(entry.Username)
		if err != nil || !secret.VerifyPassword(entry.Password, user.PasswordHash) || user.UpdatedBy != "tester" || user.Disabled {
			t.Fatalf("%s: %v %+v", entry.Username, err, user)
		}
		if code := DefaultPolicy.check(entry.Password, entry.Username, 0); code != "" || len(entry.Password) < 16 {
			t.Fatalf("made for %s: %s", entry.Username, code)
		}
	}
	alice, _ := f.db.Q().UserByName("alice")
	if !secret.VerifyPassword("Sunny-Day-123", alice.PasswordHash) || alice.FullName != "Alice Martin" {
		t.Fatalf("alice: %+v", alice)
	}
	// an event for each one, by the administrator
	added := 0
	for _, event := range f.webEvents() {
		if event.Kind == "user_added" && event.Detail == "imported" && event.By == "tester" {
			added++
		}
	}
	if added != 3 {
		t.Fatalf("events: %d", added)
	}

	// the same file again: they're all there now
	again, err := f.s.Import(testActor, ImportInput{CSV: file})
	if err != nil {
		t.Fatal(err)
	}
	if again.Imported || again.Invalid != 3 || again.Rows[0].Errors["username"] != "taken" {
		t.Fatalf("again: %+v", again)
	}
}

// Each row is checked as Add user does, and against the users there and the rows before it; a single error imports
// nothing.
func TestImportErrors(t *testing.T) {
	f := setup(t)
	f.user("carol")
	file := "username,full_name,password\n" +
		"ok,,Okay-pass-123\n" +
		"bad name,,\n" +
		"weak,,short\n" +
		"Carol,,\n" +
		",Nobody,\n" +
		"OK,,\n" +
		"fine,,,extra\n"
	result, err := f.s.Import(testActor, ImportInput{CSV: file})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported {
		t.Fatal("imported with errors")
	}
	got := map[int]map[string]string{}
	for _, row := range result.Rows {
		got[row.Line] = row.Errors
	}
	want := map[int]map[string]string{
		2: nil,
		3: {"username": "invalid"},
		4: {"password": "too_short"},
		5: {"username": "taken"},
		6: {"username": "required"},
		7: {"username": "twice"},
		8: {"row": "extra_cells"},
	}
	if !reflect.DeepEqual(got, want) || result.Invalid != 6 {
		t.Fatalf("errors (%d):\n%v\n%v", result.Invalid, got, want)
	}
	if users, _ := f.s.Users(); len(users) != 1 {
		t.Fatalf("users: %d", len(users))
	}

	for _, test := range []struct {
		file, code string
	}{
		{"", "empty"},
		{"username\n\n , \n", "no_rows"},
		{"full_name,password\nAlice,x\n", "no_username"},
		{"username,server\nalice,Office\n", "unknown_column"},
		{"username,user\nalice,alice\n", "duplicate_column"},
		{"username\n" + strings.Repeat("someone\n", MaxImportRows+1), "too_many_rows"},
		{"username\n\xff\n", "not_utf8"},
	} {
		if _, err := f.s.Import(testActor, ImportInput{CSV: test.file, Check: true}); fields(t, err)["csv"] != test.code {
			t.Errorf("%q: %v", test.file[:min(len(test.file), 30)], err)
		}
	}
}

// The passwords made for an import follow any policy, and never start with a symbol: the web UI gives them in a CSV
// file, where a spreadsheet would read = + or - first as a formula.
func TestNewPassword(t *testing.T) {
	policies := []PasswordPolicy{DefaultPolicy, {MinLength: 24, RequireLower: true, RequireUpper: true, RequireDigit: true, RequireSymbol: true}}
	for _, policy := range policies {
		for range 300 {
			password := newPassword(policy, "alice")
			if code := policy.check(password, "alice", 0); code != "" || len(password) < max(16, policy.MinLength) {
				t.Fatalf("%q: %s", password, code)
			}
			if strings.ContainsRune("-_.!?#%+=", rune(password[0])) {
				t.Fatalf("a symbol first: %q", password)
			}
		}
	}
}

// With SkipExisting, the rows of users already there are skipped instead of refused, in any case and whatever their
// cells say: those users don't change, their passwords neither. The other rows are checked and added as always.
func TestImportSkip(t *testing.T) {
	f := setup(t)
	carol := f.user("carol")
	before, _ := f.db.Q().UserByName("carol")
	file := "username,full_name,password\n" +
		"alice,Alice,\n" +
		"Carol,Someone Else,Other-Pass-9876\n" +
		"bob,Bob,\n"

	// without the option, carol stops the import
	strict, err := f.s.Import(testActor, ImportInput{CSV: file, Check: true})
	if err != nil || strict.Invalid != 1 || strict.Rows[1].Errors["username"] != "taken" {
		t.Fatalf("without skipping: %v %+v", err, strict)
	}

	checked, err := f.s.Import(testActor, ImportInput{CSV: file, Check: true, SkipExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	if checked.Invalid != 0 || checked.Users != 2 || checked.Skipped != 1 || !checked.Rows[1].Skipped ||
		checked.Rows[1].Password != "" || checked.Rows[1].Errors != nil || checked.Rows[0].Skipped {
		t.Fatalf("check: %+v", checked)
	}
	result, err := f.s.Import(testActor, ImportInput{CSV: file, SkipExisting: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Imported || result.Users != 2 || result.Skipped != 1 || len(result.Passwords) != 2 ||
		result.Passwords[0].Username != "alice" || result.Passwords[1].Username != "bob" {
		t.Fatalf("import: %+v", result)
	}
	// carol didn't change at all
	after, _ := f.db.Q().UserByName("carol")
	if *after != *before || after.ID != carol.ID {
		t.Fatalf("carol changed:\n%+v\n%+v", before, after)
	}
	// an event for each user added, none for carol
	for _, event := range f.webEvents() {
		if event.Kind == "user_added" && event.Detail == "imported" && strings.EqualFold(event.Username, "carol") {
			t.Fatal("an event for carol")
		}
	}
	// the same file again: everything skipped, nothing to add
	again, err := f.s.Import(testActor, ImportInput{CSV: file, SkipExisting: true})
	if err != nil || !again.Imported || again.Users != 0 || again.Skipped != 3 || len(again.Passwords) != 0 {
		t.Fatalf("again: %v %+v", err, again)
	}
	if users, _ := f.s.Users(); len(users) != 3 {
		t.Fatalf("users: %d", len(users))
	}
	// still refused: a row in error among the others, and the same new user twice
	bad := "username,password\nalice,\nnew,short\nnew2,\nNEW2,\n"
	refused, err := f.s.Import(testActor, ImportInput{CSV: bad, SkipExisting: true})
	if err != nil || refused.Imported || refused.Invalid != 2 || !refused.Rows[0].Skipped ||
		refused.Rows[1].Errors["password"] != "too_short" || refused.Rows[3].Errors["username"] != "twice" {
		t.Fatalf("errors with skipping: %v %+v", err, refused)
	}
}
