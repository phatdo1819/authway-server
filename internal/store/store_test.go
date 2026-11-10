package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// olderDatabase makes a database of the schema of an older version: its first migrations only.
func olderDatabase(t *testing.T, path string, version int) {
	t.Helper()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, migration := range migrations[:version] {
		if _, err := db.Exec(migration); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		t.Fatal(err)
	}
}

func schemaOf(t *testing.T, path string) int {
	t.Helper()
	version, err := SchemaOf(path)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// A new database gets the schema of this version, no copy. One of an older version is copied first, whole: the
// version of before opens the copy. One of a newer version isn't opened.
func TestSchemaChange(t *testing.T) {
	dir := t.TempDir()
	if schemaOf(t, filepath.Join(dir, "none.db")) != 0 {
		t.Error("a database that isn't there")
	}

	fresh := filepath.Join(dir, "fresh.db")
	s, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.Migrated != (Migration{}) || schemaOf(t, fresh) != Schema() {
		t.Errorf("new: %+v, schema %d", s.Migrated, schemaOf(t, fresh))
	}

	older := filepath.Join(dir, "authway.db")
	olderDatabase(t, older, Schema()-1)
	db, _ := openDB(older)
	if _, err := db.Exec("INSERT INTO meta (key, value) VALUES ('public_host', 'vpn.example.com')"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = Open(older)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	m := s.Migrated
	if m.From != Schema()-1 || m.To != Schema() || !strings.HasPrefix(filepath.Base(filepath.Dir(m.Copy)), fmt.Sprintf("before-schema%d-", Schema())) ||
		filepath.Base(m.Copy) != "authway.db" {
		t.Fatalf("migrated: %+v", m)
	}
	if schemaOf(t, older) != Schema() || schemaOf(t, m.Copy) != Schema()-1 {
		t.Errorf("schemas: %d, copy %d", schemaOf(t, older), schemaOf(t, m.Copy))
	}
	copied, _ := sql.Open("sqlite", "file:"+m.Copy)
	var host string
	if err := copied.QueryRow("SELECT value FROM meta WHERE key = 'public_host'").Scan(&host); err != nil || host != "vpn.example.com" {
		t.Errorf("the copy: %q %v", host, err)
	}
	copied.Close()

	// once changed, nothing more to copy
	s, err = Open(older)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.Migrated != (Migration{}) {
		t.Errorf("opened again: %+v", s.Migrated)
	}

	newer := filepath.Join(dir, "newer.db")
	db, _ = openDB(newer)
	db.Exec(fmt.Sprintf("PRAGMA user_version = %d", Schema()+1))
	db.Close()
	if _, err := Open(newer); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("newer: %v", err)
	}
	if schemaOf(t, newer) != Schema()+1 {
		t.Error("the schema of a newer database")
	}
}
