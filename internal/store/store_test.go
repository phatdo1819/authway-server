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

// The lock mode off of up to 0.2.0 is written as roaming when the database opens, without a change of the schema.
func TestLockOffRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authway.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for index, lock := range []string{LockOff, LockStrict} {
		if _, err := s.db.Exec("INSERT INTO servers (name, interface, listen_port, public_host, private_key, network, lock_endpoint, created_at, updated_at) VALUES (?, ?, ?, 'vpn.example.com', 'key', '10.8.0.0/24', ?, 0, 0)",
			fmt.Sprintf("s%d", index), fmt.Sprintf("wg%d", index), 51820+index, lock); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Migrated != (Migration{}) {
		t.Errorf("a change of the schema: %+v", s.Migrated)
	}
	rows, err := s.db.Query("SELECT lock_endpoint FROM servers ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var locks []string
	for rows.Next() {
		var lock string
		rows.Scan(&lock)
		locks = append(locks, lock)
	}
	if strings.Join(locks, ",") != LockRoaming+","+LockStrict {
		t.Errorf("locks: %v", locks)
	}
}

// The authenticators of before the upgrade count as used when their user had a session on a server that asks for a
// code since the key was made; the others wait for their first code.
func TestTOTPConfirmedMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authway.db")
	// the schema before migration 10, which adds totp_confirmed_at
	olderDatabase(t, path, 9)
	db, _ := openDB(path)
	for _, statement := range []string{
		"INSERT INTO servers (id, name, interface, listen_port, public_host, private_key, network, auth_mode, created_at, updated_at) VALUES (1, 'otp', 'wg0', 51820, 'vpn.example.com', 'key', '10.8.0.0/24', 'password_otp', 0, 0)",
		"INSERT INTO servers (id, name, interface, listen_port, public_host, private_key, network, auth_mode, created_at, updated_at) VALUES (2, 'password', 'wg1', 51821, 'vpn.example.com', 'key', '10.8.1.0/24', 'password', 0, 0)",
		// 1 logged in with a code; 2 only on a server without codes; 3 got a new key after its login; 4 has no key
		"INSERT INTO users (id, username, totp_secret, created_at, updated_at) VALUES (1, 'used', 'S', 0, 0), (2, 'nocode', 'S', 0, 0), (3, 'renewed', 'S', 0, 0), (4, 'none', '', 0, 0)",
		"INSERT INTO sessions (server_id, peer_id, user_id, server_name, peer_name, username, address, started_at, expires_at) VALUES (1, 1, 1, 'otp', 'p', 'used', '10.8.0.2', 100, 200), (1, 1, 1, 'otp', 'p', 'used', '10.8.0.2', 300, 400), (2, 2, 2, 'password', 'p', 'nocode', '10.8.1.2', 100, 200), (1, 3, 3, 'otp', 'p', 'renewed', '10.8.0.3', 100, 200), (1, 4, 4, 'otp', 'p', 'none', '10.8.0.4', 100, 200)",
		"INSERT INTO events (at, kind, username) VALUES (50, 'user_mfa_on', 'used'), (150, 'user_mfa_on', 'Renewed')",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want := map[int64]int64{1: 300, 2: 0, 3: 0, 4: 0}
	for id, at := range want {
		user, err := s.Q().User(id)
		if err != nil {
			t.Fatal(err)
		}
		if user.TOTPConfirmedAt != at {
			t.Errorf("%s: confirmed at %d, want %d", user.Username, user.TOTPConfirmedAt, at)
		}
	}
	// once, and only for a key
	if err := s.Q().ConfirmUserTOTP(2, 500); err != nil {
		t.Fatal(err)
	}
	s.Q().ConfirmUserTOTP(2, 600)
	s.Q().ConfirmUserTOTP(4, 500)
	if user, _ := s.Q().User(2); user.TOTPConfirmedAt != 500 || user.Version != 1 {
		t.Errorf("confirmed: %+v", user)
	}
	if user, _ := s.Q().User(4); user.TOTPConfirmedAt != 0 {
		t.Errorf("without a key: %+v", user)
	}
}

// The latest connection of each peer is the one seen last, and of two seen at the same time the later row.
func TestLatestConnections(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "authway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := s.Q()
	if latest, err := q.LatestConnections([]int64{1}); err != nil || len(latest) != 0 {
		t.Fatalf("an empty history: %v %v", latest, err)
	}
	// the rows get the ids 1 to 6 in this order
	for _, row := range []struct{ peer, seen int64 }{{1, 100}, {1, 300}, {1, 200}, {2, 50}, {2, 50}, {3, 10}} {
		c := &Connection{ServerID: 1, PeerID: row.peer, ServerName: "s", PeerName: "p", Address: "10.8.0.2",
			StartedAt: row.seen, LastSeen: row.seen}
		if err := q.CreateConnection(c); err != nil {
			t.Fatal(err)
		}
	}
	// peer 3 isn't asked for, peer 4 has no history
	latest, err := q.LatestConnections([]int64{1, 2, 4})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]int64{1: 2, 2: 5}
	if len(latest) != len(want) {
		t.Fatalf("latest: %+v", latest)
	}
	for peer, id := range want {
		if latest[peer].ID != id || latest[peer].PeerID != peer {
			t.Errorf("peer %d: row %d, want %d", peer, latest[peer].ID, id)
		}
	}
	// straight from the index, without sorting the history
	rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT id FROM connections WHERE peer_id = ? ORDER BY last_seen DESC, id DESC LIMIT 1", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if text := strings.Join(plan, "; "); !strings.Contains(text, "connections_by_peer") || strings.Contains(text, "TEMP B-TREE") {
		t.Errorf("query plan: %s", text)
	}
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
