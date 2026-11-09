// Package store keeps the configuration and the sessions in a SQLite database.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	// a name or a value that must be unique is taken
	ErrConflict = errors.New("conflict")
)

// the changes of the schema, in order: never edit one that is released, add a new one
var migrations = []string{
	`CREATE TABLE meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	CREATE TABLE admins (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		full_name TEXT NOT NULL DEFAULT '',
		password_hash TEXT NOT NULL DEFAULT '',
		totp_secret TEXT NOT NULL DEFAULT '',
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE servers (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE COLLATE NOCASE,
		interface TEXT NOT NULL UNIQUE,
		enabled INTEGER NOT NULL DEFAULT 1,
		listen_port INTEGER NOT NULL UNIQUE,
		public_host TEXT NOT NULL,
		public_port INTEGER NOT NULL DEFAULT 0,
		private_key TEXT NOT NULL,
		network TEXT NOT NULL,
		networks TEXT NOT NULL DEFAULT '[]',
		dns TEXT NOT NULL DEFAULT '[]',
		mtu INTEGER NOT NULL DEFAULT 0,
		keepalive INTEGER NOT NULL DEFAULT 25,
		auth_mode TEXT NOT NULL DEFAULT 'key',
		session_timeout INTEGER NOT NULL DEFAULT 28800,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE peers (
		id INTEGER PRIMARY KEY,
		server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
		name TEXT NOT NULL COLLATE NOCASE,
		enabled INTEGER NOT NULL DEFAULT 1,
		user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		address TEXT NOT NULL,
		private_key TEXT NOT NULL,
		public_key TEXT NOT NULL UNIQUE,
		preshared_key TEXT NOT NULL,
		route_all INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		UNIQUE (server_id, name),
		UNIQUE (server_id, address),
		UNIQUE (server_id, user_id)
	);
	CREATE TABLE sessions (
		id INTEGER PRIMARY KEY,
		server_id INTEGER NOT NULL,
		peer_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		server_name TEXT NOT NULL,
		peer_name TEXT NOT NULL,
		username TEXT NOT NULL,
		address TEXT NOT NULL,
		endpoint TEXT NOT NULL DEFAULT '',
		started_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		ended_at INTEGER NOT NULL DEFAULT 0,
		end_reason TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX sessions_by_end ON sessions (ended_at, started_at);
	CREATE TABLE events (
		id INTEGER PRIMARY KEY,
		at INTEGER NOT NULL,
		kind TEXT NOT NULL,
		server_name TEXT NOT NULL DEFAULT '',
		peer_name TEXT NOT NULL DEFAULT '',
		username TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX events_by_time ON events (at);`,
	`ALTER TABLE servers ADD COLUMN lock_endpoint TEXT NOT NULL DEFAULT 'strict';
	ALTER TABLE servers ADD COLUMN detect_copies INTEGER NOT NULL DEFAULT 1;
	ALTER TABLE servers ADD COLUMN block_copies INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE servers ADD COLUMN redirect INTEGER NOT NULL DEFAULT 1;
	ALTER TABLE servers ADD COLUMN fallback_endpoints TEXT NOT NULL DEFAULT '[]';
	ALTER TABLE peers ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE sessions ADD COLUMN paused_at INTEGER NOT NULL DEFAULT 0;
	CREATE TABLE alerts (
		id INTEGER PRIMARY KEY,
		peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
		at INTEGER NOT NULL,
		kind TEXT NOT NULL,
		username TEXT NOT NULL DEFAULT '',
		addresses TEXT NOT NULL DEFAULT '[]'
	);
	CREATE INDEX alerts_by_peer ON alerts (peer_id, at);`,
	`ALTER TABLE admins ADD COLUMN full_name TEXT NOT NULL DEFAULT '';
	ALTER TABLE admins ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
	ALTER TABLE admins ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
	ALTER TABLE admins ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE admins ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE admins ADD COLUMN last_login_at INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE admins ADD COLUMN last_login_from TEXT NOT NULL DEFAULT '';
	ALTER TABLE admins ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;`,
	`ALTER TABLE servers ADD COLUMN device_binding INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE servers ADD COLUMN machine_id INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE servers ADD COLUMN client_to_client INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE servers ADD COLUMN reachable_servers TEXT NOT NULL DEFAULT '[]';
	CREATE TABLE devices (
		peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
		window_until INTEGER NOT NULL DEFAULT 0,
		device_key TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL DEFAULT '',
		device_name TEXT NOT NULL DEFAULT '',
		machine_id TEXT NOT NULL DEFAULT '',
		enrolled_at INTEGER NOT NULL DEFAULT 0,
		last_used_at INTEGER NOT NULL DEFAULT 0,
		last_from TEXT NOT NULL DEFAULT '',
		wireguard_key TEXT NOT NULL DEFAULT '',
		wireguard_key_at INTEGER NOT NULL DEFAULT 0
	);
	CREATE UNIQUE INDEX devices_by_wireguard_key ON devices (wireguard_key) WHERE wireguard_key != '';
	CREATE TABLE connections (
		id INTEGER PRIMARY KEY,
		server_id INTEGER NOT NULL,
		peer_id INTEGER NOT NULL,
		server_name TEXT NOT NULL,
		peer_name TEXT NOT NULL,
		username TEXT NOT NULL DEFAULT '',
		address TEXT NOT NULL,
		endpoint TEXT NOT NULL DEFAULT '',
		started_at INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		ended_at INTEGER NOT NULL DEFAULT 0,
		received INTEGER NOT NULL DEFAULT 0,
		sent INTEGER NOT NULL DEFAULT 0,
		rx_start INTEGER NOT NULL DEFAULT 0,
		tx_start INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX connections_by_end ON connections (ended_at, last_seen);`,
	// 5: the administrator who made a change in the web UI
	`ALTER TABLE events ADD COLUMN actor TEXT NOT NULL DEFAULT '';`,
	// 6: the IPv6 network of the tunnels
	`ALTER TABLE servers ADD COLUMN network6 TEXT NOT NULL DEFAULT '';`,
	// 7: the servers routed to their networks, without the address translation
	`ALTER TABLE servers ADD COLUMN routed INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE servers ADD COLUMN inbound INTEGER NOT NULL DEFAULT 0;`,
}

// Store is safe for concurrent use: database/sql serializes on its single connection.
type Store struct {
	db *sql.DB
}

// Open opens the database at path, creating it and updating its schema when needed.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// one connection: SQLite writes one at a time anyway, and the pragmas hold for every query
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("the database is from a newer version of Authway Server (schema %d)", version)
	}
	for index := version; index < len(migrations); index++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[index]); err != nil {
			tx.Rollback()
			return fmt.Errorf("schema %d: %w", index+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", index+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Tx runs fn in a transaction: all its changes are saved, or none.
func (s *Store) Tx(fn func(tx *Tx) error) error {
	sqlTx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(&Tx{q: sqlTx}); err != nil {
		sqlTx.Rollback()
		return err
	}
	return sqlTx.Commit()
}

// Tx has the same methods as Store, inside a transaction.
type Tx struct {
	q querier
}

type querier interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Q gives the methods of the store outside a transaction.
func (s *Store) Q() *Tx {
	return &Tx{q: s.db}
}

func conflict(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func toJSON(values []string) string {
	if values == nil {
		values = []string{}
	}
	data, _ := json.Marshal(values)
	return string(data)
}

func fromJSON(text string) []string {
	var values []string
	if json.Unmarshal([]byte(text), &values) != nil || values == nil {
		return []string{}
	}
	return values
}

func idsToJSON(values []int64) string {
	if values == nil {
		values = []int64{}
	}
	data, _ := json.Marshal(values)
	return string(data)
}

func idsFromJSON(text string) []int64 {
	var values []int64
	if json.Unmarshal([]byte(text), &values) != nil || values == nil {
		return []int64{}
	}
	return values
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// Meta returns a value of the meta table, "" when missing.
func (t *Tx) Meta(key string) (string, error) {
	var value string
	err := t.q.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (t *Tx) SetMeta(key, value string) error {
	_, err := t.q.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value", key, value)
	return err
}
