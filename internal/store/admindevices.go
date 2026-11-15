package store

import (
	"database/sql"
	"errors"
)

// Remembered administrator devices

// AdminDevice is a browser where an administrator logs in without a code of the authenticator, until ExpiresAt.
type AdminDevice struct {
	ID      int64
	AdminID int64
	// the SHA-256 of the token in the cookie of the browser, never the token
	TokenHash string
	// a fingerprint of the password and the authenticator of the administrator when the device was remembered
	Bound        string
	CreatedAt    int64
	ExpiresAt    int64
	LastUsedAt   int64
	LastUsedFrom string
}

// AdminDevice returns the remembered device of a token hash: ErrNotFound when there is none.
func (t *Tx) AdminDevice(tokenHash string) (*AdminDevice, error) {
	var d AdminDevice
	err := t.q.QueryRow(`SELECT id, admin_id, token_hash, bound, created_at, expires_at, last_used_at, last_used_from
		FROM admin_devices WHERE token_hash = ?`, tokenHash).Scan(&d.ID, &d.AdminID, &d.TokenHash, &d.Bound,
		&d.CreatedAt, &d.ExpiresAt, &d.LastUsedAt, &d.LastUsedFrom)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func (t *Tx) CreateAdminDevice(d *AdminDevice) error {
	result, err := t.q.Exec(`INSERT INTO admin_devices (admin_id, token_hash, bound, created_at, expires_at, last_used_at,
		last_used_from) VALUES (?, ?, ?, ?, ?, ?, ?)`, d.AdminID, d.TokenHash, d.Bound, d.CreatedAt, d.ExpiresAt,
		d.LastUsedAt, d.LastUsedFrom)
	if err != nil {
		return err
	}
	d.ID, err = result.LastInsertId()
	return err
}

func (t *Tx) UseAdminDevice(id, at int64, from string) error {
	return changed(t.q.Exec("UPDATE admin_devices SET last_used_at = ?, last_used_from = ? WHERE id = ?", at, from, id))
}

func (t *Tx) DeleteAdminDevice(id int64) error {
	_, err := t.q.Exec("DELETE FROM admin_devices WHERE id = ?", id)
	return err
}

// CountAdminDevices returns how many devices an administrator has remembered.
func (t *Tx) CountAdminDevices(adminID int64) (int, error) {
	var count int
	err := t.q.QueryRow("SELECT COUNT(*) FROM admin_devices WHERE admin_id = ?", adminID).Scan(&count)
	return count, err
}

// PruneAdminDevices deletes the remembered devices that expired before a time, and the oldest of an administrator
// beyond keep.
func (t *Tx) PruneAdminDevices(before int64, keep int) error {
	if _, err := t.q.Exec("DELETE FROM admin_devices WHERE expires_at < ?", before); err != nil {
		return err
	}
	_, err := t.q.Exec(`DELETE FROM admin_devices WHERE id IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER
		(PARTITION BY admin_id ORDER BY created_at DESC, id DESC) AS rank FROM admin_devices) WHERE rank > ?)`, keep)
	return err
}
