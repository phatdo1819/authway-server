package core

import (
	"strconv"
	"time"

	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
)

// An administrator with an authenticator can ask the web UI to remember the browser: there, the password is enough
// for AdminRememberDays, without a code. The browser keeps a random token in a cookie, the database only its
// SHA-256. A remembered device stops working when its days are over, when the setting gets shorter or off, and when
// the password or the authenticator of the administrator changes. Deleting the administrator deletes it, and so does
// a restore.

const (
	DefaultAdminRememberDays = 30
	MaxAdminRememberDays     = 90
	// the devices kept for an administrator: the oldest go first
	maxAdminDevices  = 10
	metaRememberDays = "admin_remember_days"
)

// adminBound is the fingerprint of the password and the authenticator of an administrator: a new one of either
// changes it.
func adminBound(admin *store.Admin) string {
	return secret.Fingerprint("authway-admin-device\n" + admin.PasswordHash + "\n" + admin.TOTPSecret)
}

// adminRememberDaysLocked is the days a device is remembered, 0 when it's off.
func (s *Service) adminRememberDaysLocked() int {
	value, err := s.db.Q().Meta(metaRememberDays)
	if err != nil || value == "" {
		return DefaultAdminRememberDays
	}
	days, err := strconv.Atoi(value)
	if err != nil || days < 0 || days > MaxAdminRememberDays {
		return DefaultAdminRememberDays
	}
	return days
}

// AdminRememberDays is the days a device is remembered, 0 when it's off.
func (s *Service) AdminRememberDays() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adminRememberDaysLocked()
}

// RememberAdminDevice remembers the browser of an administrator who just logged in with a code. It returns the token
// for its cookie and how long it lasts, "" when remembering is off or the administrator has no authenticator.
func (s *Service) RememberAdminDevice(id int64, source string) (string, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	days := s.adminRememberDaysLocked()
	admin, err := s.db.Q().Admin(id)
	if days == 0 || err != nil || admin.TOTPSecret == "" || admin.Disabled {
		return "", 0
	}
	now := s.now()
	life := time.Duration(days) * 24 * time.Hour
	token := secret.Token(32)
	device := &store.AdminDevice{AdminID: id, TokenHash: secret.Fingerprint(token), Bound: adminBound(admin),
		CreatedAt: now.Unix(), ExpiresAt: now.Add(life).Unix(), LastUsedAt: now.Unix(), LastUsedFrom: source}
	err = s.db.Tx(func(tx *store.Tx) error {
		if err := tx.CreateAdminDevice(device); err != nil {
			return err
		}
		return tx.PruneAdminDevices(now.Unix(), maxAdminDevices)
	})
	if err != nil {
		s.log.Warn("can't remember the device of an administrator", "user", admin.Username, "error", err)
		return "", 0
	}
	s.log.Info("administrator device remembered", "user", admin.Username, "from", source, "days", days)
	return token, life
}

// RememberedAdmin tells whether a token is of a device remembered by an administrator that still works: the
// administrator then logs in without a code. A device that no longer works is deleted.
func (s *Service) RememberedAdmin(id int64, token, source string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.db.Q()
	device, err := q.AdminDevice(secret.Fingerprint(token))
	if err != nil {
		return false
	}
	// the browser was remembered by another administrator: it stays theirs
	if device.AdminID != id {
		return false
	}
	now := s.now().Unix()
	days := int64(s.adminRememberDaysLocked())
	admin, err := q.Admin(id)
	if err != nil || admin.Disabled || admin.TOTPSecret == "" || device.Bound != adminBound(admin) ||
		now >= device.ExpiresAt || now >= device.CreatedAt+days*24*3600 {
		if err := q.DeleteAdminDevice(device.ID); err != nil {
			s.log.Warn("can't forget the device of an administrator", "error", err)
		}
		return false
	}
	if err := q.UseAdminDevice(device.ID, now, source); err != nil {
		s.log.Warn("can't record the use of the device of an administrator", "error", err)
	}
	return true
}
