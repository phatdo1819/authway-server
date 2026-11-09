package core

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	// the address that new servers propose to their peers
	PublicHost     string         `json:"public_host"`
	PasswordPolicy PasswordPolicy `json:"password_policy"`
	// every administrator logs in with a code of an authenticator app too
	RequireAdminMFA bool `json:"require_admin_mfa"`
	// with device binding, the hours a new peer, or a peer with new keys, can enroll its device
	EnrollHours int `json:"enroll_hours"`
	// the days the ended sessions, the connections, the events and the alerts stay in Activity
	HistoryDays int `json:"history_days"`
}

// SettingsInput changes the settings: a missing field keeps its value.
type SettingsInput struct {
	PublicHost      *string         `json:"public_host"`
	PasswordPolicy  *PasswordPolicy `json:"password_policy"`
	RequireAdminMFA *bool           `json:"require_admin_mfa"`
	EnrollHours     *int            `json:"enroll_hours"`
	HistoryDays     *int            `json:"history_days"`
}

// metaNumber is a number of the settings, or its default when it's missing or out of its range
func (s *Service) metaNumber(key string, fallback, highest int) int {
	value, err := s.db.Q().Meta(key)
	if err != nil {
		return fallback
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > highest {
		return fallback
	}
	return number
}

func (s *Service) enrollHoursLocked() int {
	return s.metaNumber("enroll_hours", DefaultEnrollHours, MaxEnrollHours)
}

func (s *Service) historyDaysLocked() int {
	return s.metaNumber("history_days", DefaultHistoryDays, MaxHistoryDays)
}

func (s *Service) publicHostLocked() (string, error) {
	host, err := s.db.Q().Meta("public_host")
	if err != nil {
		return "", err
	}
	if host == "" {
		host = s.opts.PublicHost
	}
	return host, nil
}

func (s *Service) requireAdminMFALocked() bool {
	value, err := s.db.Q().Meta("require_admin_mfa")
	return err == nil && value == "1"
}

func (s *Service) settingsLocked() (Settings, error) {
	host, err := s.publicHostLocked()
	if err != nil {
		return Settings{}, err
	}
	return Settings{PublicHost: host, PasswordPolicy: s.policyLocked(), RequireAdminMFA: s.requireAdminMFALocked(),
		EnrollHours: s.enrollHoursLocked(), HistoryDays: s.historyDaysLocked()}, nil
}

func (s *Service) Settings() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settingsLocked()
}

// SetSettings saves the settings that an administrator changes: by is that administrator. Asking an authenticator
// of every administrator needs one of the administrator who asks, who would be locked out of the settings otherwise.
func (s *Service) SetSettings(by Actor, input SettingsInput) (Settings, error) {
	var c checks
	var host string
	if input.PublicHost != nil {
		host = strings.TrimSpace(*input.PublicHost)
		if host != "" && !validHost(host) {
			c.fail("public_host", "invalid")
		}
	}
	if input.PasswordPolicy != nil && !input.PasswordPolicy.valid() {
		c.fail("min_length", "invalid")
	}
	if input.EnrollHours != nil && (*input.EnrollHours < 1 || *input.EnrollHours > MaxEnrollHours) {
		c.fail("enroll_hours", "invalid")
	}
	if input.HistoryDays != nil && (*input.HistoryDays < 1 || *input.HistoryDays > MaxHistoryDays) {
		c.fail("history_days", "invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return Settings{}, notFound(err)
	}
	if input.RequireAdminMFA != nil && *input.RequireAdminMFA && actor.TOTPSecret == "" {
		c.fail("require_admin_mfa", "enroll_first")
	}
	if err := c.err(); err != nil {
		return Settings{}, err
	}
	before, err := s.settingsLocked()
	if err != nil {
		return Settings{}, err
	}
	var changes []string
	if input.PublicHost != nil && host != before.PublicHost {
		if err := s.db.Q().SetMeta("public_host", host); err != nil {
			return Settings{}, err
		}
		changes = append(changes, "public address")
	}
	if input.PasswordPolicy != nil && *input.PasswordPolicy != before.PasswordPolicy {
		data, _ := json.Marshal(input.PasswordPolicy)
		if err := s.db.Q().SetMeta("password_policy", string(data)); err != nil {
			return Settings{}, err
		}
		changes = append(changes, "password policy")
	}
	if input.RequireAdminMFA != nil && *input.RequireAdminMFA != before.RequireAdminMFA {
		value := ""
		if *input.RequireAdminMFA {
			value = "1"
		}
		if err := s.db.Q().SetMeta("require_admin_mfa", value); err != nil {
			return Settings{}, err
		}
		if *input.RequireAdminMFA {
			changes = append(changes, "authenticator required for the administrators")
		} else {
			changes = append(changes, "authenticator no longer required for the administrators")
		}
	}
	if input.EnrollHours != nil && *input.EnrollHours != before.EnrollHours {
		if err := s.db.Q().SetMeta("enroll_hours", strconv.Itoa(*input.EnrollHours)); err != nil {
			return Settings{}, err
		}
		changes = append(changes, fmt.Sprintf("device enrollment %d hours", *input.EnrollHours))
	}
	if input.HistoryDays != nil && *input.HistoryDays != before.HistoryDays {
		if err := s.db.Q().SetMeta("history_days", strconv.Itoa(*input.HistoryDays)); err != nil {
			return Settings{}, err
		}
		changes = append(changes, fmt.Sprintf("history kept %d days, was %d", *input.HistoryDays, before.HistoryDays))
		// fewer days: the older rows go at the next pass, not in an hour
		if *input.HistoryDays < before.HistoryDays {
			s.pruned = time.Time{}
		}
	}
	if len(changes) > 0 {
		s.log.Info("settings changed", "by", actor.Username, "changes", strings.Join(changes, ", "))
		s.changeLocked(as(actor, by), adminEvent("settings_changed", "", "", strings.Join(changes, ", ")))
	}
	return s.settingsLocked()
}
