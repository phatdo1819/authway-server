package core

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/phatdo1819/authway-server/internal/store"
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
	// the days an administrator who logged in with a code can log in from the same browser without one, 0 when off
	AdminRememberDays int `json:"admin_remember_days"`
	// the flow logs: off, internal or all (see flowlog.go), and the days they're kept
	FlowLogs string `json:"flow_logs"`
	FlowDays int    `json:"flow_days"`
}

// SettingsInput changes the settings: a missing field keeps its value.
type SettingsInput struct {
	PublicHost      *string         `json:"public_host"`
	PasswordPolicy  *PasswordPolicy `json:"password_policy"`
	RequireAdminMFA *bool           `json:"require_admin_mfa"`
	EnrollHours     *int            `json:"enroll_hours"`
	HistoryDays     *int            `json:"history_days"`
	// 0 turns it off
	AdminRememberDays *int    `json:"admin_remember_days"`
	FlowLogs          *string `json:"flow_logs"`
	FlowDays          *int    `json:"flow_days"`
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
		EnrollHours: s.enrollHoursLocked(), HistoryDays: s.historyDaysLocked(), AdminRememberDays: s.adminRememberDaysLocked(),
		FlowLogs: s.flowModeLocked(), FlowDays: s.flowDaysLocked()}, nil
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
	if input.AdminRememberDays != nil && (*input.AdminRememberDays < 0 || *input.AdminRememberDays > MaxAdminRememberDays) {
		c.fail("admin_remember_days", "invalid")
	}
	if input.FlowLogs != nil && *input.FlowLogs != FlowsOff && *input.FlowLogs != FlowsInternal && *input.FlowLogs != FlowsAll {
		c.fail("flow_logs", "invalid")
	}
	if input.FlowDays != nil && (*input.FlowDays < 1 || *input.FlowDays > MaxFlowDays) {
		c.fail("flow_days", "invalid")
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
	// the values that change, written in one transaction: all of them or none
	var changes []string
	values := map[string]string{}
	if input.PublicHost != nil && host != before.PublicHost {
		values["public_host"] = host
		changes = append(changes, "public address")
	}
	if input.PasswordPolicy != nil && *input.PasswordPolicy != before.PasswordPolicy {
		data, _ := json.Marshal(input.PasswordPolicy)
		values["password_policy"] = string(data)
		changes = append(changes, "password policy")
	}
	if input.RequireAdminMFA != nil && *input.RequireAdminMFA != before.RequireAdminMFA {
		if *input.RequireAdminMFA {
			values["require_admin_mfa"] = "1"
			changes = append(changes, "authenticator required for the administrators")
		} else {
			values["require_admin_mfa"] = ""
			changes = append(changes, "authenticator no longer required for the administrators")
		}
	}
	if input.EnrollHours != nil && *input.EnrollHours != before.EnrollHours {
		values["enroll_hours"] = strconv.Itoa(*input.EnrollHours)
		changes = append(changes, fmt.Sprintf("device enrollment %d hours", *input.EnrollHours))
	}
	if input.HistoryDays != nil && *input.HistoryDays != before.HistoryDays {
		values["history_days"] = strconv.Itoa(*input.HistoryDays)
		changes = append(changes, fmt.Sprintf("history kept %d days, was %d", *input.HistoryDays, before.HistoryDays))
	}
	if input.AdminRememberDays != nil && *input.AdminRememberDays != before.AdminRememberDays {
		values[metaRememberDays] = strconv.Itoa(*input.AdminRememberDays)
		if *input.AdminRememberDays == 0 {
			changes = append(changes, "administrator devices no longer remembered")
		} else {
			changes = append(changes, fmt.Sprintf("administrator devices remembered %d days, was %d", *input.AdminRememberDays,
				before.AdminRememberDays))
		}
	}
	if input.FlowLogs != nil && *input.FlowLogs != before.FlowLogs {
		values["flow_logs"] = *input.FlowLogs
		changes = append(changes, "flow logs "+map[string]string{FlowsOff: "off", FlowsInternal: "on, internal traffic",
			FlowsAll: "on, all traffic"}[*input.FlowLogs])
	}
	if input.FlowDays != nil && *input.FlowDays != before.FlowDays {
		values["flow_days"] = strconv.Itoa(*input.FlowDays)
		changes = append(changes, fmt.Sprintf("flow logs kept %d days, was %d", *input.FlowDays, before.FlowDays))
	}
	if len(values) > 0 {
		err := s.db.Tx(func(tx *store.Tx) error {
			for key, value := range values {
				if err := tx.SetMeta(key, value); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return Settings{}, err
		}
	}
	// fewer days: the older rows go at the next pass, not in an hour
	if (input.HistoryDays != nil && *input.HistoryDays < before.HistoryDays) ||
		(input.FlowDays != nil && *input.FlowDays < before.FlowDays) {
		s.pruned = time.Time{}
	}
	if _, changed := values["flow_logs"]; changed {
		s.configureFlowsLocked()
	}
	if len(changes) > 0 {
		s.log.Info("settings changed", "by", actor.Username, "changes", strings.Join(changes, ", "))
		s.changeLocked(as(actor, by), adminEvent("settings_changed", "", "", strings.Join(changes, ", ")))
	}
	return s.settingsLocked()
}
