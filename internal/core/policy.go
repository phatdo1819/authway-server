package core

import (
	"encoding/json"
	"strings"
	"unicode"
)

// PasswordPolicy is what the passwords that people choose must have, for the users and the administrators. The
// passwords that the server makes itself (16 random letters and digits) don't follow it: they're changed at the
// first login.
type PasswordPolicy struct {
	MinLength     int  `json:"min_length"`
	RequireLower  bool `json:"require_lower"`
	RequireUpper  bool `json:"require_upper"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`
}

const (
	// the policy can't ask for less, or for more
	PolicyMinLength = 8
	PolicyMaxLength = 64
	// the administrators have at least this, whatever the policy
	AdminMinPassword = 12
)

// DefaultPolicy is the policy until an administrator changes it.
var DefaultPolicy = PasswordPolicy{MinLength: 10, RequireLower: true, RequireUpper: true, RequireDigit: true}

func (p PasswordPolicy) valid() bool {
	return p.MinLength >= PolicyMinLength && p.MinLength <= PolicyMaxLength
}

// check returns the code of the first rule that the password breaks, "" when it follows them all. minLength raises
// the minimum of the policy, for the administrators.
func (p PasswordPolicy) check(password, username string, minLength int) string {
	length := len([]rune(password))
	if minLength < p.MinLength {
		minLength = p.MinLength
	}
	switch {
	case length < minLength:
		return "too_short"
	case len(password) > MaxPassword:
		return "too_long"
	}
	var lower, upper, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsLetter(r):
			// a letter without case, of a script that has none: a letter all the same
			lower, upper = true, true
		default:
			symbol = true
		}
	}
	switch {
	case p.RequireLower && !lower:
		return "needs_lower"
	case p.RequireUpper && !upper:
		return "needs_upper"
	case p.RequireDigit && !digit:
		return "needs_digit"
	case p.RequireSymbol && !symbol:
		return "needs_symbol"
	}
	if name := strings.ToLower(username); len([]rune(name)) >= 3 && strings.Contains(strings.ToLower(password), name) {
		return "contains_username"
	}
	return ""
}

// policyLocked returns the policy saved, the default one when there is none.
func (s *Service) policyLocked() PasswordPolicy {
	text, err := s.db.Q().Meta("password_policy")
	if err != nil || text == "" {
		return DefaultPolicy
	}
	var policy PasswordPolicy
	if json.Unmarshal([]byte(text), &policy) != nil || !policy.valid() {
		return DefaultPolicy
	}
	return policy
}

// PasswordPolicy returns the policy of the passwords.
func (s *Service) PasswordPolicy() PasswordPolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyLocked()
}
