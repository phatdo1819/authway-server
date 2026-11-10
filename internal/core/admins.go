package core

import (
	"errors"
	"strings"
	"time"

	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

// What an administrator must do before using the web UI.
const (
	SetupPassword = "password" // choose a password: another administrator or the command line set the current one
	SetupMFA      = "mfa"      // set up an authenticator app: the settings ask one of every administrator
)

// An authenticator being set up waits this long for its first code.
const pendingTOTPTime = 10 * time.Minute

// RefusedError is a change that the rules of the administrators don't allow: Code says which rule.
type RefusedError struct {
	Code string
}

func (e *RefusedError) Error() string {
	return "refused: " + e.Code
}

var roleNames = map[string]string{
	store.RoleAdmin:    "Administrator",
	store.RoleOperator: "Operator",
	store.RoleViewer:   "Read-only",
}

// RoleRank orders the roles: a route needs a rank, the role of the administrator gives one. 0: no role.
func RoleRank(role string) int {
	switch role {
	case store.RoleViewer:
		return 1
	case store.RoleOperator:
		return 2
	case store.RoleAdmin:
		return 3
	}
	return 0
}

type AdminView struct {
	ID                 int64  `json:"id"`
	Username           string `json:"username"`
	FullName           string `json:"full_name"`
	Role               string `json:"role"`
	TOTP               bool   `json:"totp"`
	Disabled           bool   `json:"disabled"`
	MustChangePassword bool   `json:"must_change_password"`
	LastLoginAt        int64  `json:"last_login_at"`
	LastLoginFrom      string `json:"last_login_from"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
	// Version counts the changes made by the administrators: a form sends the one it opened with, and a change
	// made since refuses the save. UpdatedBy made the latest one
	Version   int64  `json:"version"`
	UpdatedBy string `json:"updated_by"`
}

func adminView(a *store.Admin) AdminView {
	return AdminView{
		ID: a.ID, Username: a.Username, FullName: a.FullName, Role: a.Role, TOTP: a.TOTPSecret != "",
		Disabled: a.Disabled, MustChangePassword: a.MustChangePassword, LastLoginAt: a.LastLoginAt,
		LastLoginFrom: a.LastLoginFrom, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, Version: a.Version,
		UpdatedBy: a.UpdatedBy,
	}
}

// AdminInput adds or edits an administrator. The username and the password are read only when it's added: the
// password is the first one, which the new administrator changes at the first login.
type AdminInput struct {
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
	Password string `json:"password"`
	// when edited: the version the form opened with, see ChangedError; 0 doesn't check it
	Version int64 `json:"version"`
}

type pendingSecret struct {
	secret string
	at     time.Time
}

func adminEvent(kind, username, source, detail string) store.Event {
	return store.Event{Kind: kind, Username: username, Source: source, Detail: detail}
}

// as is the actor of a change with the username of the database, the address of the request
func as(admin *store.Admin, by Actor) Actor {
	return Actor{ID: admin.ID, Username: admin.Username, From: by.From}
}

// EnsureAdmin creates the first administrator when there is none, with the password given or a random one, and
// returns that password; "" when an administrator exists. A random password is in the log of the container: the
// administrator changes it at the first login.
func (s *Service) EnsureAdmin(username, password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count, err := s.db.Q().CountAdmins()
	if err != nil || count > 0 {
		return "", err
	}
	generated := password == ""
	if generated {
		password = secret.Password(16)
	}
	hash, err := secret.HashPassword(password)
	if err != nil {
		return "", err
	}
	admin := &store.Admin{Username: username, PasswordHash: hash, Role: store.RoleAdmin, MustChangePassword: generated,
		CreatedAt: s.now().Unix()}
	if err := s.db.Q().CreateAdmin(admin); err != nil {
		return "", err
	}
	return password, nil
}

// AdminLogin checks the credentials of an administrator. A disabled administrator is returned too: the caller
// says so, once the password is right.
func (s *Service) AdminLogin(username, password string) (*store.Admin, bool) {
	s.mu.Lock()
	admin, err := s.db.Q().AdminByName(strings.TrimSpace(username))
	s.mu.Unlock()
	if err != nil || len(password) > MaxPassword {
		secret.SpendCheck(password)
		return nil, false
	}
	if !secret.VerifyPassword(password, admin.PasswordHash) {
		return nil, false
	}
	return admin, true
}

// CheckAdminCode checks a code of the authenticator of an administrator; each code works once.
func (s *Service) CheckAdminCode(id int64, code string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, err := s.db.Q().Admin(id)
	if err != nil || admin.TOTPSecret == "" {
		return false
	}
	now := s.now()
	counter, ok := totp.Verify(admin.TOTPSecret, code, now)
	return ok && !s.adminCodeUsedLocked(id, counter, now)
}

func (s *Service) adminCodeUsedLocked(id int64, counter uint64, now time.Time) bool {
	codes := s.usedAdminCodes[id]
	if codes == nil {
		codes = map[uint64]time.Time{}
		s.usedAdminCodes[id] = codes
	}
	if _, used := codes[counter]; used {
		return true
	}
	codes[counter] = now
	return false
}

// AdminLoggedIn records a login of an administrator.
func (s *Service) AdminLoggedIn(id int64, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, err := s.db.Q().Admin(id)
	if err != nil {
		return
	}
	if err := s.db.Q().SetAdminLogin(id, s.now().Unix(), source); err != nil {
		s.log.Error("can't save the login of an administrator", "error", err)
	}
	s.eventLocked(adminEvent("admin_login", admin.Username, source, ""))
}

// AdminLoginFailed records a failed login of the web UI: reason says what was wrong. The username is kept only when
// it's the one of an administrator: what's typed there can be a password, and the events are read by every role. It
// returns the username kept, "" for an unknown one.
func (s *Service) AdminLoginFailed(username, source, reason string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, err := s.db.Q().AdminByName(strings.TrimSpace(username))
	if err != nil {
		s.eventLocked(adminEvent("admin_login_failed", "", source, "unknown username"))
		return ""
	}
	s.eventLocked(adminEvent("admin_login_failed", admin.Username, source, reason))
	return admin.Username
}

func (s *Service) Admin(id int64) (*store.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, err := s.db.Q().Admin(id)
	return admin, notFound(err)
}

// AdminAccess returns an administrator who can use the web UI, with what it must do first ("" when nothing):
// ErrNotFound when it's deleted or disabled. The web UI asks at every request, so a change applies at once.
func (s *Service) AdminAccess(id int64) (*store.Admin, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adminAccessLocked(id)
}

// ErrStale is a session of the web UI opened before a restore: its id can be another administrator now.
var ErrStale = errors.New("stale_session")

// Generation counts the restores of a backup. A session of the web UI keeps the one of its login.
func (s *Service) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// AdminAccessSince is AdminAccess for a session opened at a generation: ErrStale when a backup was restored since,
// checked with the same lock as the read of the administrator, so no request runs as another one.
func (s *Service) AdminAccessSince(id int64, generation uint64) (*store.Admin, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return nil, "", ErrStale
	}
	return s.adminAccessLocked(id)
}

func (s *Service) adminAccessLocked(id int64) (*store.Admin, string, error) {
	admin, err := s.db.Q().Admin(id)
	if err != nil || admin.Disabled {
		return nil, "", ErrNotFound
	}
	switch {
	case admin.MustChangePassword:
		return admin, SetupPassword, nil
	case admin.TOTPSecret == "" && s.requireAdminMFALocked():
		return admin, SetupMFA, nil
	}
	return admin, "", nil
}

func (s *Service) Admins() ([]AdminView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.db.Q().Admins()
	if err != nil {
		return nil, err
	}
	views := make([]AdminView, 0, len(list))
	for index := range list {
		views = append(views, adminView(&list[index]))
	}
	return views, nil
}

func (s *Service) checkAdminPassword(password, username string) string {
	if password == "" {
		return "required"
	}
	return s.PasswordPolicy().check(password, username, AdminMinPassword)
}

// CreateAdmin adds an administrator, who changes the password at the first login: by is the administrator who adds.
func (s *Service) CreateAdmin(by Actor, input AdminInput) (*AdminView, error) {
	var c checks
	username := strings.TrimSpace(input.Username)
	switch {
	case username == "":
		c.fail("username", "required")
	case !usernamePattern.MatchString(username):
		c.fail("username", "invalid")
	}
	if !validFullName(input.FullName) {
		c.fail("full_name", "invalid")
	}
	if RoleRank(input.Role) == 0 {
		c.fail("role", "invalid")
	}
	if code := s.checkAdminPassword(input.Password, username); code != "" {
		c.fail("password", code)
	}
	if err := c.err(); err != nil {
		return nil, err
	}
	hash, err := secret.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err := s.db.Q().AdminByName(username); err == nil {
		return nil, &ValidationError{Fields: map[string]string{"username": "taken"}}
	}
	now := s.now().Unix()
	admin := &store.Admin{
		Username: username, FullName: strings.TrimSpace(input.FullName), PasswordHash: hash, Role: input.Role,
		Disabled: input.Disabled, MustChangePassword: true, CreatedAt: now, UpdatedAt: now, UpdatedBy: actor.Username,
	}
	if err := s.db.Q().CreateAdmin(admin); err != nil {
		return nil, takenOr(err, "username")
	}
	s.log.Info("administrator added", "user", admin.Username, "role", admin.Role, "by", actor.Username)
	s.changeLocked(as(actor, by), adminEvent("admin_added", admin.Username, "", roleNames[admin.Role]))
	view := adminView(admin)
	return &view, nil
}

// UpdateAdmin changes the name, the role and the state of an administrator. Nobody changes their own role or
// disables themselves, and an active administrator with the role admin always stays.
func (s *Service) UpdateAdmin(by Actor, id int64, input AdminInput) (*AdminView, error) {
	var c checks
	if !validFullName(input.FullName) {
		c.fail("full_name", "invalid")
	}
	if RoleRank(input.Role) == 0 {
		c.fail("role", "invalid")
	}
	if err := c.err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return nil, notFound(err)
	}
	admin, err := s.db.Q().Admin(id)
	if err != nil {
		return nil, notFound(err)
	}
	if stale(input.Version, admin.Version) {
		view := adminView(admin)
		return nil, &ChangedError{Current: &view, By: admin.UpdatedBy, At: admin.UpdatedAt}
	}
	if id == by.ID {
		if input.Role != admin.Role {
			c.fail("role", "own_account")
		}
		if input.Disabled {
			c.fail("disabled", "own_account")
		}
	}
	activeAdmin := admin.Role == store.RoleAdmin && !admin.Disabled
	if activeAdmin && (input.Role != store.RoleAdmin || input.Disabled) {
		if count, err := s.db.Q().CountActiveAdmins(); err != nil {
			return nil, err
		} else if count <= 1 {
			c.fail("role", "last_admin")
		}
	}
	if err := c.err(); err != nil {
		return nil, err
	}
	var changes []string
	if input.Role != admin.Role {
		changes = append(changes, roleNames[admin.Role]+" → "+roleNames[input.Role])
	}
	if input.Disabled != admin.Disabled {
		changes = append(changes, map[bool]string{true: "disabled", false: "enabled"}[input.Disabled])
	}
	admin.FullName = strings.TrimSpace(input.FullName)
	admin.Role = input.Role
	admin.Disabled = input.Disabled
	admin.UpdatedAt, admin.UpdatedBy = s.now().Unix(), actor.Username
	if err := s.db.Q().UpdateAdmin(admin); err != nil {
		return nil, notFound(err)
	}
	s.log.Info("administrator changed", "user", admin.Username, "role", admin.Role, "disabled", admin.Disabled, "by", actor.Username)
	if len(changes) > 0 {
		s.changeLocked(as(actor, by), adminEvent("admin_changed", admin.Username, "", strings.Join(changes, ", ")))
	}
	view := adminView(admin)
	return &view, nil
}

// DeleteAdmin deletes another administrator; the last active one with the role admin stays.
func (s *Service) DeleteAdmin(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return notFound(err)
	}
	admin, err := s.db.Q().Admin(id)
	if err != nil {
		return notFound(err)
	}
	if id == by.ID {
		return &RefusedError{Code: "own_account"}
	}
	if admin.Role == store.RoleAdmin && !admin.Disabled {
		if count, err := s.db.Q().CountActiveAdmins(); err != nil {
			return err
		} else if count <= 1 {
			return &RefusedError{Code: "last_admin"}
		}
	}
	if err := s.db.Q().DeleteAdmin(id); err != nil {
		return notFound(err)
	}
	delete(s.usedAdminCodes, id)
	delete(s.pendingTOTP, id)
	s.log.Info("administrator deleted", "user", admin.Username, "by", actor.Username)
	s.changeLocked(as(actor, by), adminEvent("admin_deleted", admin.Username, "", ""))
	return nil
}

// ResetAdminPassword gives another administrator a password, which it changes at the next login.
func (s *Service) ResetAdminPassword(by Actor, id int64, password string) error {
	if by.ID == id {
		return &RefusedError{Code: "own_account"}
	}
	admin, err := s.Admin(id)
	if err != nil {
		return err
	}
	if code := s.checkAdminPassword(password, admin.Username); code != "" {
		return &ValidationError{Fields: map[string]string{"password": code}}
	}
	hash, err := secret.HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return notFound(err)
	}
	if err := s.db.Q().SetAdminPassword(id, hash, true, s.now().Unix()); err != nil {
		return notFound(err)
	}
	s.log.Info("administrator password reset", "user", admin.Username, "by", actor.Username)
	s.changeLocked(as(actor, by), adminEvent("admin_password_reset", admin.Username, "", ""))
	return nil
}

// RemoveAdminTOTP removes the authenticator of another administrator, who lost it.
func (s *Service) RemoveAdminTOTP(by Actor, id int64) error {
	if by.ID == id {
		return &RefusedError{Code: "own_account"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return notFound(err)
	}
	admin, err := s.db.Q().Admin(id)
	if err != nil {
		return notFound(err)
	}
	if err := s.db.Q().SetAdminTOTP(id, "", s.now().Unix()); err != nil {
		return notFound(err)
	}
	delete(s.usedAdminCodes, id)
	s.log.Info("authenticator removed from an administrator", "user", admin.Username, "by", actor.Username)
	s.changeLocked(as(actor, by), adminEvent("admin_mfa_removed", admin.Username, "", ""))
	return nil
}

// ChangeAdminPassword changes the password of the administrator logged in, who gives the current one.
func (s *Service) ChangeAdminPassword(by Actor, current, password string) error {
	id := by.ID
	admin, err := s.Admin(id)
	if err != nil {
		return err
	}
	var c checks
	if !secret.VerifyPassword(current, admin.PasswordHash) {
		c.fail("current", "wrong")
	}
	if code := s.checkAdminPassword(password, admin.Username); code != "" {
		c.fail("password", code)
	} else if password == current {
		c.fail("password", "same")
	}
	if err := c.err(); err != nil {
		return err
	}
	hash, err := secret.HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.db.Q().SetAdminPassword(id, hash, false, s.now().Unix()); err != nil {
		return notFound(err)
	}
	s.changeLocked(as(admin, by), adminEvent("admin_password_changed", admin.Username, "", ""))
	return nil
}

// StartAdminTOTP makes a secret for the authenticator of the administrator logged in, who gives the password: a
// session left open alone can't put another authenticator on the account and lock its owner out. The secret is
// saved when the first code is right: until then the current authenticator, if any, keeps working.
func (s *Service) StartAdminTOTP(id int64, password string) (*TOTPSetup, error) {
	admin, err := s.Admin(id)
	if err != nil {
		return nil, err
	}
	if len(password) > MaxPassword || !secret.VerifyPassword(password, admin.PasswordHash) {
		return nil, &ValidationError{Fields: map[string]string{"password": "wrong"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := pendingSecret{secret: totp.NewSecret(), at: s.now()}
	s.pendingTOTP[id] = pending
	return &TOTPSetup{Secret: pending.secret, URI: totp.URI(Issuer+" Server", admin.Username, pending.secret)}, nil
}

// ConfirmAdminTOTP saves the secret of StartAdminTOTP when the code of the app is right.
func (s *Service) ConfirmAdminTOTP(by Actor, code string) error {
	id := by.ID
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, err := s.db.Q().Admin(id)
	if err != nil {
		return notFound(err)
	}
	pending, ok := s.pendingTOTP[id]
	now := s.now()
	if !ok || now.Sub(pending.at) > pendingTOTPTime {
		delete(s.pendingTOTP, id)
		return &RefusedError{Code: "setup_expired"}
	}
	counter, valid := totp.Verify(pending.secret, code, now)
	if !valid {
		return &ValidationError{Fields: map[string]string{"code": "wrong_code"}}
	}
	if err := s.db.Q().SetAdminTOTP(id, pending.secret, now.Unix()); err != nil {
		return notFound(err)
	}
	delete(s.pendingTOTP, id)
	// the codes of the old authenticator are gone; this one is spent
	delete(s.usedAdminCodes, id)
	s.adminCodeUsedLocked(id, counter, now)
	s.log.Info("authenticator set up for an administrator", "user", admin.Username)
	s.changeLocked(as(admin, by), adminEvent("admin_mfa_on", admin.Username, "", ""))
	return nil
}

// RemoveOwnAdminTOTP removes the authenticator of the administrator logged in, who gives the password; not when
// the settings ask one of every administrator.
func (s *Service) RemoveOwnAdminTOTP(by Actor, password string) error {
	id := by.ID
	admin, err := s.Admin(id)
	if err != nil {
		return err
	}
	if !secret.VerifyPassword(password, admin.PasswordHash) {
		return &ValidationError{Fields: map[string]string{"password": "wrong"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.requireAdminMFALocked() {
		return &RefusedError{Code: "mfa_required"}
	}
	if err := s.db.Q().SetAdminTOTP(id, "", s.now().Unix()); err != nil {
		return notFound(err)
	}
	delete(s.usedAdminCodes, id)
	s.log.Info("authenticator removed by its administrator", "user", admin.Username)
	s.changeLocked(as(admin, by), adminEvent("admin_mfa_removed", admin.Username, "", ""))
	return nil
}

func (s *Service) pruneAdminCodesLocked(now time.Time) {
	for id, codes := range s.usedAdminCodes {
		for counter, at := range codes {
			if now.Sub(at) > 3*time.Minute {
				delete(codes, counter)
			}
		}
		if len(codes) == 0 {
			delete(s.usedAdminCodes, id)
		}
	}
	for id, pending := range s.pendingTOTP {
		if now.Sub(pending.at) > pendingTOTPTime {
			delete(s.pendingTOTP, id)
		}
	}
}
