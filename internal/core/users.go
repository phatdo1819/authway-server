package core

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

const (
	MaxPassword = 256
	Issuer      = "Authway"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// UserInput is what the web UI sends to add or edit a user. An empty password keeps the current one.
type UserInput struct {
	Username string `json:"username"`
	FullName string `json:"full_name"`
	Password string `json:"password"`
	Disabled bool   `json:"disabled"`
	// when edited: the version the form opened with, see ChangedError; 0 doesn't check it
	Version int64 `json:"version"`
}

func (s *Service) CreateUser(by Actor, input UserInput) (*UserView, error) {
	user := &store.User{}
	hash, err := s.checkUser(input, user, true)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Q().UserByName(user.Username); err == nil {
		return nil, &ValidationError{Fields: map[string]string{"username": "taken"}}
	}
	user.PasswordHash = hash
	now := s.now().Unix()
	user.CreatedAt, user.UpdatedAt, user.UpdatedBy = now, now, by.Username
	if err := s.db.Q().CreateUser(user); err != nil {
		return nil, takenOr(err, "username")
	}
	s.log.Info("user added", "user", user.Username)
	detail := ""
	if user.Disabled {
		detail = "disabled"
	}
	s.changeLocked(by, store.Event{Kind: "user_added", Username: user.Username, Detail: detail})
	return s.userViewLocked(user)
}

func (s *Service) UpdateUser(by Actor, id int64, input UserInput) (*UserView, error) {
	// the hash takes time: out of the lock
	var checked store.User
	hash, err := s.checkUser(input, &checked, false)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// the user of now, not of before the hash: an authenticator set up meanwhile stays
	current, err := s.db.Q().User(id)
	if err != nil {
		return nil, notFound(err)
	}
	if stale(input.Version, current.Version) {
		view, err := s.userViewLocked(current)
		if err != nil {
			return nil, err
		}
		return nil, &ChangedError{Current: view, By: current.UpdatedBy, At: current.UpdatedAt}
	}
	// a user of Active Directory gets its username, full name, state and password from there: the next sync would
	// undo a change made here
	if current.FromDirectory() {
		var c checks
		if checked.Username != current.Username {
			c.fail("username", "directory")
		}
		if checked.FullName != current.FullName {
			c.fail("full_name", "directory")
		}
		if checked.Disabled != current.Disabled {
			c.fail("disabled", "directory")
		}
		if hash != "" {
			c.fail("password", "directory")
		}
		if err := c.err(); err != nil {
			return nil, err
		}
	}
	if other, err := s.db.Q().UserByName(checked.Username); err == nil && other.ID != id {
		return nil, &ValidationError{Fields: map[string]string{"username": "taken"}}
	}
	user := *current
	user.Username, user.FullName, user.Disabled = checked.Username, checked.FullName, checked.Disabled
	if hash != "" {
		user.PasswordHash = hash
	}
	user.UpdatedAt, user.UpdatedBy = s.now().Unix(), by.Username
	if err := s.db.Q().UpdateUser(&user); err != nil {
		return nil, takenOr(notFound(err), "username")
	}
	s.log.Info("user changed", "user", user.Username)
	var c changes
	c.text("username", current.Username, user.Username)
	c.text("full name", current.FullName, user.FullName)
	if hash != "" {
		c = append(c, "new password")
	}
	if current.Disabled != user.Disabled {
		c = append(c, map[bool]string{true: "disabled", false: "enabled"}[user.Disabled])
	}
	if len(c) > 0 {
		s.changeLocked(by, store.Event{Kind: "user_changed", Username: user.Username, Detail: c.String()})
	}
	if hash != "" || user.Disabled {
		s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
	}
	return s.userViewLocked(&user)
}

// DeleteUser deletes a user and its peers, on every server.
func (s *Service) DeleteUser(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, err := s.db.Q().User(id)
	if err != nil {
		return notFound(err)
	}
	// its peers go with it: the event names them
	peers, err := s.db.Q().PeersOfUser(id)
	if err != nil {
		return err
	}
	var gone []string
	servers, _ := s.db.Q().Servers()
	names := serverNames(servers)
	for _, peer := range peers {
		gone = append(gone, names[peer.ServerID]+" · "+peer.Name)
	}
	s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
	// as DeletePeer: a new peer can get the id of one of them, the history must not go on with it
	for _, peer := range peers {
		if err := s.db.Q().EndConnectionsOf(peer.ServerID, peer.ID); err != nil {
			s.log.Error("can't end the connections of a peer", "peer", peer.Name, "error", err)
		}
	}
	if err := s.db.Q().DeleteUser(id); err != nil {
		return notFound(err)
	}
	for _, peer := range peers {
		s.forgetPeerLocked(peer.ID)
	}
	s.log.Info("user deleted with its peers", "user", user.Username)
	detail := ""
	if len(gone) > 0 {
		detail = "with its peers: " + strings.Join(gone, ", ")
	}
	s.changeLocked(by, store.Event{Kind: "user_deleted", Username: user.Username, Detail: detail})
	s.applyLocked()
	return nil
}

// TOTPSetup is shown once, when the authenticator of a user is set up.
type TOTPSetup struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// SetupTOTP gives a user a new authenticator secret: the codes of the old one stop working.
func (s *Service) SetupTOTP(by Actor, id int64) (*TOTPSetup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, err := s.db.Q().User(id)
	if err != nil {
		return nil, notFound(err)
	}
	user.TOTPSecret = totp.NewSecret()
	// nobody has scanned this key yet
	user.TOTPConfirmedAt = 0
	user.UpdatedAt, user.UpdatedBy = s.now().Unix(), by.Username
	if err := s.db.Q().UpdateUser(user); err != nil {
		return nil, err
	}
	delete(s.usedCodes, id)
	s.log.Info("new authenticator for a user", "user", user.Username)
	s.changeLocked(by, store.Event{Kind: "user_mfa_on", Username: user.Username})
	s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
	return &TOTPSetup{Secret: user.TOTPSecret, URI: totp.URI(Issuer, user.Username, user.TOTPSecret)}, nil
}

// CheckTOTP checks a code from the authenticator app of a user, to show that the key was scanned: once it works, the
// key counts as in use, as after a login with a code. Only for a key nobody has used yet: on a key in use, it would
// let an operator try codes without the password.
func (s *Service) CheckTOTP(by Actor, id int64, code string) (*UserView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, err := s.db.Q().User(id)
	if err != nil {
		return nil, notFound(err)
	}
	switch {
	case user.TOTPSecret == "":
		return nil, &ValidationError{Fields: map[string]string{"code": "no_otp"}}
	case user.TOTPConfirmedAt != 0:
		return nil, &ValidationError{Fields: map[string]string{"code": "otp_in_use"}}
	}
	// not kept as used: the user can log in with the same code right after
	if _, ok := totp.Verify(user.TOTPSecret, strings.TrimSpace(code), s.now()); !ok {
		return nil, &ValidationError{Fields: map[string]string{"code": "invalid_otp"}}
	}
	if err := s.db.Q().ConfirmUserTOTP(id, s.now().Unix()); err != nil {
		return nil, err
	}
	s.log.Info("authenticator of a user checked", "user", user.Username, "by", by.Username)
	user, err = s.db.Q().User(id)
	if err != nil {
		return nil, notFound(err)
	}
	return s.userViewLocked(user)
}

func (s *Service) RemoveTOTP(by Actor, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, err := s.db.Q().User(id)
	if err != nil {
		return notFound(err)
	}
	user.TOTPSecret, user.TOTPConfirmedAt = "", 0
	user.UpdatedAt, user.UpdatedBy = s.now().Unix(), by.Username
	if err := s.db.Q().UpdateUser(user); err != nil {
		return err
	}
	s.log.Info("authenticator removed from a user", "user", user.Username)
	s.changeLocked(by, store.Event{Kind: "user_mfa_removed", Username: user.Username})
	s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
	return nil
}

// checkUser checks the input, copies it into user and returns the hash of the new password, "" when it doesn't change
func (s *Service) checkUser(input UserInput, user *store.User, create bool) (string, error) {
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
	switch {
	case input.Password == "" && create:
		c.fail("password", "required")
	case input.Password == "":
	default:
		if code := s.PasswordPolicy().check(input.Password, username, 0); code != "" {
			c.fail("password", code)
		}
	}
	if err := c.err(); err != nil {
		return "", err
	}
	user.Username = username
	user.FullName = strings.TrimSpace(input.FullName)
	user.Disabled = input.Disabled
	if input.Password == "" {
		return "", nil
	}
	return hashShared(input.Password)
}

func validFullName(name string) bool {
	name = strings.TrimSpace(name)
	return len([]rune(name)) <= 128 && strings.IndexFunc(name, unicode.IsControl) < 0
}
