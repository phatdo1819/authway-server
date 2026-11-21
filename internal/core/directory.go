package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/phatdo1819/authway-server/internal/directory"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

// Users from Active Directory. The members of one group of the directory, nested groups included, are synced every
// few minutes: a new member becomes a user, a renamed one is renamed, one disabled in the directory or out of the
// group is disabled. Their password stays in the directory, which checks it at each login of the VPN; their
// authenticator, their peers and the rest are in Authway Server, as for the other users. The web UI's administrators
// stay local.

const (
	metaDirectory       = "directory"
	DefaultSyncMinutes  = 15
	MinSyncMinutes      = 5
	MaxSyncMinutes      = 1440
	maxDirectoryServers = 4
	maxDirectoryText    = 512
	// the actor of the changes the sync makes, in the events and as updated_by: no administrator has a space in its
	// username
	DirectoryActor = "directory sync"
	// how often the loop looks whether a sync is due, and the first time after the start
	directoryCheckEvery = time.Minute
	firstDirectorySync  = 10 * time.Second
	// a user of the directory fails this many logins, from any IPs but the one of its latest login, before Authway
	// Server stops asking the directory: the directory has a lockout of its own, which a copy of a configuration must
	// not trigger. With the 5 of that IP, the directory sees at most 10 wrong passwords of a user in 15 minutes.
	DirectoryPeerFailures = MaxFailures
	// a sync that would disable more than DirectoryHoldMin users, and more than a quarter of the enabled users of the
	// directory, at once, disables none of them until an administrator confirms: a group or a permission changed by
	// mistake is much more likely than that many people leaving together
	DirectoryHoldMin = 5
	// the syncs that fail in a row before the warning at the top of the web UI: one can be a domain controller
	// restarting
	directoryAlertFailures = 2
)

// DirectorySettings is the connection to Active Directory. The password of the service account never goes to the
// web UI: DirectoryView says only whether there is one.
type DirectorySettings struct {
	Enabled bool `json:"enabled"`
	// the domain controllers, host or host:port, tried in order
	Servers []string `json:"servers"`
	// directory.SecurityLDAPS or directory.SecurityStartTLS
	Security string `json:"security"`
	// PEM, for domain controllers whose certificate the system doesn't trust; "" for the system's
	CACertificates string `json:"ca_certificates"`
	BindUser       string `json:"bind_user"`
	// in a DirectoryInput, "" keeps the one saved
	BindPassword string `json:"bind_password,omitempty"`
	BaseDN       string `json:"base_dn"`
	Group        string `json:"group"`
	// directory.AttributeAccountName or directory.AttributePrincipal
	UsernameAttribute string `json:"username_attribute"`
	SyncMinutes       int    `json:"sync_minutes"`
	// a local user with the username of a member of the group becomes that member's user: its peers and authenticator
	// stay, its password is the directory's from then on
	LinkLocalUsers bool `json:"link_local_users"`
}

func (d DirectorySettings) config() directory.Config {
	return directory.Config{
		Servers: d.Servers, Security: d.Security, CACertificates: d.CACertificates, BindUser: d.BindUser,
		BindPassword: d.BindPassword, BaseDN: d.BaseDN, Group: d.Group, UsernameAttribute: d.UsernameAttribute,
	}
}

// DirectoryStatus is the latest sync.
type DirectoryStatus struct {
	// when it ended, 0 before the first
	At int64 `json:"at"`
	// why it failed, "" when it worked
	Error string `json:"error"`
	// the accounts in the group, and what changed in Authway Server
	Members  int `json:"members"`
	Added    int `json:"added"`
	Updated  int `json:"updated"`
	Disabled int `json:"disabled"`
	// the accounts left out, and why
	Skipped []DirectorySkip `json:"skipped"`
	// the usernames of the users the sync would have disabled, past the limit of DirectoryHoldMin: it disabled none
	// of them, until an administrator confirms
	Held []string `json:"held"`
	// when the password of the service account expires, in Unix time; 0 when it never does, or the directory doesn't
	// tell. A sync that fails keeps the one of before
	PasswordExpires int64 `json:"password_expires"`
	// the domain controllers that didn't answer before the one that did, and why
	Unanswered []string `json:"unanswered"`
	// the syncs that failed in a row, and when the first of them ended
	Failures     int   `json:"failures"`
	FailingSince int64 `json:"failing_since"`
}

// DirectoryAlert is what's wrong with Active Directory, for the warning at the top of the web UI: the syncs fail, one
// waits for an administrator, or the password of the service account expires soon.
type DirectoryAlert struct {
	// the error of the syncs that fail in a row, since then
	Error        string `json:"error,omitempty"`
	FailingSince int64  `json:"failing_since,omitempty"`
	// the users a sync didn't disable
	Held int `json:"held,omitempty"`
	// when the password of the service account expires: within system.DirectoryPasswordWarning, or past
	PasswordExpires int64 `json:"password_expires,omitempty"`
}

// DirectorySkip is an account of the group that the sync left out. Reason: invalid_username (Authway Server doesn't
// accept that username), local_user (a local user has that username), other_account (another account of the directory
// had it), taken (a rename to the username of another user).
type DirectorySkip struct {
	Username string `json:"username"`
	Reason   string `json:"reason"`
}

// DirectoryView is the settings, without the password of the service account, and the latest sync.
type DirectoryView struct {
	DirectorySettings
	BindPasswordSet bool            `json:"bind_password_set"`
	Status          DirectoryStatus `json:"status"`
}

// DirectoryTest is what a test of the settings found: the members of the group, a few of their usernames.
type DirectoryTest struct {
	Error    string   `json:"error"`
	Members  int      `json:"members"`
	Disabled int      `json:"disabled"`
	Sample   []string `json:"sample"`
}

// errDirectoryOff is a login of a user of the directory while the directory is turned off
var errDirectoryOff = errors.New("Active Directory is turned off in the settings")

func defaultDirectory() DirectorySettings {
	return DirectorySettings{Servers: []string{}, Security: directory.SecurityLDAPS,
		UsernameAttribute: directory.AttributeAccountName, SyncMinutes: DefaultSyncMinutes}
}

func (s *Service) directorySettingsLocked() DirectorySettings {
	settings := defaultDirectory()
	text, err := s.db.Q().Meta(metaDirectory)
	if err != nil || text == "" {
		return settings
	}
	if err := json.Unmarshal([]byte(text), &settings); err != nil {
		s.log.Error("can't read the Active Directory settings", "error", err)
		return defaultDirectory()
	}
	if settings.Servers == nil {
		settings.Servers = []string{}
	}
	return settings
}

func (s *Service) directoryViewLocked() *DirectoryView {
	settings := s.directorySettingsLocked()
	view := &DirectoryView{DirectorySettings: settings, BindPasswordSet: settings.BindPassword != "", Status: s.directoryStatus}
	view.BindPassword = ""
	if view.Status.Skipped == nil {
		view.Status.Skipped = []DirectorySkip{}
	}
	if view.Status.Held == nil {
		view.Status.Held = []string{}
	}
	if view.Status.Unanswered == nil {
		view.Status.Unanswered = []string{}
	}
	return view
}

// directoryAlertLocked is what the warning at the top of the web UI says of Active Directory; nil when nothing
func (s *Service) directoryAlertLocked() *DirectoryAlert {
	if s.opts.Directory == nil || !s.directorySettingsLocked().Enabled {
		return nil
	}
	status := s.directoryStatus
	var alert DirectoryAlert
	if status.Error != "" && status.Failures >= directoryAlertFailures {
		alert.Error, alert.FailingSince = status.Error, status.FailingSince
	}
	alert.Held = len(status.Held)
	if status.PasswordExpires != 0 && time.Unix(status.PasswordExpires, 0).Sub(s.now()) <= system.DirectoryPasswordWarning {
		alert.PasswordExpires = status.PasswordExpires
	}
	if alert == (DirectoryAlert{}) {
		return nil
	}
	return &alert
}

// Directory is the settings of Active Directory and the latest sync, for the web UI.
func (s *Service) Directory() *DirectoryView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.directoryViewLocked()
}

// checkDirectory checks settings of the web UI or of a backup; saved is the password of the service account saved,
// kept when the input has none. Turned on, they need everything to connect.
func checkDirectory(input DirectorySettings, saved string) (DirectorySettings, error) {
	var c checks
	out := DirectorySettings{Enabled: input.Enabled, LinkLocalUsers: input.LinkLocalUsers, Servers: []string{}}
	out.Security = input.Security
	if out.Security == "" {
		out.Security = directory.SecurityLDAPS
	}
	if out.Security != directory.SecurityLDAPS && out.Security != directory.SecurityStartTLS {
		c.fail("security", "invalid")
	}
	for _, text := range input.Servers {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		host, _, ok := directory.ParseServer(text, out.Security)
		if !ok || !validHost(host) {
			c.fail("servers", "invalid")
			continue
		}
		if containsText(out.Servers, text) {
			c.fail("servers", "duplicate")
			continue
		}
		out.Servers = append(out.Servers, text)
	}
	if len(out.Servers) > maxDirectoryServers {
		c.fail("servers", "too_many")
	}
	out.CACertificates = strings.TrimSpace(input.CACertificates)
	if out.CACertificates != "" {
		if _, err := directory.CAPool(out.CACertificates); err != nil {
			c.fail("ca_certificates", "invalid")
		}
	}
	text := func(field, value string) string {
		value = strings.TrimSpace(value)
		if len([]rune(value)) > maxDirectoryText || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			c.fail(field, "invalid")
		}
		return value
	}
	out.BindUser = text("bind_user", input.BindUser)
	out.BindPassword = input.BindPassword
	if out.BindPassword == "" {
		out.BindPassword = saved
	}
	if len(out.BindPassword) > MaxPassword {
		c.fail("bind_password", "too_long")
	}
	out.BaseDN = text("base_dn", input.BaseDN)
	if out.BaseDN != "" && !directory.ValidDN(out.BaseDN) {
		c.fail("base_dn", "invalid")
	}
	out.Group = text("group", input.Group)
	if out.Group != "" && !directory.ValidDN(out.Group) {
		c.fail("group", "invalid")
	}
	out.UsernameAttribute = input.UsernameAttribute
	if out.UsernameAttribute == "" {
		out.UsernameAttribute = directory.AttributeAccountName
	}
	if out.UsernameAttribute != directory.AttributeAccountName && out.UsernameAttribute != directory.AttributePrincipal {
		c.fail("username_attribute", "invalid")
	}
	out.SyncMinutes = input.SyncMinutes
	if out.SyncMinutes == 0 {
		out.SyncMinutes = DefaultSyncMinutes
	}
	if out.SyncMinutes < MinSyncMinutes || out.SyncMinutes > MaxSyncMinutes {
		c.fail("sync_minutes", "invalid")
	}
	if input.Enabled {
		requireDirectory(out, &c)
	}
	return out, c.err()
}

// requireDirectory fails the fields that a connection needs and that are empty
func requireDirectory(d DirectorySettings, c *checks) {
	for field, empty := range map[string]bool{
		"servers": len(d.Servers) == 0, "bind_user": d.BindUser == "", "bind_password": d.BindPassword == "",
		"base_dn": d.BaseDN == "", "group": d.Group == "",
	} {
		if empty {
			c.fail(field, "required")
		}
	}
}

// SetDirectory saves the settings of Active Directory: an empty password keeps the one saved. Turned on, the first
// sync runs at once.
func (s *Service) SetDirectory(by Actor, input DirectorySettings) (*DirectoryView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	actor, err := s.db.Q().Admin(by.ID)
	if err != nil {
		return nil, notFound(err)
	}
	before := s.directorySettingsLocked()
	settings, err := checkDirectory(input, before.BindPassword)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	if err := s.db.Q().SetMeta(metaDirectory, string(data)); err != nil {
		return nil, err
	}
	if c := directoryChanges(before, settings); len(c) > 0 {
		s.log.Info("Active Directory settings changed", "by", actor.Username, "changes", c.String())
		s.changeLocked(as(actor, by), adminEvent("settings_changed", "", "", "Active Directory: "+c.String()))
	}
	if settings.Enabled {
		// at once, not at the next check of the loop
		s.directorySynced = time.Time{}
		select {
		case s.directoryWake <- struct{}{}:
		default:
		}
	}
	return s.directoryViewLocked(), nil
}

func directoryChanges(before, after DirectorySettings) changes {
	var c changes
	c.toggle("sync", before.Enabled, after.Enabled)
	c.list("domain controllers", before.Servers, after.Servers)
	c.text("connection", before.Security, after.Security)
	if before.CACertificates != after.CACertificates {
		c = append(c, "CA certificates changed")
	}
	c.text("service account", before.BindUser, after.BindUser)
	if before.BindPassword != after.BindPassword {
		c = append(c, "new service account password")
	}
	c.text("search base", before.BaseDN, after.BaseDN)
	c.text("group", before.Group, after.Group)
	c.text("username from", before.UsernameAttribute, after.UsernameAttribute)
	c.number("sync every", before.SyncMinutes, after.SyncMinutes, "min")
	c.toggle("link local users", before.LinkLocalUsers, after.LinkLocalUsers)
	return c
}

// TestDirectory connects with settings of the web UI, saved or not, and reads the members of the group: nothing
// changes. An empty password is the one saved.
func (s *Service) TestDirectory(input DirectorySettings) (*DirectoryTest, error) {
	if s.opts.Directory == nil {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	saved := s.directorySettingsLocked().BindPassword
	s.mu.Unlock()
	settings, err := checkDirectory(input, saved)
	if err == nil {
		var c checks
		requireDirectory(settings, &c)
		err = c.err()
	}
	if err != nil {
		return nil, err
	}
	// the network, out of the lock
	group, err := s.opts.Directory.Members(settings.config())
	if err != nil {
		return &DirectoryTest{Error: err.Error(), Sample: []string{}}, nil
	}
	test := &DirectoryTest{Members: len(group.Members), Sample: []string{}}
	names := make([]string, 0, len(group.Members))
	for _, member := range group.Members {
		if member.Disabled {
			test.Disabled++
		}
		names = append(names, member.Username)
	}
	sort.Strings(names)
	test.Sample = names[:min(5, len(names))]
	return test, nil
}

// runDirectory syncs when the settings ask for it, until ctx ends
func (s *Service) runDirectory(ctx context.Context) {
	timer := time.NewTimer(firstDirectorySync)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.directoryWake:
		}
		s.mu.Lock()
		settings := s.directorySettingsLocked()
		every := settings.SyncMinutes
		if s.directoryStatus.Error != "" {
			// a sync that failed is tried again sooner
			every = min(every, MinSyncMinutes)
		}
		due := settings.Enabled && s.now().Sub(s.directorySynced) >= time.Duration(every)*time.Minute
		s.mu.Unlock()
		if due {
			s.SyncDirectory(Actor{Username: DirectoryActor}, 0)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(directoryCheckEvery)
	}
}

// SyncDirectory reads the members of the group and brings the users of the directory in line with them, one sync at
// a time. Its errors are in the status. confirm is how many users an administrator agreed to disable, after a sync held
// them: up to that many, they are; 0 holds them again.
func (s *Service) SyncDirectory(by Actor, confirm int) (DirectoryStatus, error) {
	if s.opts.Directory == nil {
		return DirectoryStatus{}, ErrNotFound
	}
	if confirm > 0 {
		// after the sync that runs, if any: a confirmation needs a sync of its own
		s.directoryMu.Lock()
	} else if !s.directoryMu.TryLock() {
		// a sync is running: its result answers this one too, rather than a second sync after it, which would make
		// Sync now wait twice as long for a directory that doesn't answer
		s.directoryMu.Lock()
		s.directoryMu.Unlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.directoryStatus, nil
	}
	defer s.directoryMu.Unlock()
	s.mu.Lock()
	settings := s.directorySettingsLocked()
	s.directorySynced = s.now()
	s.mu.Unlock()
	if !settings.Enabled {
		return DirectoryStatus{}, &RefusedError{Code: "directory_off"}
	}
	// the network, out of the lock
	group, err := s.opts.Directory.Members(settings.config())
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.directoryStatus
	status := DirectoryStatus{At: s.now().Unix(), Skipped: []DirectorySkip{}, Held: []string{}, Unanswered: []string{}}
	status.Unanswered = append(status.Unanswered, group.Unanswered...)
	if !group.PasswordExpires.IsZero() {
		status.PasswordExpires = group.PasswordExpires.Unix()
	}
	again := false
	if err == nil && !reflect.DeepEqual(s.directorySettingsLocked(), settings) {
		err = errors.New("the settings changed during the sync, so it runs again")
		s.directorySynced = time.Time{}
		again = true
	}
	if err == nil {
		err = s.applyDirectoryLocked(group.Members, &status, confirm)
	}
	syncer := Actor{Username: DirectoryActor}
	switch {
	case again:
		// not a failure: the next check of the loop syncs again
		status.Error = err.Error()
		status.PasswordExpires, status.Failures, status.FailingSince = previous.PasswordExpires, previous.Failures, previous.FailingSince
	case err != nil:
		status.Error = err.Error()
		status.Failures, status.FailingSince = 1, status.At
		if previous.Failures > 0 {
			status.Failures, status.FailingSince = previous.Failures+1, previous.FailingSince
		}
		status.PasswordExpires = previous.PasswordExpires
		if previous.Error != status.Error {
			s.log.Error("can't sync with Active Directory", "error", err)
		}
		if previous.Failures == 0 {
			s.changeLocked(syncer, store.Event{Kind: "directory_failed", Detail: status.Error})
		}
	case previous.Failures > 0:
		s.log.Info("synced with Active Directory again")
		syncs := "1 failed sync"
		if previous.Failures > 1 {
			syncs = fmt.Sprintf("%d failed syncs", previous.Failures)
		}
		s.changeLocked(syncer, store.Event{Kind: "directory_restored", Detail: "after " + syncs})
	}
	if len(status.Held) > 0 && !slices.Equal(status.Held, previous.Held) {
		s.log.Warn("an Active Directory sync would disable many users at once, so it disabled none: an administrator confirms in the settings",
			"users", len(status.Held))
		s.changeLocked(syncer, store.Event{Kind: "directory_held", Detail: heldDetail(status.Held, status.Members)})
	}
	if confirm > 0 && status.Disabled > 0 && len(previous.Held) > 0 {
		s.changeLocked(by, store.Event{Kind: "directory_confirmed",
			Detail: fmt.Sprintf("disabled %d users that a sync had held", status.Disabled)})
	}
	if status.Added+status.Updated+status.Disabled > 0 {
		s.log.Info("synced with Active Directory", "members", status.Members, "added", status.Added,
			"updated", status.Updated, "disabled", status.Disabled, "skipped", len(status.Skipped))
	}
	s.directoryStatus = status
	return status, nil
}

// heldDetail is the event of a sync that held users: how many, and the first ones
func heldDetail(held []string, members int) string {
	names := strings.Join(held[:min(len(held), 10)], ", ")
	if len(held) > 10 {
		names += ", …"
	}
	return fmt.Sprintf("would disable %d users at once, with %d members left in the group: %s", len(held), members, names)
}

// applyDirectoryLocked makes the users of the directory match the members of the group. Past the limit of
// DirectoryHoldMin, and of confirm, it disables no one: the users it would have disabled are in status.Held.
func (s *Service) applyDirectoryLocked(members []directory.User, status *DirectoryStatus, confirm int) error {
	q := s.db.Q()
	settings := s.directorySettingsLocked()
	users, err := q.Users()
	if err != nil {
		return err
	}
	byID := map[string]*store.User{}
	byName := map[string]*store.User{}
	active := 0
	for index := range users {
		user := &users[index]
		byName[strings.ToLower(user.Username)] = user
		if user.FromDirectory() {
			byID[user.DirectoryID] = user
			if !user.Disabled {
				active++
			}
		}
	}
	// a group without members is much more likely a wrong group, or a service account that can't read it, than all
	// the users gone at once: nobody is disabled
	if len(members) == 0 && active > 0 {
		return errors.New("the group has no members, so no user was disabled: check the group, and that the service account can read its members")
	}
	held := s.heldLocked(members, users, byID, active, confirm)
	status.Held = append(status.Held, held...)
	by := Actor{Username: DirectoryActor}
	now := s.now().Unix()
	skip := func(username, reason string) {
		status.Skipped = append(status.Skipped, DirectorySkip{Username: username, Reason: reason})
	}
	seen := map[string]bool{}
	for _, member := range members {
		if seen[member.ID] {
			continue
		}
		seen[member.ID] = true
		status.Members++
		name := strings.TrimSpace(member.Username)
		if !usernamePattern.MatchString(name) {
			skip(member.Username, "invalid_username")
			continue
		}
		fullName := directoryName(member.FullName)
		user, known := byID[member.ID]
		linked := false
		if !known {
			other := byName[strings.ToLower(name)]
			switch {
			case other == nil:
				user = &store.User{Username: name, FullName: fullName, Disabled: member.Disabled, DirectoryID: member.ID,
					CreatedAt: now, UpdatedAt: now, UpdatedBy: DirectoryActor}
				if err := q.CreateUser(user); err != nil {
					s.log.Error("can't add a user of Active Directory", "user", name, "error", err)
					skip(name, "taken")
					continue
				}
				byName[strings.ToLower(name)] = user
				status.Added++
				detail := "from Active Directory"
				if user.Disabled {
					detail += ", disabled"
				}
				s.changeLocked(by, store.Event{Kind: "user_added", Username: name, Detail: detail})
				continue
			case other.FromDirectory():
				// a former account with the same name: its user stays until an administrator deletes it
				skip(name, "other_account")
				continue
			case !settings.LinkLocalUsers:
				skip(name, "local_user")
				continue
			}
			user, linked = other, true
		}
		before := *user
		var c changes
		if user.Username != name {
			if other := byName[strings.ToLower(name)]; other != nil && other.ID != user.ID {
				skip(name, "taken")
			} else {
				c.text("username", user.Username, name)
				delete(byName, strings.ToLower(user.Username))
				user.Username = name
				byName[strings.ToLower(name)] = user
			}
		}
		c.text("full name", user.FullName, fullName)
		user.FullName = fullName
		if user.Disabled != member.Disabled && !(member.Disabled && len(held) > 0 && !linked) {
			c = append(c, map[bool]string{true: "disabled in Active Directory", false: "enabled in Active Directory"}[member.Disabled])
			user.Disabled = member.Disabled
		}
		if linked {
			c = append(c, "now from Active Directory, which checks the password")
			user.DirectoryID, user.PasswordHash = member.ID, ""
		}
		if len(c) == 0 {
			continue
		}
		user.UpdatedAt, user.UpdatedBy = now, DirectoryActor
		if err := q.UpdateUser(user); err != nil {
			s.log.Error("can't update a user of Active Directory", "user", before.Username, "error", err)
			*user = before
			continue
		}
		if user.Disabled && !before.Disabled {
			status.Disabled++
		} else {
			status.Updated++
		}
		s.changeLocked(by, store.Event{Kind: "user_changed", Username: user.Username, Detail: c.String()})
		// the password of before no longer counts
		if (user.Disabled && !before.Disabled) || linked {
			id := user.ID
			s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
		}
	}
	for index := range users {
		user := &users[index]
		if !user.FromDirectory() || seen[user.DirectoryID] || user.Disabled || len(held) > 0 {
			continue
		}
		user.Disabled = true
		user.UpdatedAt, user.UpdatedBy = now, DirectoryActor
		if err := q.UpdateUser(user); err != nil {
			s.log.Error("can't disable a user of Active Directory", "user", user.Username, "error", err)
			continue
		}
		status.Disabled++
		s.changeLocked(by, store.Event{Kind: "user_changed", Username: user.Username,
			Detail: "disabled: no longer in the Active Directory group"})
		id := user.ID
		s.endSessionsLocked(func(session store.Session) bool { return session.UserID == id }, EndUserChanged)
	}
	return nil
}

// heldLocked is the usernames of the users a sync would disable, sorted, when they're too many at once: more than
// DirectoryHoldMin, more than a quarter of the enabled users of the directory, and more than an administrator
// confirmed. nil when the sync can disable them.
func (s *Service) heldLocked(members []directory.User, users []store.User, byID map[string]*store.User, active, confirm int) []string {
	var names []string
	seen := map[string]bool{}
	for _, member := range members {
		if seen[member.ID] {
			continue
		}
		seen[member.ID] = true
		if user := byID[member.ID]; user != nil && member.Disabled && !user.Disabled {
			names = append(names, user.Username)
		}
	}
	for _, user := range users {
		if user.FromDirectory() && !seen[user.DirectoryID] && !user.Disabled {
			names = append(names, user.Username)
		}
	}
	if len(names) <= DirectoryHoldMin || len(names)*4 <= active || len(names) <= confirm {
		return nil
	}
	sort.Strings(names)
	return names
}

// directoryName is a display name of the directory as a full name: without control characters, at most 128
// characters
func directoryName(name string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name))
	if runes := []rune(name); len(runes) > 128 {
		name = strings.TrimSpace(string(runes[:128]))
	}
	return name
}

// checkDirectoryPassword asks the directory whether a password is the one of a user, out of the lock: nil when it
// is, an error of package directory when it isn't, errDirectoryOff or any other error when it can't tell.
func (s *Service) checkDirectoryPassword(settings DirectorySettings, id, password string) error {
	if !settings.Enabled || s.opts.Directory == nil {
		return errDirectoryOff
	}
	_, err := s.opts.Directory.Authenticate(settings.config(), id, password)
	return err
}

// refusedByDirectory tells whether the directory refused a password, as opposed to not answering
func refusedByDirectory(err error) bool {
	for _, refused := range []error{directory.ErrWrongPassword, directory.ErrLocked, directory.ErrPasswordExpired,
		directory.ErrDisabled, directory.ErrNotMember} {
		if errors.Is(err, refused) {
			return true
		}
	}
	return false
}

// directoryReason is why the directory refused a password, for the event of the failed login; "" for a wrong one
func directoryReason(err error) string {
	switch {
	case errors.Is(err, directory.ErrLocked):
		return "locked out in Active Directory"
	case errors.Is(err, directory.ErrPasswordExpired):
		return "password expired in Active Directory"
	case errors.Is(err, directory.ErrDisabled):
		return "disabled in Active Directory"
	case errors.Is(err, directory.ErrNotMember):
		return "no longer in the Active Directory group"
	}
	return ""
}

// sameUser tells whether a username typed at a login is the one of the user. A user of the directory can also type
// DOMAIN\name or name@domain, as in Windows, and only the name before the @ of a user principal name: alice for
// alice@example.com. The peer says whose login it is: the username only confirms it.
func sameUser(typed string, user *store.User) bool {
	typed = strings.TrimSpace(typed)
	if strings.EqualFold(typed, user.Username) {
		return true
	}
	if !user.FromDirectory() {
		return false
	}
	short, _, principal := strings.Cut(user.Username, "@")
	if _, name, ok := strings.Cut(typed, `\`); ok {
		// DOMAIN\alice
		typed = name
	} else if name, _, ok := strings.Cut(typed, "@"); ok && !principal {
		// alice@example.com, for the logon name alice
		typed = name
	}
	return strings.EqualFold(typed, user.Username) || (principal && short != "" && strings.EqualFold(typed, short))
}

// validDirectoryID tells whether a text is an objectGUID in hex, as the sync keeps it
func validDirectoryID(text string) bool {
	data, err := hex.DecodeString(text)
	return err == nil && len(data) == 16 && hex.EncodeToString(data) == text
}

// peerFailureLimit is how many failed logins of a peer, from any IPs but the one of its latest login, lock it out
func peerFailureLimit(user *store.User) int {
	if user != nil && user.FromDirectory() {
		return DirectoryPeerFailures
	}
	return MaxFailures * PeerFailureFactor
}
