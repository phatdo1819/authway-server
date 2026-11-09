package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/backup"
	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/totp"
)

// A backup has the whole configuration: the settings, the administrators, the users, the servers and the peers,
// with their keys, password hashes and authenticator secrets, sealed with a passphrase (internal/backup). The
// history of the sessions, the events and the alerts aren't in it.

// BackupVersion is the version of the content of the backups: a restore takes this one and the older ones. 4 added
// the routed servers: an older Authway Server would translate their networks again. 3 added the IPv6 networks of
// the servers: an older Authway Server refuses the backup rather than lose them. 2 added
// the devices, device binding and the traffic between peers: a backup of version 1 has neither, its peers enroll
// a device when their server asks for one.
const BackupVersion = 4

var interfacePattern = regexp.MustCompile(`^wg[0-9]{1,3}$`)

type backupContent struct {
	Version   int            `json:"version"`
	CreatedAt int64          `json:"created_at"`
	MadeBy    string         `json:"made_by"`
	Settings  backupSettings `json:"settings"`
	Admins    []backupAdmin  `json:"admins"`
	Users     []backupUser   `json:"users"`
	Servers   []backupServer `json:"servers"`
	Peers     []backupPeer   `json:"peers"`
	Devices   []backupDevice `json:"devices"`
}

type backupSettings struct {
	// "": the one of the environment, AUTHWAY_PUBLIC_HOST
	PublicHost      string         `json:"public_host"`
	PasswordPolicy  PasswordPolicy `json:"password_policy"`
	RequireAdminMFA bool           `json:"require_admin_mfa"`
	// 0, in version 1: the default
	EnrollHours int `json:"enroll_hours"`
	// 0 when never set, and in the backups made before it: the default
	HistoryDays int `json:"history_days,omitempty"`
}

// backupDevice is the device of a peer, or its enrollment: a restore on a new host keeps the devices enrolled,
// and the keys they gave their peers
type backupDevice struct {
	PeerID         int64  `json:"peer_id"`
	WindowUntil    int64  `json:"window_until"`
	Key            string `json:"key"`
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	MachineID      string `json:"machine_id"`
	EnrolledAt     int64  `json:"enrolled_at"`
	LastUsedAt     int64  `json:"last_used_at"`
	LastFrom       string `json:"last_from"`
	WireGuardKey   string `json:"wireguard_key"`
	WireGuardKeyAt int64  `json:"wireguard_key_at"`
}

type backupAdmin struct {
	ID                 int64  `json:"id"`
	Username           string `json:"username"`
	FullName           string `json:"full_name"`
	PasswordHash       string `json:"password_hash"`
	Role               string `json:"role"`
	TOTPSecret         string `json:"totp_secret"`
	Disabled           bool   `json:"disabled"`
	MustChangePassword bool   `json:"must_change_password"`
	LastLoginAt        int64  `json:"last_login_at"`
	LastLoginFrom      string `json:"last_login_from"`
	CreatedAt          int64  `json:"created_at"`
	UpdatedAt          int64  `json:"updated_at"`
}

type backupUser struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	FullName     string `json:"full_name"`
	PasswordHash string `json:"password_hash"`
	TOTPSecret   string `json:"totp_secret"`
	Disabled     bool   `json:"disabled"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type backupServer struct {
	ID                int64    `json:"id"`
	Name              string   `json:"name"`
	Interface         string   `json:"interface"`
	Enabled           bool     `json:"enabled"`
	ListenPort        int      `json:"listen_port"`
	PublicHost        string   `json:"public_host"`
	PublicPort        int      `json:"public_port"`
	PrivateKey        string   `json:"private_key"`
	Network           string   `json:"network"`
	Network6          string   `json:"network6,omitempty"`
	Networks          []string `json:"networks"`
	DNS               []string `json:"dns"`
	MTU               int      `json:"mtu"`
	Keepalive         int      `json:"keepalive"`
	AuthMode          string   `json:"auth_mode"`
	SessionTimeout    int      `json:"session_timeout"`
	LockEndpoint      string   `json:"lock_endpoint"`
	DetectCopies      bool     `json:"detect_copies"`
	BlockCopies       bool     `json:"block_copies"`
	Redirect          bool     `json:"redirect"`
	FallbackEndpoints []string `json:"fallback_endpoints"`
	DeviceBinding     bool     `json:"device_binding"`
	MachineID         bool     `json:"machine_id"`
	ClientToClient    bool     `json:"client_to_client"`
	ReachableServers  []int64  `json:"reachable_servers"`
	Routed            bool     `json:"routed,omitempty"`
	Inbound           bool     `json:"inbound,omitempty"`
	CreatedAt         int64    `json:"created_at"`
	UpdatedAt         int64    `json:"updated_at"`
}

type backupPeer struct {
	ID           int64  `json:"id"`
	ServerID     int64  `json:"server_id"`
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	UserID       int64  `json:"user_id"`
	Address      string `json:"address"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	RouteAll     bool   `json:"route_all"`
	Blocked      bool   `json:"blocked"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// BackupSummary says what a backup has, before it's restored.
type BackupSummary struct {
	CreatedAt      int64  `json:"created_at"`
	MadeBy         string `json:"made_by"`
	Servers        int    `json:"servers"`
	Peers          int    `json:"peers"`
	Users          int    `json:"users"`
	Administrators int    `json:"administrators"`
	// the enabled administrators with the role Administrator: they can log in after the restore
	AdminUsernames []string `json:"admin_usernames"`
	// the administrator who asks is in the backup and enabled: the same username logs in after the restore, with
	// the password of the backup
	IncludesYou bool `json:"includes_you"`
}

func (b *BackupSummary) text() string {
	return fmt.Sprintf("%s, %s, %s, %s", count(b.Servers, "server"), count(b.Peers, "peer"), count(b.Users, "user"),
		count(b.Administrators, "administrator"))
}

func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// restorePlan is a backup checked, ready to replace the configuration
type restorePlan struct {
	settings backupSettings
	admins   []store.Admin
	users    []store.User
	servers  []store.Server
	peers    []store.Peer
	devices  []store.Device
	summary  BackupSummary
}

// Backup seals the configuration for the administrator by, who gives the password: a session alone can't take the
// keys of every tunnel. It returns the name of the file and its content.
func (s *Service) Backup(by Actor, password, passphrase string) (string, []byte, error) {
	admin, err := s.Admin(by.ID)
	if err != nil {
		return "", nil, err
	}
	var c checks
	if len(password) > MaxPassword || !secret.VerifyPassword(password, admin.PasswordHash) {
		c.fail("password", "wrong")
	}
	if code := backup.CheckPassphrase(passphrase); code != "" {
		c.fail("passphrase", code)
	}
	if err := c.err(); err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	now := s.now()
	content, err := s.backupContentLocked(now)
	s.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	data, err := json.Marshal(content)
	if err != nil {
		return "", nil, err
	}
	// the key takes time and memory: out of the lock
	sealed, err := backup.Seal(data, passphrase, now)
	if err != nil {
		return "", nil, err
	}
	summary := summarize(content, admin.Username)
	s.mu.Lock()
	s.log.Info("backup made", "by", admin.Username, "content", summary.text())
	s.changeLocked(as(admin, by), adminEvent("backup_made", "", "", summary.text()))
	s.mu.Unlock()
	return "authway-backup-" + now.UTC().Format("20060102-150405") + ".json", sealed, nil
}

func (s *Service) backupContentLocked(now time.Time) (*backupContent, error) {
	q := s.db.Q()
	host, err := q.Meta("public_host")
	if err != nil {
		return nil, err
	}
	// 0 when never set: the default stays the default of the version that restores
	stored, err := q.Meta("enroll_hours")
	if err != nil {
		return nil, err
	}
	hours := 0
	if stored != "" {
		hours = s.enrollHoursLocked()
	}
	if stored, err = q.Meta("history_days"); err != nil {
		return nil, err
	}
	days := 0
	if stored != "" {
		days = s.historyDaysLocked()
	}
	version := s.opts.Version
	if version == "" {
		version = "dev"
	}
	content := &backupContent{
		Version: BackupVersion, CreatedAt: now.Unix(), MadeBy: "Authway Server " + version,
		Settings: backupSettings{PublicHost: host, PasswordPolicy: s.policyLocked(), RequireAdminMFA: s.requireAdminMFALocked(),
			EnrollHours: hours, HistoryDays: days},
		Admins: []backupAdmin{}, Users: []backupUser{}, Servers: []backupServer{}, Peers: []backupPeer{},
		Devices: []backupDevice{},
	}
	admins, err := q.Admins()
	if err != nil {
		return nil, err
	}
	for _, a := range admins {
		content.Admins = append(content.Admins, backupAdmin{
			ID: a.ID, Username: a.Username, FullName: a.FullName, PasswordHash: a.PasswordHash, Role: a.Role,
			TOTPSecret: a.TOTPSecret, Disabled: a.Disabled, MustChangePassword: a.MustChangePassword,
			LastLoginAt: a.LastLoginAt, LastLoginFrom: a.LastLoginFrom, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		})
	}
	users, err := q.Users()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		content.Users = append(content.Users, backupUser{
			ID: u.ID, Username: u.Username, FullName: u.FullName, PasswordHash: u.PasswordHash, TOTPSecret: u.TOTPSecret,
			Disabled: u.Disabled, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
		})
	}
	servers, err := q.Servers()
	if err != nil {
		return nil, err
	}
	for _, v := range servers {
		content.Servers = append(content.Servers, backupServer{
			ID: v.ID, Name: v.Name, Interface: v.Interface, Enabled: v.Enabled, ListenPort: v.ListenPort,
			PublicHost: v.PublicHost, PublicPort: v.PublicPort, PrivateKey: v.PrivateKey, Network: v.Network, Network6: v.Network6,
			Networks: v.Networks, DNS: v.DNS, MTU: v.MTU, Keepalive: v.Keepalive, AuthMode: v.AuthMode,
			SessionTimeout: v.SessionTimeout, LockEndpoint: v.LockEndpoint, DetectCopies: v.DetectCopies,
			BlockCopies: v.BlockCopies, Redirect: v.Redirect, FallbackEndpoints: v.FallbackEndpoints,
			DeviceBinding: v.DeviceBinding, MachineID: v.MachineID, ClientToClient: v.ClientToClient,
			ReachableServers: v.ReachableServers, Routed: v.Routed, Inbound: v.Inbound, CreatedAt: v.CreatedAt,
			UpdatedAt: v.UpdatedAt,
		})
	}
	peers, err := q.Peers(0)
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		content.Peers = append(content.Peers, backupPeer{
			ID: p.ID, ServerID: p.ServerID, Name: p.Name, Enabled: p.Enabled, UserID: p.UserID, Address: p.Address,
			PrivateKey: p.PrivateKey, PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, RouteAll: p.RouteAll,
			Blocked: p.Blocked, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		})
	}
	devices, err := q.Devices()
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		d, ok := devices[p.ID]
		if !ok {
			continue
		}
		content.Devices = append(content.Devices, backupDevice{
			PeerID: d.PeerID, WindowUntil: d.WindowUntil, Key: d.Key, Kind: d.Kind, Name: d.Name, MachineID: d.MachineID,
			EnrolledAt: d.EnrolledAt, LastUsedAt: d.LastUsedAt, LastFrom: d.LastFrom, WireGuardKey: d.WireGuardKey,
			WireGuardKeyAt: d.WireGuardKeyAt,
		})
	}
	return content, nil
}

func summarize(content *backupContent, asker string) BackupSummary {
	summary := BackupSummary{
		CreatedAt: content.CreatedAt, MadeBy: content.MadeBy, Servers: len(content.Servers), Peers: len(content.Peers),
		Users: len(content.Users), Administrators: len(content.Admins), AdminUsernames: []string{},
	}
	for _, a := range content.Admins {
		if a.Disabled {
			continue
		}
		if a.Role == store.RoleAdmin {
			summary.AdminUsernames = append(summary.AdminUsernames, a.Username)
		}
		if strings.EqualFold(a.Username, asker) {
			summary.IncludesYou = true
		}
	}
	return summary
}

// CheckBackup opens a backup and says what it has, for the administrator by, before a restore: nothing changes.
func (s *Service) CheckBackup(by Actor, data []byte, passphrase string) (*BackupSummary, error) {
	admin, err := s.Admin(by.ID)
	if err != nil {
		return nil, err
	}
	content, err := openBackup(data, passphrase)
	if err != nil {
		return nil, err
	}
	plan, err := s.checkBackup(content, admin.Username)
	if err != nil {
		return nil, err
	}
	return &plan.summary, nil
}

// Restore replaces the whole configuration with a backup, for the administrator by, who gives the password. The
// open sessions end, the alerts go, the history and the events stay. The administrators are the ones of the backup:
// the caller logs out every session of the web UI.
func (s *Service) Restore(by Actor, password string, data []byte, passphrase string) (*BackupSummary, error) {
	admin, err := s.Admin(by.ID)
	if err != nil {
		return nil, err
	}
	if len(password) > MaxPassword || !secret.VerifyPassword(password, admin.PasswordHash) {
		return nil, &ValidationError{Fields: map[string]string{"password": "wrong"}}
	}
	content, err := openBackup(data, passphrase)
	if err != nil {
		return nil, err
	}
	plan, err := s.checkBackup(content, admin.Username)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var ended int64
	err = s.db.Tx(func(tx *store.Tx) error {
		var err error
		if ended, err = tx.EndOpenSessions(now.Unix(), EndRestored); err != nil {
			return err
		}
		// the ids of the backup can be of other peers
		if err := tx.EndOpenConnections(); err != nil {
			return err
		}
		if err := tx.ClearConfig(); err != nil {
			return err
		}
		policy, _ := json.Marshal(plan.settings.PasswordPolicy)
		mfa := ""
		if plan.settings.RequireAdminMFA {
			mfa = "1"
		}
		hours, days := "", ""
		if plan.settings.EnrollHours != 0 {
			hours = strconv.Itoa(plan.settings.EnrollHours)
		}
		if plan.settings.HistoryDays != 0 {
			days = strconv.Itoa(plan.settings.HistoryDays)
		}
		for key, value := range map[string]string{
			"public_host": plan.settings.PublicHost, "password_policy": string(policy), "require_admin_mfa": mfa,
			"enroll_hours": hours, "history_days": days,
		} {
			if err := tx.SetMeta(key, value); err != nil {
				return err
			}
		}
		for index := range plan.users {
			if err := tx.CreateUser(&plan.users[index]); err != nil {
				return fmt.Errorf("user %s: %w", plan.users[index].Username, err)
			}
		}
		for index := range plan.servers {
			if err := tx.CreateServer(&plan.servers[index]); err != nil {
				return fmt.Errorf("server %s: %w", plan.servers[index].Name, err)
			}
		}
		for index := range plan.peers {
			if err := tx.CreatePeer(&plan.peers[index]); err != nil {
				return fmt.Errorf("peer %s: %w", plan.peers[index].Name, err)
			}
		}
		for index := range plan.devices {
			if err := tx.SaveDevice(&plan.devices[index]); err != nil {
				return fmt.Errorf("device of the peer %d: %w", plan.devices[index].PeerID, err)
			}
		}
		for index := range plan.admins {
			if err := tx.CreateAdmin(&plan.admins[index]); err != nil {
				return fmt.Errorf("administrator %s: %w", plan.admins[index].Username, err)
			}
		}
		return nil
	})
	if err != nil {
		// nothing changed: the transaction is undone
		return nil, err
	}
	// what's in memory was about the configuration before: the ids of the backup can be of other peers and users
	s.failures = newLoginFailures()
	s.copies = map[int64]*copyTrack{}
	s.usedCodes = map[int64]map[uint64]time.Time{}
	s.usedAdminCodes = map[int64]map[uint64]time.Time{}
	s.pendingTOTP = map[int64]pendingSecret{}
	s.challenges = challenges{}
	s.mismatches = map[int64]time.Time{}
	s.counters = map[int64]peerCounters{}
	s.generation++
	s.applyLocked()
	detail := fmt.Sprintf("backup of %s: %s", time.Unix(plan.summary.CreatedAt, 0).UTC().Format("2006-01-02 15:04 UTC"),
		plan.summary.text())
	s.log.Info("configuration restored", "by", admin.Username, "backup", detail, "sessions_ended", ended)
	s.changeLocked(as(admin, by), adminEvent("backup_restored", "", "", detail))
	return &plan.summary, nil
}

// openBackup decrypts a backup: a wrong passphrase, a file that isn't a backup or a newer one are validation errors
func openBackup(data []byte, passphrase string) (*backupContent, error) {
	if len(data) == 0 {
		return nil, &ValidationError{Fields: map[string]string{"backup": "required"}}
	}
	if passphrase == "" {
		return nil, &ValidationError{Fields: map[string]string{"passphrase": "required"}}
	}
	if len(passphrase) > backup.MaxPassphrase {
		return nil, &ValidationError{Fields: map[string]string{"passphrase": "wrong"}}
	}
	plain, _, err := backup.Open(data, passphrase)
	switch {
	case errors.Is(err, backup.ErrPassphrase):
		return nil, &ValidationError{Fields: map[string]string{"passphrase": "wrong"}}
	case errors.Is(err, backup.ErrNewer):
		return nil, &ValidationError{Fields: map[string]string{"backup": "newer_version"}}
	case errors.Is(err, backup.ErrFormat):
		return nil, &ValidationError{Fields: map[string]string{"backup": "not_backup"}}
	case err != nil:
		return nil, err
	}
	var content backupContent
	if err := json.Unmarshal(plain, &content); err != nil {
		return nil, badBackup("the content can't be read")
	}
	if content.Version > BackupVersion {
		return nil, &ValidationError{Fields: map[string]string{"backup": "newer_version"}}
	}
	if content.Version < 1 {
		return nil, badBackup("no version")
	}
	return &content, nil
}

func badBackup(format string, args ...any) error {
	return &ValidationError{Fields: map[string]string{"backup": "invalid_content"}, Detail: fmt.Sprintf(format, args...)}
}

// short quotes a name of a backup for a message, cut when it's long
func short(name string) string {
	if runes := []rune(name); len(runes) > 40 {
		name = string(runes[:40]) + "…"
	}
	return fmt.Sprintf("%q", name)
}

// checkBackup checks a backup as the API checks what it gets: a file edited by hand, or damaged and still sealed,
// can't put on the system what the web UI refuses. asker is the username of the administrator who restores.
func (s *Service) checkBackup(content *backupContent, asker string) (*restorePlan, error) {
	plan := &restorePlan{settings: content.Settings}
	plan.settings.PublicHost = strings.TrimSpace(plan.settings.PublicHost)
	if host := plan.settings.PublicHost; host != "" && !validHost(host) {
		return nil, badBackup("the public address %s isn't valid", short(host))
	}
	if !plan.settings.PasswordPolicy.valid() {
		return nil, badBackup("the minimum length of the password policy isn't valid")
	}
	if hours := plan.settings.EnrollHours; hours != 0 && (hours < 1 || hours > MaxEnrollHours) {
		return nil, badBackup("the hours of the device enrollment aren't valid")
	}
	if days := plan.settings.HistoryDays; days != 0 && (days < 1 || days > MaxHistoryDays) {
		return nil, badBackup("the days of the history aren't valid")
	}

	userIDs := map[int64]bool{}
	usernames := map[string]bool{}
	for _, b := range content.Users {
		name := strings.TrimSpace(b.Username)
		switch {
		case !usernamePattern.MatchString(name):
			return nil, badBackup("the username %s isn't valid", short(b.Username))
		case usernames[strings.ToLower(name)]:
			return nil, badBackup("two users are named %s", short(name))
		case b.ID <= 0 || userIDs[b.ID]:
			return nil, badBackup("the user %s has no id of its own", short(name))
		case !validFullName(b.FullName):
			return nil, badBackup("the full name of the user %s isn't valid", short(name))
		case !secret.ValidHash(b.PasswordHash):
			return nil, badBackup("the password hash of the user %s isn't valid", short(name))
		case b.TOTPSecret != "" && !totp.ValidSecret(b.TOTPSecret):
			return nil, badBackup("the authenticator of the user %s isn't valid", short(name))
		}
		userIDs[b.ID] = true
		usernames[strings.ToLower(name)] = true
		plan.users = append(plan.users, store.User{
			ID: b.ID, Username: name, FullName: strings.TrimSpace(b.FullName), PasswordHash: b.PasswordHash,
			TOTPSecret: b.TOTPSecret, Disabled: b.Disabled, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
		})
	}

	adminIDs := map[int64]bool{}
	adminNames := map[string]bool{}
	active := 0
	for _, b := range content.Admins {
		name := strings.TrimSpace(b.Username)
		switch {
		case !usernamePattern.MatchString(name):
			return nil, badBackup("the administrator username %s isn't valid", short(b.Username))
		case adminNames[strings.ToLower(name)]:
			return nil, badBackup("two administrators are named %s", short(name))
		case b.ID <= 0 || adminIDs[b.ID]:
			return nil, badBackup("the administrator %s has no id of its own", short(name))
		case !validFullName(b.FullName):
			return nil, badBackup("the full name of the administrator %s isn't valid", short(name))
		case RoleRank(b.Role) == 0:
			return nil, badBackup("the role of the administrator %s isn't valid", short(name))
		case !secret.ValidHash(b.PasswordHash):
			return nil, badBackup("the password hash of the administrator %s isn't valid", short(name))
		case b.TOTPSecret != "" && !totp.ValidSecret(b.TOTPSecret):
			return nil, badBackup("the authenticator of the administrator %s isn't valid", short(name))
		case len(b.LastLoginFrom) > 64 || strings.IndexFunc(b.LastLoginFrom, unicode.IsControl) >= 0:
			return nil, badBackup("the last login of the administrator %s isn't valid", short(name))
		}
		if b.Role == store.RoleAdmin && !b.Disabled {
			active++
		}
		adminIDs[b.ID] = true
		adminNames[strings.ToLower(name)] = true
		plan.admins = append(plan.admins, store.Admin{
			ID: b.ID, Username: name, FullName: strings.TrimSpace(b.FullName), PasswordHash: b.PasswordHash,
			Role: b.Role, TOTPSecret: b.TOTPSecret, Disabled: b.Disabled, MustChangePassword: b.MustChangePassword,
			LastLoginAt: b.LastLoginAt, LastLoginFrom: b.LastLoginFrom, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
		})
	}
	if active == 0 {
		// nobody could log in to change anything after the restore
		return nil, badBackup("it has no enabled administrator with the role Administrator")
	}

	if len(content.Servers) > maxServers {
		return nil, badBackup("it has more than %d servers", maxServers)
	}
	byID := map[int64]store.Server{}
	interfaces := map[string]bool{}
	for _, b := range content.Servers {
		server := store.Server{ID: b.ID}
		input := ServerInput{
			Name: b.Name, Enabled: b.Enabled, PublicHost: b.PublicHost, ListenPort: b.ListenPort,
			PublicPort: b.PublicPort, Network: b.Network, Network6: b.Network6, Networks: b.Networks, DNS: b.DNS, MTU: b.MTU,
			Keepalive: b.Keepalive, AuthMode: b.AuthMode, SessionTimeout: b.SessionTimeout,
			LockEndpoint: b.LockEndpoint, DetectCopies: b.DetectCopies, BlockCopies: b.BlockCopies,
			Redirect: b.Redirect, FallbackEndpoints: b.FallbackEndpoints, DeviceBinding: b.DeviceBinding,
			MachineID: b.MachineID, ClientToClient: b.ClientToClient, Routed: b.Routed, Inbound: b.Inbound,
			// checked below, once all the servers are known
			ReachableServers: nil,
		}
		if err := s.checkServer(input, &server, plan.servers); err != nil {
			return nil, badBackup("the server %s: %v", short(b.Name), err)
		}
		_, keyErr := wgtypes.ParseKey(b.PrivateKey)
		_, seen := byID[b.ID]
		switch {
		case b.ID <= 0 || seen:
			return nil, badBackup("the server %s has no id of its own", short(b.Name))
		case !interfacePattern.MatchString(b.Interface) || interfaces[b.Interface]:
			return nil, badBackup("the interface of the server %s isn't valid", short(b.Name))
		case keyErr != nil:
			return nil, badBackup("the key of the server %s isn't valid", short(b.Name))
		}
		server.Interface, server.PrivateKey = b.Interface, b.PrivateKey
		server.CreatedAt, server.UpdatedAt = b.CreatedAt, b.UpdatedAt
		interfaces[b.Interface] = true
		plan.servers = append(plan.servers, server)
		byID[b.ID] = server
	}
	for index, b := range content.Servers {
		reachable := []int64{}
		for _, id := range b.ReachableServers {
			if _, ok := byID[id]; !ok || id == b.ID || containsID(reachable, id) {
				return nil, badBackup("the servers that %s reaches aren't valid", short(b.Name))
			}
			reachable = append(reachable, id)
		}
		plan.servers[index].ReachableServers = reachable
	}

	type taken struct {
		names, addresses map[string]bool
		users            map[int64]bool
	}
	perServer := map[int64]*taken{}
	peerIDs := map[int64]bool{}
	publicKeys := map[string]bool{}
	for _, b := range content.Peers {
		name := strings.TrimSpace(b.Name)
		server, ok := byID[b.ServerID]
		if !ok {
			return nil, badBackup("the peer %s has no server", short(name))
		}
		used := perServer[b.ServerID]
		if used == nil {
			used = &taken{names: map[string]bool{}, addresses: map[string]bool{}, users: map[int64]bool{}}
			perServer[b.ServerID] = used
		}
		tunnel, _ := netip.ParsePrefix(server.Network)
		address, addressErr := netip.ParseAddr(b.Address)
		private, err1 := wgtypes.ParseKey(b.PrivateKey)
		public, err2 := wgtypes.ParseKey(b.PublicKey)
		_, err3 := wgtypes.ParseKey(b.PresharedKey)
		switch {
		case name == "" || len([]rune(name)) > maxPeerName || strings.IndexFunc(name, unicode.IsControl) >= 0:
			return nil, badBackup("the name of a peer of %s isn't valid", short(server.Name))
		case used.names[strings.ToLower(name)]:
			return nil, badBackup("two peers of %s are named %s", short(server.Name), short(name))
		case b.ID <= 0 || peerIDs[b.ID]:
			return nil, badBackup("the peer %s has no id of its own", short(name))
		case b.UserID != 0 && !userIDs[b.UserID]:
			return nil, badBackup("the user of the peer %s isn't in the backup", short(name))
		case b.UserID != 0 && used.users[b.UserID]:
			return nil, badBackup("a user has two peers on %s", short(server.Name))
		case addressErr != nil || !peerAddress(tunnel, address) || used.addresses[address.String()]:
			return nil, badBackup("the address of the peer %s isn't valid", short(name))
		case errors.Join(err1, err2, err3) != nil || private.PublicKey() != public:
			return nil, badBackup("the keys of the peer %s aren't valid", short(name))
		case publicKeys[public.String()]:
			return nil, badBackup("two peers have the keys of %s", short(name))
		}
		used.names[strings.ToLower(name)] = true
		used.addresses[address.String()] = true
		if b.UserID != 0 {
			used.users[b.UserID] = true
		}
		peerIDs[b.ID] = true
		publicKeys[public.String()] = true
		plan.peers = append(plan.peers, store.Peer{
			ID: b.ID, ServerID: b.ServerID, Name: name, Enabled: b.Enabled, UserID: b.UserID,
			Address: address.String(), PrivateKey: private.String(), PublicKey: public.String(),
			PresharedKey: b.PresharedKey, RouteAll: b.RouteAll, Blocked: b.Blocked, CreatedAt: b.CreatedAt,
			UpdatedAt: b.UpdatedAt,
		})
	}

	peerNames := map[int64]string{}
	for _, peer := range plan.peers {
		peerNames[peer.ID] = peer.Name
	}
	// a key the device gives its peer can't be the one of another peer or of a server: WireGuard tells the peers
	// apart by their key only
	usedKeys := map[string]bool{}
	for key := range publicKeys {
		usedKeys[key] = true
	}
	for index := range plan.servers {
		usedKeys[serverPublicKey(&plan.servers[index])] = true
	}
	devicePeers := map[int64]bool{}
	for _, b := range content.Devices {
		name, ok := peerNames[b.PeerID]
		_, keyOK := decodeDeviceKey(b.Key)
		_, wireguardOK := decodeWireGuardKey(b.WireGuardKey)
		switch {
		case !ok:
			return nil, badBackup("a device has no peer")
		case devicePeers[b.PeerID]:
			return nil, badBackup("the peer %s has two devices", short(name))
		case b.Key != "" && !keyOK:
			return nil, badBackup("the key of the device of the peer %s isn't valid", short(name))
		case b.Kind != "" && !deviceKinds[b.Kind], deviceName(b.Name) != b.Name,
			b.MachineID != "" && !isMachineID(b.MachineID),
			len(b.LastFrom) > 64 || strings.IndexFunc(b.LastFrom, unicode.IsControl) >= 0:
			return nil, badBackup("the device of the peer %s isn't valid", short(name))
		case b.WireGuardKey != "" && (b.Key == "" || !wireguardOK || usedKeys[b.WireGuardKey]):
			return nil, badBackup("the WireGuard key of the device of the peer %s isn't valid", short(name))
		}
		devicePeers[b.PeerID] = true
		if b.WireGuardKey != "" {
			usedKeys[b.WireGuardKey] = true
		}
		plan.devices = append(plan.devices, store.Device{
			PeerID: b.PeerID, WindowUntil: b.WindowUntil, Key: b.Key, Kind: b.Kind, Name: b.Name, MachineID: b.MachineID,
			EnrolledAt: b.EnrolledAt, LastUsedAt: b.LastUsedAt, LastFrom: b.LastFrom, WireGuardKey: b.WireGuardKey,
			WireGuardKeyAt: b.WireGuardKeyAt,
		})
	}
	plan.summary = summarize(content, asker)
	return plan, nil
}
