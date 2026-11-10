// Package admin serves the web UI of the administrators and its JSON API.
package admin

import (
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/backup"
	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
)

//go:embed ui
var uiFiles embed.FS

const (
	cookieName = "authway_admin"
	// every API request carries this header: a page of another site can't add it without a CORS preflight, which
	// this API never answers
	csrfHeader  = "X-Requested-With"
	csrfValue   = "authway"
	sessionIdle = 2 * time.Hour
	sessionMax  = 12 * time.Hour
	maxBody     = 64 * 1024
	// a backup in a JSON string: its quotes and line breaks take two bytes each
	maxBackupBody = 2*backup.MaxSize + maxBody
	// failed logins of administrators from one address
	maxFailures = 10
	failWindow  = 15 * time.Minute
	// wrong authenticator codes of one administrator, from any address: the password was right
	maxCodeFailures = 5
	// wrong passwords given by a session to change its own account: a session left open can't be used to find the
	// password
	maxPasswordFailures = 10
	// the longest an import waits for the hashes of its passwords
	importTime = 5 * time.Minute
)

// What a route needs of the administrator: anyone logged in, even before the setup of the account, or a role.
const (
	needLogin    = 0
	needViewer   = 1
	needOperator = 2
	needAdmin    = 3
)

type Options struct {
	Log *slog.Logger
	// Secure marks the cookie for HTTPS only
	Secure bool
}

type Admin struct {
	core   *core.Service
	log    *slog.Logger
	secure bool

	mu       sync.Mutex
	sessions map[string]*session
	failures map[netip.Addr][]time.Time
	// wrong codes, by administrator
	codeFailures map[int64][]time.Time
	// wrong passwords of the changes of the own account, by administrator
	passwordFailures map[int64][]time.Time
}

type session struct {
	adminID int64
	// the generation of the configuration at the login: after a restore, adminID can be another administrator
	generation uint64
	created    time.Time
	seen       time.Time
}

// identity is the administrator of a request, read from the database at every request: a change of role, a
// disabled or deleted administrator apply at once.
type identity struct {
	admin *store.Admin
	// what the administrator must do before the rest of the web UI: core.SetupPassword, core.SetupMFA or ""
	setup string
	// the session of the request
	key string
}

func (who *identity) id() int64 {
	return who.admin.ID
}

func New(service *core.Service, options Options) *Admin {
	if options.Log == nil {
		options.Log = slog.Default()
	}
	return &Admin{
		core: service, log: options.Log, secure: options.Secure,
		sessions: map[string]*session{}, failures: map[netip.Addr][]time.Time{}, codeFailures: map[int64][]time.Time{},
		passwordFailures: map[int64][]time.Time{},
	}
}

type handler func(w http.ResponseWriter, r *http.Request, who *identity) (any, error)

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, need int, h handler) {
		mux.Handle(pattern, a.authenticated(need, h))
	}
	mux.HandleFunc("POST /api/login", a.login)
	// the health check of the container, without a login: short codes of what fails, nothing more
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if failing := a.core.Health(); len(failing) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy", "failing": failing})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// the account of the administrator logged in: also before its setup
	route("POST /api/logout", needLogin, a.logout)
	route("GET /api/me", needLogin, a.me)
	route("PUT /api/me/password", needLogin, a.changePassword)
	route("POST /api/me/totp", needLogin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.withPassword(who, func() (any, error) {
			return a.core.StartAdminTOTP(who.id(), input.Password)
		})
	})
	route("PUT /api/me/totp", needLogin, a.confirmTOTP)
	route("DELETE /api/me/totp", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.withPassword(who, func() (any, error) {
			return nil, a.core.RemoveOwnAdminTOTP(actor(who, r), input.Password)
		})
	})

	route("GET /api/status", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Status()
	})
	route("GET /api/settings", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Settings()
	})
	route("PUT /api/settings", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input core.SettingsInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.SetSettings(actor(who, r), input)
	})

	// a backup has every key and password hash, and a restore replaces everything: an Administrator, with the password
	mux.Handle("POST /api/backup", a.authenticatedRaw(needAdmin, a.backup))
	route("POST /api/restore/check", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input struct {
			Passphrase string `json:"passphrase"`
			Backup     string `json:"backup"`
		}
		if err := readJSONMax(r, &input, maxBackupBody); err != nil {
			return nil, err
		}
		return a.core.CheckBackup(actor(who, r), []byte(input.Backup), input.Passphrase)
	})
	route("POST /api/restore", needAdmin, a.restore)

	route("GET /api/admins", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Admins()
	})
	route("POST /api/admins", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input core.AdminInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		view, err := a.core.CreateAdmin(actor(who, r), input)
		if err == nil {
			// the id of a deleted administrator can come back
			a.forget(view.ID)
		}
		return view, err
	})
	route("PUT /api/admins/{id}", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input core.AdminInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		view, err := a.core.UpdateAdmin(actor(who, r), id, input)
		if err == nil && view.Disabled {
			a.endSessions(id, "")
		}
		return view, err
	})
	route("DELETE /api/admins/{id}", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		if err := a.core.DeleteAdmin(actor(who, r), id); err != nil {
			return nil, err
		}
		a.endSessions(id, "")
		a.forget(id)
		return nil, nil
	})
	route("PUT /api/admins/{id}/password", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		if err := a.core.ResetAdminPassword(actor(who, r), id, input.Password); err != nil {
			return nil, err
		}
		a.endSessions(id, "")
		return nil, nil
	})
	route("DELETE /api/admins/{id}/totp", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		if err := a.core.RemoveAdminTOTP(actor(who, r), id); err != nil {
			return nil, err
		}
		a.endSessions(id, "")
		return nil, nil
	})

	route("GET /api/servers", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Servers()
	})
	route("GET /api/servers/defaults", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		// ?server=ID: the values that server can take, its IPv6 network
		id, _ := strconv.ParseInt(r.URL.Query().Get("server"), 10, 64)
		return a.core.ServerDefaults(id)
	})
	route("POST /api/servers", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input core.ServerInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.CreateServer(actor(who, r), input)
	})
	route("GET /api/servers/{id}", needViewer, withID(a.core.Server))
	route("PUT /api/servers/{id}", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input core.ServerInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.UpdateServer(actor(who, r), id, input)
	})
	route("DELETE /api/servers/{id}", needAdmin, withActorIDDone(a.core.DeleteServer))
	route("GET /api/servers/{id}/peers", needViewer, withID(a.core.Peers))
	route("POST /api/servers/{id}/peers", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input core.PeerInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.CreatePeer(actor(who, r), id, input)
	})

	route("PUT /api/peers/{id}", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input core.PeerInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.UpdatePeer(actor(who, r), id, input)
	})
	route("DELETE /api/peers/{id}", needOperator, withActorIDDone(a.core.DeletePeer))
	route("POST /api/peers/{id}/keys", needOperator, withActorID(a.core.RegeneratePeerKeys))
	route("POST /api/peers/{id}/logout", needOperator, withActorIDDone(a.core.LogoutPeer))
	route("GET /api/peers/{id}/alerts", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		return a.core.Alerts(id, limit(r))
	})
	route("DELETE /api/peers/{id}/alerts", needOperator, withActorIDDone(a.core.ClearPeerAlerts))
	// device binding: let a new device enroll, or revoke the one enrolled
	route("POST /api/peers/{id}/device", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input struct {
			Hours int `json:"hours"`
		}
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.AllowDevice(actor(who, r), id, input.Hours)
	})
	route("DELETE /api/peers/{id}/device", needOperator, withActorID(a.core.RevokeDevice))
	route("GET /api/alerts", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Alerts(0, limit(r))
	})
	// the configuration file has the private key of the peer
	mux.Handle("GET /api/peers/{id}/config", a.authenticatedRaw(needOperator, a.peerConfig))
	// users from a CSV file: checked, or imported whole
	route("POST /api/import", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input core.ImportInput
		// a CSV file in a JSON string: its quotes and line breaks take two bytes each
		if err := readJSONMax(r, &input, 2*core.MaxImportBytes+maxBody); err != nil {
			return nil, err
		}
		if !input.Check {
			// the passwords of hundreds of users take longer to hash than an answer usually waits
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(importTime))
		}
		return a.core.Import(actor(who, r), input)
	})

	route("GET /api/users", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.Users()
	})
	route("POST /api/users", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		var input core.UserInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.CreateUser(actor(who, r), input)
	})
	route("PUT /api/users/{id}", needOperator, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		var input core.UserInput
		if err := readJSON(r, &input); err != nil {
			return nil, err
		}
		return a.core.UpdateUser(actor(who, r), id, input)
	})
	route("DELETE /api/users/{id}", needOperator, withActorIDDone(a.core.DeleteUser))
	route("POST /api/users/{id}/totp", needOperator, withActorID(a.core.SetupTOTP))
	route("DELETE /api/users/{id}/totp", needOperator, withActorIDDone(a.core.RemoveTOTP))

	route("GET /api/sessions", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.OpenSessions()
	})
	route("DELETE /api/sessions/{id}", needOperator, withActorIDDone(a.core.EndSession))
	// the history lists: a page of what matches the filter, and how many match; or all of it, as CSV
	route("GET /api/history", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.HistoryPage(filter(r, false))
	})
	route("GET /api/connections", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.ConnectionsPage(filter(r, false))
	})
	route("GET /api/events", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.EventsPage(filter(r, false), r.URL.Query().Get("type"))
	})
	mux.Handle("GET /api/history/csv", a.authenticatedRaw(needViewer, a.historyCSV))
	mux.Handle("GET /api/connections/csv", a.authenticatedRaw(needViewer, a.connectionsCSV))
	mux.Handle("GET /api/events/csv", a.authenticatedRaw(needViewer, a.eventsCSV))

	// the System page: the resources of the host and of Authway Server, the checks, their history, the latest lines
	// of the log. No secret goes to the log: the viewers can read it
	route("GET /api/system", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.System()
	})
	route("GET /api/system/history", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		query := r.URL.Query()
		seconds, _ := strconv.Atoi(query.Get("range"))
		since, _ := strconv.ParseInt(query.Get("since"), 10, 64)
		return a.core.SystemHistory(seconds, since)
	})
	route("GET /api/system/log", needViewer, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return a.core.SystemLog(r.URL.Query().Get("level") == "all")
	})
	// the address of the Docker host changed: the routers have the new routes. A change of the network, like the
	// servers: an Administrator
	route("POST /api/host-addresses/confirm", needAdmin, func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		return nil, a.core.ConfirmHostAddresses(actor(who, r))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	})
	mux.Handle("/", onlyGet(a.static()))
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// static serves the built web UI, and its index for the paths of the router of the UI
func (a *Admin) static() http.Handler {
	dist, err := fs.Sub(uiFiles, "ui/dist")
	if err == nil {
		if _, err = fs.Stat(dist, "index.html"); err != nil {
			dist = nil
		}
	}
	if dist == nil {
		placeholder, _ := uiFiles.ReadFile("ui/placeholder.html")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(placeholder)
		})
	}
	files := http.FileServerFS(dist)
	index, _ := fs.ReadFile(dist, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if _, err := fs.Stat(dist, path); err == nil {
				if strings.HasPrefix(path, "assets/") {
					// the names of the built files change with their content
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(index)
	})
}

// sameSite refuses the requests of other sites: the custom header, and the fetch metadata of the browsers that send it
func sameSite(r *http.Request) bool {
	if r.Header.Get(csrfHeader) != csrfValue {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

// who returns the session of the request: its administrator (0 without a session), its key and its generation
func (a *Admin) who(r *http.Request) (int64, string, uint64) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return 0, "", 0
	}
	key := secret.Fingerprint(cookie.Value)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.sessions[key]
	if !ok {
		return 0, "", 0
	}
	if now.Sub(entry.seen) > sessionIdle || now.Sub(entry.created) > sessionMax {
		delete(a.sessions, key)
		return 0, "", 0
	}
	entry.seen = now
	return entry.adminID, key, entry.generation
}

// endSessions logs out an administrator everywhere, but the session except
func (a *Admin) endSessions(adminID int64, except string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, entry := range a.sessions {
		if entry.adminID == adminID && key != except {
			delete(a.sessions, key)
		}
	}
}

func (a *Admin) authenticated(need int, h handler) http.Handler {
	return a.authenticatedRaw(need, func(w http.ResponseWriter, r *http.Request, who *identity) {
		result, err := h(w, r, who)
		if err != nil {
			a.writeError(w, r, err)
			return
		}
		if result == nil {
			result = map[string]any{"result": "success"}
		}
		writeJSON(w, http.StatusOK, result)
	})
}

func (a *Admin) authenticatedRaw(need int, h func(w http.ResponseWriter, r *http.Request, who *identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameSite(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		adminID, key, generation := a.who(r)
		if adminID == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not_authenticated"})
			return
		}
		admin, setup, err := a.core.AdminAccessSince(adminID, generation)
		if errors.Is(err, core.ErrStale) {
			// opened before a restore: only this session ends, the id can be of another administrator now
			a.mu.Lock()
			delete(a.sessions, key)
			a.mu.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not_authenticated"})
			return
		}
		if errors.Is(err, core.ErrNotFound) {
			// deleted or disabled since the login
			a.endSessions(adminID, "")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not_authenticated"})
			return
		}
		if err != nil {
			a.writeError(w, r, err)
			return
		}
		if need > needLogin {
			if setup != "" {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "setup_required", "setup": setup})
				return
			}
			if core.RoleRank(admin.Role) < need {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "not_allowed"})
				return
			}
		}
		h(w, r, &identity{admin: admin, setup: setup, key: key})
	})
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	if !sameSite(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return
	}
	source := remoteAddress(r)
	// counted by network: an IPv6 address by its /64, whose many addresses don't multiply the attempts
	counted := failureKey(source)
	now := time.Now()
	// before the password check: a restore during it gives the session an old generation, which the next request refuses
	generation := a.core.Generation()
	a.mu.Lock()
	recent := recentFailures(a.failures[counted], now)
	a.failures[counted] = recent
	a.mu.Unlock()
	if len(recent) >= maxFailures {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_attempts", "retry_after": retryAfter(recent, maxFailures, now)})
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if err := readJSON(r, &input); err != nil {
		a.writeError(w, r, err)
		return
	}
	name := truncate(strings.TrimSpace(input.Username), 64)
	fail := func(status int, code, reason string) {
		a.mu.Lock()
		a.failures[counted] = append(a.failures[counted], now)
		a.mu.Unlock()
		// an unknown username isn't kept, in the log either: it can be a password typed in the wrong field
		if known := a.core.AdminLoginFailed(name, source.String(), reason); known != "" {
			a.log.Warn("administrator login failed", "user", known, "from", source, "reason", reason)
		} else {
			a.log.Warn("administrator login failed", "from", source, "reason", "unknown username")
		}
		writeJSON(w, status, map[string]any{"error": code})
	}
	admin, ok := a.core.AdminLogin(input.Username, input.Password)
	if !ok {
		fail(http.StatusUnauthorized, "invalid_credentials", "wrong username or password")
		return
	}
	if admin.Disabled {
		fail(http.StatusForbidden, "disabled", "account disabled")
		return
	}
	if admin.TOTPSecret != "" {
		if input.OTP == "" {
			// the password is right: the page asks the code
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "otp_required"})
			return
		}
		a.mu.Lock()
		codes := recentFailures(a.codeFailures[admin.ID], now)
		a.codeFailures[admin.ID] = codes
		a.mu.Unlock()
		if len(codes) >= maxCodeFailures {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_attempts", "retry_after": retryAfter(codes, maxCodeFailures, now)})
			return
		}
		if !a.core.CheckAdminCode(admin.ID, strings.TrimSpace(input.OTP)) {
			a.mu.Lock()
			a.codeFailures[admin.ID] = append(a.codeFailures[admin.ID], now)
			a.mu.Unlock()
			fail(http.StatusUnauthorized, "invalid_otp", "wrong authenticator code")
			return
		}
	}
	token := secret.Token(32)
	a.mu.Lock()
	delete(a.failures, counted)
	delete(a.codeFailures, admin.ID)
	for key, entry := range a.sessions {
		if now.Sub(entry.seen) > sessionIdle || now.Sub(entry.created) > sessionMax {
			delete(a.sessions, key)
		}
	}
	for address, list := range a.failures {
		if len(recentFailures(list, now)) == 0 {
			delete(a.failures, address)
		}
	}
	a.sessions[secret.Fingerprint(token)] = &session{adminID: admin.ID, generation: generation, created: now, seen: now}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: a.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax.Seconds()),
	})
	a.log.Info("administrator logged in", "user", admin.Username, "from", source)
	a.core.AdminLoggedIn(admin.ID, source.String())
	_, setup, _ := a.core.AdminAccess(admin.ID)
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "role": admin.Role, "setup": setup})
}

func retryAfter(list []time.Time, max int, now time.Time) int {
	return int(list[len(list)-max].Add(failWindow).Sub(now).Seconds()) + 1
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
	a.mu.Lock()
	delete(a.sessions, who.key)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	return nil, nil
}

func (a *Admin) me(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
	settings, err := a.core.Settings()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":                who.admin.ID,
		"username":          who.admin.Username,
		"full_name":         who.admin.FullName,
		"role":              who.admin.Role,
		"totp":              who.admin.TOTPSecret != "",
		"setup":             who.setup,
		"require_admin_mfa": settings.RequireAdminMFA,
		"password_policy":   settings.PasswordPolicy,
	}, nil
}

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
	var input struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &input); err != nil {
		return nil, err
	}
	if _, err := a.withPassword(who, func() (any, error) {
		return nil, a.core.ChangeAdminPassword(actor(who, r), input.Current, input.Password)
	}); err != nil {
		return nil, err
	}
	// the other sessions of this administrator end
	a.endSessions(who.id(), who.key)
	a.log.Info("administrator password changed", "user", who.admin.Username)
	return nil, nil
}

// tooManyError is a request refused until RetryAfter seconds have passed.
type tooManyError struct {
	RetryAfter int
}

func (e *tooManyError) Error() string {
	return "too many attempts"
}

// withPassword runs a change of the own account that needs its password: the wrong passwords count, and 10 in 15
// minutes stop these changes, so a session left open can't be used to find the password.
func (a *Admin) withPassword(who *identity, change func() (any, error)) (any, error) {
	now := time.Now()
	a.mu.Lock()
	recent := recentFailures(a.passwordFailures[who.id()], now)
	a.passwordFailures[who.id()] = recent
	a.mu.Unlock()
	if len(recent) >= maxPasswordFailures {
		return nil, &tooManyError{RetryAfter: retryAfter(recent, maxPasswordFailures, now)}
	}
	result, err := change()
	var validation *core.ValidationError
	if errors.As(err, &validation) && (validation.Fields["current"] == "wrong" || validation.Fields["password"] == "wrong") {
		a.mu.Lock()
		a.passwordFailures[who.id()] = append(a.passwordFailures[who.id()], now)
		a.mu.Unlock()
		a.log.Warn("wrong password given by a session of an administrator", "user", who.admin.Username)
	}
	return result, err
}

// forget drops the failures counted for an administrator
func (a *Admin) forget(adminID int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.codeFailures, adminID)
	delete(a.passwordFailures, adminID)
}

func (a *Admin) confirmTOTP(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
	var input struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &input); err != nil {
		return nil, err
	}
	if err := a.core.ConfirmAdminTOTP(actor(who, r), strings.TrimSpace(input.Code)); err != nil {
		return nil, err
	}
	// a session opened without the code ends
	a.endSessions(who.id(), who.key)
	return nil, nil
}

// backup answers the file of a backup, sealed with the passphrase chosen
func (a *Admin) backup(w http.ResponseWriter, r *http.Request, who *identity) {
	var input struct {
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if err := readJSON(r, &input); err != nil {
		a.writeError(w, r, err)
		return
	}
	var name string
	var data []byte
	_, err := a.withPassword(who, func() (any, error) {
		var err error
		name, data, err = a.core.Backup(actor(who, r), input.Password, input.Passphrase)
		return nil, err
	})
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Write(data)
}

// restore replaces the configuration with a backup. The administrators are the ones of the backup, maybe with other
// ids: every session of the web UI ends, this one too, and the counters of the failures start again.
func (a *Admin) restore(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
	var input struct {
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
		Backup     string `json:"backup"`
	}
	if err := readJSONMax(r, &input, maxBackupBody); err != nil {
		return nil, err
	}
	summary, err := a.withPassword(who, func() (any, error) {
		return a.core.Restore(actor(who, r), input.Password, []byte(input.Backup), input.Passphrase)
	})
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.sessions = map[string]*session{}
	a.codeFailures = map[int64][]time.Time{}
	a.passwordFailures = map[int64][]time.Time{}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	a.log.Info("every session of the web UI ended after a restore", "by", who.admin.Username)
	return summary, nil
}

func (a *Admin) peerConfig(w http.ResponseWriter, r *http.Request, who *identity) {
	id, err := pathID(r)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	name, text, err := a.core.PeerConfig(actor(who, r), id)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Write([]byte(text))
}

var errBadRequest = errors.New("invalid_request")

func (a *Admin) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *core.ValidationError
	var refused *core.RefusedError
	var tooMany *tooManyError
	var changedSince *core.ChangedError
	switch {
	case errors.As(err, &changedSince):
		// saved by another administrator since the form opened: what it is now, for the form to show the changes
		writeJSON(w, http.StatusConflict, map[string]any{"error": "changed", "current": changedSince.Current,
			"by": changedSince.By, "at": changedSince.At})
	case errors.As(err, &validation):
		body := map[string]any{"error": "validation", "fields": validation.Fields}
		if validation.Detail != "" {
			body["detail"] = validation.Detail
		}
		writeJSON(w, http.StatusBadRequest, body)
	case errors.As(err, &tooMany):
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_attempts", "retry_after": tooMany.RetryAfter})
	case errors.As(err, &refused):
		writeJSON(w, http.StatusConflict, map[string]any{"error": refused.Code})
	case errors.Is(err, core.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	case errors.Is(err, errBadRequest):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
	default:
		a.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal_error"})
	}
}

func readJSON(r *http.Request, target any) error {
	return readJSONMax(r, target, maxBody)
}

// readJSONMax reads a body of at most max bytes: more for the routes that get a backup
func readJSONMax(r *http.Request, target any, max int) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errBadRequest
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(max)+1))
	if err != nil || len(data) > max {
		return errBadRequest
	}
	if err := json.Unmarshal(data, target); err != nil {
		return errBadRequest
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"error":"internal_error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, core.ErrNotFound
	}
	return id, nil
}

func withID[T any](fn func(int64) (T, error)) handler {
	return func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		return fn(id)
	}
}

// actor is the administrator of a request, for the events of the changes
func actor(who *identity, r *http.Request) core.Actor {
	from := ""
	if address := remoteAddress(r); address.IsValid() {
		from = address.String()
	}
	return core.Actor{ID: who.admin.ID, Username: who.admin.Username, From: from}
}

func withActorID[T any](fn func(core.Actor, int64) (T, error)) handler {
	return func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		return fn(actor(who, r), id)
	}
}

func withActorIDDone(fn func(core.Actor, int64) error) handler {
	return func(w http.ResponseWriter, r *http.Request, who *identity) (any, error) {
		id, err := pathID(r)
		if err != nil {
			return nil, err
		}
		return nil, fn(actor(who, r), id)
	}
}

// filter reads the filter of a history list: q, the words to find; server, its id; since and until, Unix times;
// limit and offset, the page. A CSV file takes all the rows that match, up to core.MaxExport.
func filter(r *http.Request, export bool) core.Filter {
	query := r.URL.Query()
	number := func(name string) int64 {
		value, err := strconv.ParseInt(query.Get(name), 10, 64)
		if err != nil || value < 0 {
			return 0
		}
		return value
	}
	words := strings.Fields(query.Get("q"))
	if len(words) > maxSearchWords {
		words = words[:maxSearchWords]
	}
	for index, word := range words {
		if runes := []rune(word); len(runes) > maxSearchWord {
			words[index] = string(runes[:maxSearchWord])
		}
	}
	f := core.Filter{Search: strings.Join(words, " "), ServerID: number("server"), Since: number("since"), Until: number("until")}
	if export {
		f.Limit = core.MaxExport
		return f
	}
	f.Limit = limit(r)
	f.Offset = int(min(number("offset"), core.MaxExport))
	return f
}

const (
	maxSearchWords = 8
	maxSearchWord  = 64
)

func limit(r *http.Request) int {
	value, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || value <= 0 {
		return 200
	}
	if value > core.MaxPage {
		return core.MaxPage
	}
	return value
}

func remoteAddress(r *http.Request) netip.Addr {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return addrPort.Addr().Unmap()
}

// failureKey is what the failed logins count by: an IPv4 address, or the /64 of an IPv6 one.
func failureKey(address netip.Addr) netip.Addr {
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().Addr()
	}
	return address
}

func recentFailures(list []time.Time, now time.Time) []time.Time {
	kept := list[:0:0]
	for _, at := range list {
		if now.Sub(at) < failWindow {
			kept = append(kept, at)
		}
	}
	return kept
}

func truncate(text string, length int) string {
	if len(text) > length {
		return text[:length]
	}
	return text
}

// onlyGet answers the pages; the catch-all of /api/ answers the rest of the API
func onlyGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}
