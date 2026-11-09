// Package portal serves the login page and its API on the address of each WireGuard server, port 8181 by default.
// nftables lets only the peers reach it, through their tunnel.
package portal

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/core"
)

//go:embed static
var static embed.FS

const maxBody = 4096

type Options struct {
	Log *slog.Logger
	// DevPeer, only with the fake network: the requests from this computer count as coming from that peer address
	DevPeer netip.Addr
}

type Portal struct {
	core    *core.Service
	log     *slog.Logger
	devPeer netip.Addr
	limiter *limiter
}

func New(service *core.Service, options Options) *Portal {
	if options.Log == nil {
		options.Log = slog.Default()
	}
	// 30 requests a minute for each address, 10 at once: it only stops floods, the failed logins are counted by the
	// core for each public IP
	return &Portal{core: service, log: options.Log, devPeer: options.DevPeer, limiter: newLimiter(30, time.Minute, 10)}
}

func (p *Portal) Handler() http.Handler {
	files, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", p.status)
	mux.HandleFunc("POST /api/login", p.limited(p.login))
	mux.HandleFunc("POST /api/logout", p.logout)
	mux.HandleFunc("POST /api/device-key", p.limited(p.deviceKey))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	})
	mux.Handle("/", onlyGet(http.FileServerFS(files)))
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// client returns the tunnel address of the peer and the host it asked for
func (p *Portal) client(r *http.Request) (netip.Addr, string) {
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, ""
	}
	address := addrPort.Addr().Unmap()
	if p.devPeer.IsValid() && address.IsLoopback() {
		return p.devPeer, p.core.DevHost(p.devPeer)
	}
	return address, r.Host
}

func (p *Portal) status(w http.ResponseWriter, r *http.Request) {
	address, host := p.client(r)
	// the ID of the device key of Authway; an app without a key yet sends device= empty, which counts
	var keyID *string
	if values, ok := r.URL.Query()["device"]; ok && len(values) > 0 {
		id := values[0]
		keyID = &id
	}
	answer(w, p.core.LoginStatus(address, host, keyID))
}

func (p *Portal) login(w http.ResponseWriter, r *http.Request) {
	var request core.LoginRequest
	if !readJSON(w, r, &request) {
		return
	}
	address, host := p.client(r)
	answer(w, p.core.Login(address, host, request))
}

func (p *Portal) logout(w http.ResponseWriter, r *http.Request) {
	var request map[string]any
	if !readJSON(w, r, &request) {
		return
	}
	address, host := p.client(r)
	answer(w, p.core.Logout(address, host))
}

func (p *Portal) deviceKey(w http.ResponseWriter, r *http.Request) {
	var request core.DeviceKeyRequest
	if !readJSON(w, r, &request) {
		return
	}
	address, host := p.client(r)
	answer(w, p.core.DeviceKey(address, host, request))
}

func (p *Portal) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		address, _ := p.client(r)
		if !p.limiter.allow(address, time.Now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_requests", "retry_after": 10})
			return
		}
		next(w, r)
	}
}

// readJSON reads a small JSON object. A form of another site can't send application/json without a CORS preflight,
// which this API never answers.
func readJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.ContentLength > maxBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return false
	}
	if len(data) == 0 {
		data = []byte("{}")
	}
	if err := json.Unmarshal(data, target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return false
	}
	return true
}

func answer(w http.ResponseWriter, a core.Answer) {
	writeJSON(w, a.Status, a.Body)
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

// limiter is a token bucket for each address
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens a second
	burst   float64
	buckets map[netip.Addr]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(count int, per time.Duration, burst int) *limiter {
	return &limiter{rate: float64(count) / per.Seconds(), burst: float64(burst), buckets: map[netip.Addr]*bucket{}}
}

func (l *limiter) allow(address netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > time.Minute {
		l.swept = now
		for key, b := range l.buckets {
			if now.Sub(b.at) > time.Minute {
				delete(l.buckets, key)
			}
		}
	}
	b, ok := l.buckets[address]
	if !ok {
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[address] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
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
