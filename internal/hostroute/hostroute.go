// Package hostroute routes the tunnels of the routed servers through the Docker host, when the container is on a
// Docker bridge. The router of the networks sends a tunnel to the address of the host, and the host sends it on to
// the container: that needs a route on the host, and a way through the rules of Docker for the connections started
// from the networks. Authway Server writes what it needs in a folder that it shares with a helper on the network of
// the host (authway-server host-routes, in compose.host-routes.yaml); the helper adds the routes and the rules, and
// writes back what it did, with the address of the host towards each network: the next hop on the router.
package hostroute

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// what Authway Server asks, and what the helper did: both in the shared folder
	WantedFile = "wanted.json"
	ReportFile = "report.json"
	// the protocol of the routes of the helper, to tell them from the others: ip route show proto 77
	Proto = "77"
	// the comment of the rules of the helper in the chain DOCKER-USER of Docker
	Comment = "authway-server"
	// the helper looks again this often, and at once when the wanted file changes
	Interval = 5 * time.Second
	// a report older than this: the helper is stopped
	StaleAfter = 30 * time.Second
)

// Wanted is what Authway Server asks of the Docker host.
type Wanted struct {
	// the addresses of the container on its Docker network: the helper looks after the routes on their bridges, also
	// once no server is routed any more, to take its routes away
	Addresses []string `json:"addresses"`
	Routes    []Want   `json:"routes"`
}

// Want is the route to the tunnel network of a routed server through the address of the container, for one IP
// version.
type Want struct {
	Server string `json:"server"`
	Tunnel string `json:"tunnel"`
	Via    string `json:"via"`
	// the first network of the server of that version: the host tells its address towards it
	Network string `json:"network"`
	// the networks start connections to the peers: the rules of Docker have to let them through
	Inbound bool `json:"inbound"`
}

// Report is what the helper did, written again at each pass.
type Report struct {
	At     int64   `json:"at"`
	Routes []State `json:"routes"`
	// why nothing was done: the wanted file can't be read
	Error string `json:"error,omitempty"`
}

// State is what became of a Want.
type State struct {
	Tunnel string `json:"tunnel"`
	Via    string `json:"via"`
	// the bridge of the container on the host
	Bridge string `json:"bridge,omitempty"`
	// the address of the Docker host towards the network: the next hop of the route on the router
	Host   string `json:"host,omitempty"`
	Routed bool   `json:"routed"`
	// the connections started from the networks pass the rules of Docker
	Inbound bool `json:"inbound"`
	// why the route, or the rule of a server with connections from its networks, isn't there
	Error string `json:"error,omitempty"`
}

// Fresh tells whether the helper wrote the report lately: an older one, it's stopped.
func (r Report) Fresh(now time.Time) bool {
	age := now.Sub(time.Unix(r.At, 0))
	return r.At > 0 && age < StaleAfter && age > -StaleAfter
}

// Find is the state of the route to a tunnel through an address of the container.
func (r Report) Find(tunnel, via string) (State, bool) {
	for _, state := range r.Routes {
		if state.Tunnel == tunnel && state.Via == via {
			return state, true
		}
	}
	return State{}, false
}

// writeJSON replaces a file of the folder at once: the other side never reads half of it.
func writeJSON(dir, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), filepath.Join(dir, name))
	}
	if err != nil {
		os.Remove(file.Name())
	}
	return err
}

func readJSON(dir, name string, value any) error {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

// WriteWanted is for Authway Server: what it needs now.
func WriteWanted(dir string, wanted Wanted) error {
	return writeJSON(dir, WantedFile, wanted)
}

// WantedExists tells whether the file is still there: a folder emptied, Authway Server writes it again.
func WantedExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, WantedFile))
	return err == nil
}

// ReadWanted is for the helper: an error wrapping fs.ErrNotExist when Authway Server wrote nothing yet.
func ReadWanted(dir string) (Wanted, error) {
	var wanted Wanted
	err := readJSON(dir, WantedFile, &wanted)
	return wanted, err
}

func writeReport(dir string, report Report) error {
	return writeJSON(dir, ReportFile, report)
}

// ReadReport is what the helper did; an error when it never wrote.
func ReadReport(dir string) (Report, error) {
	var report Report
	err := readJSON(dir, ReportFile, &report)
	return report, err
}

// Reader reads the report at most once a second: every view of a routed server asks for it.
type Reader struct {
	dir    string
	mu     sync.Mutex
	readAt time.Time
	report Report
	err    error
}

func NewReader(dir string) *Reader {
	return &Reader{dir: dir}
}

// Get is the latest report, and whether the helper is running.
func (r *Reader) Get(now time.Time) (Report, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.readAt.IsZero() || now.Sub(r.readAt) >= time.Second || now.Before(r.readAt) {
		r.report, r.err = ReadReport(r.dir)
		r.readAt = now
	}
	return r.report, r.err == nil && r.report.Fresh(now)
}

// ErrNoChain is the answer of a host without the chain DOCKER-USER: Docker with its nftables backend, or no Docker.
var ErrNoChain = errors.New("the Docker host has no chain DOCKER-USER")
