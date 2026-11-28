package core

import (
	"context"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/flows"
	"github.com/phatdo1819/authway-server/internal/store"
)

// Flow logs: which destinations each peer reached, and how. The connection tracking of the kernel says each
// connection that starts and ends (see internal/flows); the connections of the peers add up in memory by hour, peer,
// protocol, destination and port, and the rows of each minute are written together, in one transaction, outside the
// lock of the service. A row of an hour gets the connections that started in it, and the bytes of each when it ends.
//
// Off by default. Internal records the connections to the networks of the peer's server, to the tunnels (the other
// peers), and to the addresses of the names of the access rules; All records the internet of the peers that send all
// their traffic too. Never the traffic to Authway Server itself: the login page, the DNS of the names. Not in the
// backups: they belong to this server, as the history does.
//
// What it costs: one process, conntrack, reads the events of the kernel; nothing changes in the path of the packets.
// The memory is bounded (maxOpenFlows, maxPendingFlows, maxFlowNames), the table too (MaxFlowRows, and the days of
// the settings), and what doesn't fit is counted, for the System page.

const (
	FlowsOff      = "off"
	FlowsInternal = "internal"
	FlowsAll      = "all"

	DefaultFlowDays = 90
	MaxFlowDays     = 365
	// the most rows of the flow logs: past it, the oldest hours go at the next pruning. About 180 bytes a row
	MaxFlowRows = 1_000_000

	// connections followed from their start to their end, for their bytes: past it, the bytes of the new ones are lost
	maxOpenFlows = 200_000
	// rows waiting for the next writing: past it, the new destinations of the minute are lost
	maxPendingFlows = 50_000
	// destinations whose name is known, from the DNS answers of the peers: past it, the names start again
	maxFlowNames = 65_536
	// a stopped conntrack starts again after this
	flowRetry = 30 * time.Second
)

// flowPeer is a peer as its rows of the flow logs keep it
type flowPeer struct {
	serverID, peerID               int64
	serverName, peerName, username string
	// the destinations of FlowsInternal: the networks of its server and the tunnels of all of them
	internal []netip.Prefix
}

type flowKey struct {
	hour     int64
	peerID   int64
	protocol uint8
	address  netip.Addr
	port     uint16
}

type flowRow struct {
	peer                        *flowPeer
	name                        string
	connections, sent, received int64
	first, last                 int64
}

// openFlow is a connection followed until it ends, for its bytes
type openFlow struct {
	key  flowKey
	peer *flowPeer
	name string
}

// flowRecorder has a lock of its own: the events come many a second, out of the lock of the service.
type flowRecorder struct {
	mu   sync.Mutex
	mode string
	// the peers by their addresses in the tunnels, the addresses of Authway Server there, the stand-in network
	peers    map[netip.Addr]*flowPeer
	own      map[netip.Addr]bool
	standIns netip.Prefix
	names    map[netip.Addr]string
	open     map[uint32]openFlow
	rows     map[flowKey]*flowRow
	// since the start: the times the kernel dropped events, and the rows that didn't fit
	lost, dropped uint64
	// conntrack runs; why it stopped
	running bool
	err     string
}

func newFlowRecorder() *flowRecorder {
	return &flowRecorder{mode: FlowsOff, names: map[netip.Addr]string{}, open: map[uint32]openFlow{},
		rows: map[flowKey]*flowRow{}}
}

func (r *flowRecorder) on() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mode != FlowsOff
}

// configure takes the mode and the peers of now. Off forgets what waits, but not the names: turned on later, the
// connections to the addresses that the devices kept from their answers have them.
func (r *flowRecorder) configure(mode string, peers map[netip.Addr]*flowPeer, own map[netip.Addr]bool, standIns netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode, r.peers, r.own, r.standIns = mode, peers, own, standIns
	if mode == FlowsOff {
		r.open = map[uint32]openFlow{}
		r.rows = map[flowKey]*flowRow{}
	}
}

// noteName records the name that gave an address to a peer, from a DNS answer or a look-up of Authway Server: its
// rows show it. Even while the flow logs are off.
func (r *flowRecorder) noteName(address netip.Addr, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.names) >= maxFlowNames {
		r.names = map[netip.Addr]string{}
	}
	r.names[address] = name
}

func (r *flowRecorder) lostEvents() {
	r.mu.Lock()
	r.lost++
	r.mu.Unlock()
}

// match is the row of a connection, its peer and the name of its destination: false for a connection that isn't of
// a peer, or that the mode doesn't record
func (r *flowRecorder) match(e flows.Event, now time.Time) (flowKey, *flowPeer, string, bool) {
	peer := r.peers[e.Source]
	if peer == nil {
		return flowKey{}, nil, "", false
	}
	// to Authway Server, or redirected to it: the login page, the DNS of the names
	if r.own[e.Destination] || r.own[e.ReplySource] {
		return flowKey{}, nil, "", false
	}
	// translated: where it went, a stand-in address leads to an internet one
	destination := e.Destination
	if e.ReplySource.IsValid() && e.ReplySource != e.Destination {
		destination = e.ReplySource
	}
	name := r.names[destination]
	if name == "" {
		name = r.names[e.Destination]
	}
	if r.mode == FlowsInternal && name == "" && !r.standIns.Contains(e.Destination) &&
		!insideAny(netip.PrefixFrom(destination, destination.BitLen()), peer.internal) {
		return flowKey{}, nil, "", false
	}
	key := flowKey{hour: now.Truncate(time.Hour).Unix(), peerID: peer.peerID, protocol: e.Protocol, address: destination, port: e.Port}
	return key, peer, name, true
}

// row is the pending row of a key, a new one when it has none: nil when there's no room
func (r *flowRecorder) row(key flowKey, peer *flowPeer, name string, now int64) *flowRow {
	row := r.rows[key]
	if row == nil {
		if len(r.rows) >= maxPendingFlows {
			r.dropped++
			return nil
		}
		row = &flowRow{peer: peer, first: now}
		r.rows[key] = row
	}
	if row.name == "" {
		row.name = name
	}
	row.last = max(row.last, now)
	return row
}

// record takes an event of the kernel
func (r *flowRecorder) record(e flows.Event, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.mode == FlowsOff {
		return
	}
	if e.New {
		key, peer, name, ok := r.match(e, now)
		if !ok {
			return
		}
		if row := r.row(key, peer, name, now.Unix()); row != nil {
			row.connections++
		}
		if len(r.open) < maxOpenFlows {
			r.open[e.ID] = openFlow{key: key, peer: peer, name: name}
		}
		return
	}
	flow, known := r.open[e.ID]
	if known {
		delete(r.open, e.ID)
	} else {
		// started before Authway Server watched, or when there was no room: counted at its end
		key, peer, name, ok := r.match(e, now)
		if !ok {
			return
		}
		flow = openFlow{key: key, peer: peer, name: name}
	}
	row := r.row(flow.key, flow.peer, flow.name, now.Unix())
	if row == nil {
		return
	}
	if !known {
		row.connections++
	}
	row.sent += int64(e.Sent)
	row.received += int64(e.Received)
}

// take is the rows that wait, for their writing
func (r *flowRecorder) take() map[flowKey]*flowRow {
	r.mu.Lock()
	defer r.mu.Unlock()
	rows := r.rows
	r.rows = map[flowKey]*flowRow{}
	return rows
}

func (r *flowRecorder) setRunning(running bool, err string) {
	r.mu.Lock()
	r.running, r.err = running, err
	r.mu.Unlock()
}

// writeFlows writes the rows that wait, in one transaction, outside the lock of the service
func (s *Service) writeFlows() {
	rows := s.flows.take()
	if len(rows) == 0 {
		return
	}
	err := s.db.Tx(func(tx *store.Tx) error {
		for key, row := range rows {
			flow := &store.Flow{Hour: key.hour, ServerID: row.peer.serverID, PeerID: key.peerID, ServerName: row.peer.serverName,
				PeerName: row.peer.peerName, Username: row.peer.username, Protocol: int(key.protocol),
				Address: key.address.String(), Port: int(key.port), Name: row.name, Connections: row.connections,
				Sent: row.sent, Received: row.received, FirstAt: row.first, LastAt: row.last}
			if err := tx.AddFlow(flow); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("can't write the flow logs: the rows of this minute are lost", "rows", len(rows), "error", err)
		s.flows.mu.Lock()
		s.flows.dropped += uint64(len(rows))
		s.flows.mu.Unlock()
	}
}

// runFlows runs conntrack while the flow logs are on, and writes their rows every minute, until ctx ends
func (s *Service) runFlows(ctx context.Context) {
	if s.opts.Flows == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var cancel context.CancelFunc
	done := make(chan error, 1)
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel = nil
			s.flows.setRunning(false, "")
		}
	}
	defer s.writeFlows()
	defer stop()
	var retryAt, written time.Time
	for {
		now := time.Now()
		on := s.flows.on()
		switch {
		case on && cancel == nil && !now.Before(retryAt):
			cancel = s.watchFlows(ctx, done)
		case !on && cancel != nil:
			stop()
			s.log.Info("flow logs: off")
		}
		select {
		case <-ctx.Done():
			return
		case err := <-done:
			cancel()
			cancel = nil
			message := "conntrack stopped"
			if err != nil {
				message = err.Error()
			}
			s.flows.setRunning(false, message)
			s.log.Warn("flow logs: can't watch the connections, trying again in 30 seconds", "error", message)
			retryAt = time.Now().Add(flowRetry)
		case <-ticker.C:
		}
		if time.Since(written) >= flows.Interval {
			written = time.Now()
			s.writeFlows()
		}
	}
}

// watchFlows starts conntrack, which says in done when it stops: the function that stops it
func (s *Service) watchFlows(ctx context.Context, done chan<- error) context.CancelFunc {
	watch, cancel := context.WithCancel(ctx)
	s.flows.setRunning(true, "")
	s.log.Info("flow logs: watching the connections of the peers")
	go func() {
		done <- s.opts.Flows(watch, func(e flows.Event) { s.flows.record(e, s.now()) }, s.flows.lostEvents)
	}()
	return cancel
}

func (s *Service) flowModeLocked() string {
	value, err := s.db.Q().Meta("flow_logs")
	if err != nil || (value != FlowsInternal && value != FlowsAll) {
		return FlowsOff
	}
	return value
}

func (s *Service) flowDaysLocked() int {
	return s.metaNumber("flow_days", DefaultFlowDays, MaxFlowDays)
}

// configureFlowsLocked gives the recorder the mode and the peers of now: at each apply, and when the settings change
func (s *Service) configureFlowsLocked() {
	mode := s.flowModeLocked()
	if mode == FlowsOff {
		s.flows.configure(mode, nil, nil, netip.Prefix{})
		return
	}
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return
	}
	users, err := q.Users()
	if err != nil {
		return
	}
	usernames := map[int64]string{}
	for _, user := range users {
		usernames[user.ID] = user.Username
	}
	var tunnels []netip.Prefix
	own := map[netip.Addr]bool{}
	for index := range servers {
		server := &servers[index]
		if tunnel, err := netip.ParsePrefix(server.Network); err == nil {
			tunnels = append(tunnels, tunnel.Masked())
			own[serverAddress(tunnel.Masked())] = true
		}
		if tunnel6 := tunnel6Of(server); tunnel6.IsValid() {
			tunnels = append(tunnels, tunnel6)
			own[serverAddress(tunnel6)] = true
		}
	}
	peers := map[netip.Addr]*flowPeer{}
	for index := range servers {
		server := &servers[index]
		if !server.Enabled {
			continue
		}
		list, err := q.Peers(server.ID)
		if err != nil {
			continue
		}
		internal := append(parsePrefixes(server.Networks), tunnels...)
		for _, peer := range list {
			if !peer.Enabled {
				continue
			}
			entry := &flowPeer{serverID: server.ID, peerID: peer.ID, serverName: server.Name, peerName: peer.Name,
				username: usernames[peer.UserID], internal: internal}
			for _, address := range addressesOf(server, peer.Address) {
				peers[address] = entry
			}
		}
	}
	standIns := netip.Prefix{}
	if validStandIns(s.opts.StandIns) {
		standIns = s.opts.StandIns.Masked()
	}
	s.flows.configure(mode, peers, own, standIns)
}

// FlowView is a row of the flow logs.
type FlowView struct {
	ID         int64  `json:"id"`
	Hour       int64  `json:"hour"`
	ServerID   int64  `json:"server_id"`
	ServerName string `json:"server_name"`
	PeerID     int64  `json:"peer_id"`
	PeerName   string `json:"peer_name"`
	Username   string `json:"username"`
	// tcp, udp, icmp, icmpv6, or the number of another protocol
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Name        string `json:"name"`
	Connections int64  `json:"connections"`
	Sent        int64  `json:"sent"`
	Received    int64  `json:"received"`
	FirstAt     int64  `json:"first_at"`
	LastAt      int64  `json:"last_at"`
}

func protocolName(number int) string {
	switch number {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return strconv.Itoa(number)
}

func (s *Service) FlowsPage(f Filter) (Page[FlowView], error) {
	flowRows, total, err := s.db.Q().FlowsPage(f)
	if err != nil {
		return Page[FlowView]{}, err
	}
	page := Page[FlowView]{Items: make([]FlowView, 0, len(flowRows)), Total: total}
	for _, r := range flowRows {
		page.Items = append(page.Items, FlowView{ID: r.ID, Hour: r.Hour, ServerID: r.ServerID, ServerName: r.ServerName,
			PeerID: r.PeerID, PeerName: r.PeerName, Username: r.Username, Protocol: protocolName(r.Protocol),
			Address: r.Address, Port: r.Port, Name: r.Name, Connections: r.Connections, Sent: r.Sent, Received: r.Received,
			FirstAt: r.FirstAt, LastAt: r.LastAt})
	}
	return page, nil
}

// FlowStatus says what the flow logs do: for the Activity page and the System page.
type FlowStatus struct {
	Mode string `json:"mode"`
	Days int    `json:"days"`
	// conntrack runs; why it stopped
	Recording bool   `json:"recording"`
	Error     string `json:"error"`
	// the kernel counts the bytes of the connections
	Bytes bool `json:"bytes"`
	// since the start: the times the kernel dropped events, and the rows that didn't fit
	Lost    uint64 `json:"lost"`
	Dropped uint64 `json:"dropped"`
	Rows    int    `json:"rows"`
	MaxRows int    `json:"max_rows"`
	// the oldest hour kept, 0 without rows
	Oldest int64 `json:"oldest"`
}

func (s *Service) FlowStatus() (FlowStatus, error) {
	s.mu.Lock()
	status := FlowStatus{Mode: s.flowModeLocked(), Days: s.flowDaysLocked(), MaxRows: MaxFlowRows}
	s.mu.Unlock()
	rows, oldest, err := s.db.Q().FlowStats()
	if err != nil {
		return FlowStatus{}, err
	}
	status.Rows, status.Oldest = rows, oldest
	s.flows.mu.Lock()
	status.Recording, status.Error, status.Lost, status.Dropped = s.flows.running, s.flows.err, s.flows.lost, s.flows.dropped
	s.flows.mu.Unlock()
	if s.opts.FlowBytes != nil {
		status.Bytes = s.opts.FlowBytes()
	}
	return status, nil
}
