package store

// Flow is a row of the flow logs: the connections that a peer started to one destination and port during one hour,
// and their bytes, counted when they end.
type Flow struct {
	ID int64
	// the start of the hour, in Unix seconds
	Hour       int64
	ServerID   int64
	PeerID     int64
	ServerName string
	PeerName   string
	Username   string
	// the IP protocol: 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6
	Protocol int
	// where the connections went: the real address, not a stand-in one
	Address string
	Port    int
	// the name of the access rules that gave the address, when it came from one
	Name        string
	Connections int64
	// the bytes from the peer, and back to it
	Sent     int64
	Received int64
	FirstAt  int64
	LastAt   int64
}

const flowColumns = "id, hour, server_id, peer_id, server_name, peer_name, username, protocol, address, port, name, connections, sent, received, first_at, last_at"

// AddFlow adds a row of the flow logs to the one of the same hour, peer, protocol, address and port, or makes it:
// its connections and bytes add up, the first and the last times widen, a name replaces an empty one.
func (t *Tx) AddFlow(f *Flow) error {
	_, err := t.q.Exec(`INSERT INTO flows (hour, server_id, peer_id, server_name, peer_name, username, protocol, address,
		port, name, connections, sent, received, first_at, last_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (hour, peer_id, protocol, address, port) DO UPDATE SET connections = connections + excluded.connections,
		sent = sent + excluded.sent, received = received + excluded.received,
		first_at = MIN(first_at, excluded.first_at), last_at = MAX(last_at, excluded.last_at),
		name = CASE WHEN excluded.name != '' THEN excluded.name ELSE name END`,
		f.Hour, f.ServerID, f.PeerID, f.ServerName, f.PeerName, f.Username, f.Protocol, f.Address, f.Port, f.Name,
		f.Connections, f.Sent, f.Received, f.FirstAt, f.LastAt)
	return err
}

// FlowsPage returns the rows of the flow logs that match, the latest first, and how many match in all. The dates
// take the rows whose hour overlaps them.
func (t *Tx) FlowsPage(f Filter) ([]Flow, int, error) {
	w := &where{}
	if f.ServerID != 0 {
		w.add("server_id = ?", f.ServerID)
	}
	if f.Since != 0 {
		w.add("last_at >= ?", f.Since)
	}
	if f.Until != 0 {
		w.add("first_at < ?", f.Until)
	}
	w.search(f.Search, "server_name", "peer_name", "username", "address", "name", "CAST(port AS TEXT)")
	total, err := t.count("flows", w)
	if err != nil {
		return nil, 0, err
	}
	query, args := w.page("last_at DESC, id DESC", f)
	rows, err := t.q.Query("SELECT "+flowColumns+" FROM flows "+query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []Flow
	for rows.Next() {
		var r Flow
		if err := rows.Scan(&r.ID, &r.Hour, &r.ServerID, &r.PeerID, &r.ServerName, &r.PeerName, &r.Username, &r.Protocol,
			&r.Address, &r.Port, &r.Name, &r.Connections, &r.Sent, &r.Received, &r.FirstAt, &r.LastAt); err != nil {
			return nil, 0, err
		}
		list = append(list, r)
	}
	return list, total, rows.Err()
}

// PruneFlows deletes the rows of the flow logs whose last connection is older than before, and the oldest hours past
// max rows.
func (t *Tx) PruneFlows(before int64, max int) error {
	if _, err := t.q.Exec("DELETE FROM flows WHERE last_at < ?", before); err != nil {
		return err
	}
	var count int
	if err := t.q.QueryRow("SELECT COUNT(*) FROM flows").Scan(&count); err != nil || count <= max {
		return err
	}
	// the hour of the row that stays oldest: that whole hour and the older ones go
	var hour int64
	if err := t.q.QueryRow("SELECT hour FROM flows ORDER BY hour DESC, id DESC LIMIT 1 OFFSET ?", max).Scan(&hour); err != nil {
		return err
	}
	_, err := t.q.Exec("DELETE FROM flows WHERE hour <= ?", hour)
	return err
}

// FlowStats are how many rows the flow logs have, and the oldest hour, 0 without rows.
func (t *Tx) FlowStats() (rows int, oldest int64, err error) {
	err = t.q.QueryRow("SELECT COUNT(*), COALESCE(MIN(hour), 0) FROM flows").Scan(&rows, &oldest)
	return rows, oldest, err
}
