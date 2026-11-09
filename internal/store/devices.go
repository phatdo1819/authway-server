package store

// Devices

const deviceColumns = "peer_id, window_until, device_key, kind, device_name, machine_id, enrolled_at, last_used_at, last_from, wireguard_key, wireguard_key_at"

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	err := row.Scan(&d.PeerID, &d.WindowUntil, &d.Key, &d.Kind, &d.Name, &d.MachineID, &d.EnrolledAt, &d.LastUsedAt,
		&d.LastFrom, &d.WireGuardKey, &d.WireGuardKeyAt)
	return &d, err
}

// Device returns the device of a peer: ErrNotFound when the peer has neither a device nor an enrollment.
func (t *Tx) Device(peerID int64) (*Device, error) {
	d, err := scanDevice(t.q.QueryRow("SELECT "+deviceColumns+" FROM devices WHERE peer_id = ?", peerID))
	return d, notFound(err)
}

// Devices returns the devices of all the peers, by peer.
func (t *Tx) Devices() (map[int64]Device, error) {
	rows, err := t.q.Query("SELECT " + deviceColumns + " FROM devices")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := map[int64]Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices[d.PeerID] = *d
	}
	return devices, rows.Err()
}

// SaveDevice creates or replaces the device of a peer.
func (t *Tx) SaveDevice(d *Device) error {
	_, err := t.q.Exec(`INSERT INTO devices (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (peer_id) DO UPDATE SET window_until = excluded.window_until, device_key = excluded.device_key,
		kind = excluded.kind, device_name = excluded.device_name, machine_id = excluded.machine_id,
		enrolled_at = excluded.enrolled_at, last_used_at = excluded.last_used_at, last_from = excluded.last_from,
		wireguard_key = excluded.wireguard_key, wireguard_key_at = excluded.wireguard_key_at`,
		d.PeerID, d.WindowUntil, d.Key, d.Kind, d.Name, d.MachineID, d.EnrolledAt, d.LastUsedAt, d.LastFrom,
		d.WireGuardKey, d.WireGuardKeyAt)
	return conflict(err)
}

func (t *Tx) DeleteDevice(peerID int64) error {
	_, err := t.q.Exec("DELETE FROM devices WHERE peer_id = ?", peerID)
	return err
}

// Connections

const connectionColumns = "id, server_id, peer_id, server_name, peer_name, username, address, endpoint, started_at, last_seen, ended_at, received, sent, rx_start, tx_start"

func (t *Tx) queryConnections(query string, args ...any) ([]Connection, error) {
	rows, err := t.q.Query("SELECT "+connectionColumns+" FROM connections "+query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.ServerID, &c.PeerID, &c.ServerName, &c.PeerName, &c.Username, &c.Address,
			&c.Endpoint, &c.StartedAt, &c.LastSeen, &c.EndedAt, &c.Received, &c.Sent, &c.RxStart, &c.TxStart); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// OpenConnections returns the connections that haven't ended.
func (t *Tx) OpenConnections() ([]Connection, error) {
	return t.queryConnections("WHERE ended_at = 0 ORDER BY started_at")
}

// Connections returns the latest connections, the open ones first, then the newest.
func (t *Tx) Connections(limit int) ([]Connection, error) {
	return t.queryConnections("ORDER BY ended_at != 0, CASE WHEN ended_at = 0 THEN started_at ELSE ended_at END DESC, id DESC LIMIT ?", limit)
}

func (t *Tx) CreateConnection(c *Connection) error {
	result, err := t.q.Exec(`INSERT INTO connections (server_id, peer_id, server_name, peer_name, username, address,
		endpoint, started_at, last_seen, received, sent, rx_start, tx_start) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ServerID, c.PeerID, c.ServerName, c.PeerName, c.Username, c.Address, c.Endpoint, c.StartedAt, c.LastSeen,
		c.Received, c.Sent, c.RxStart, c.TxStart)
	if err != nil {
		return err
	}
	c.ID, err = result.LastInsertId()
	return err
}

// UpdateConnection saves what changes while a peer is connected: its names, the latest change of its counters and
// its bytes.
func (t *Tx) UpdateConnection(c *Connection) error {
	return changed(t.q.Exec(`UPDATE connections SET server_name = ?, peer_name = ?, username = ?, last_seen = ?,
		received = ?, sent = ?, rx_start = ?, tx_start = ? WHERE id = ? AND ended_at = 0`,
		c.ServerName, c.PeerName, c.Username, c.LastSeen, c.Received, c.Sent, c.RxStart, c.TxStart, c.ID))
}

// EndConnection ends a connection at the latest change of its counters.
func (t *Tx) EndConnection(id int64) error {
	return changed(t.q.Exec("UPDATE connections SET ended_at = MAX(last_seen, started_at) WHERE id = ? AND ended_at = 0", id))
}

// EndOpenConnections ends every open connection at its latest change: at start, the interfaces are new.
func (t *Tx) EndOpenConnections() error {
	_, err := t.q.Exec("UPDATE connections SET ended_at = MAX(last_seen, started_at) WHERE ended_at = 0")
	return err
}

// EndConnectionsOf ends the open connections of a peer, or of all the peers of a server with peerID 0, before they
// are deleted: a new peer can get the same id.
func (t *Tx) EndConnectionsOf(serverID, peerID int64) error {
	_, err := t.q.Exec("UPDATE connections SET ended_at = MAX(last_seen, started_at) WHERE ended_at = 0 AND (peer_id = ? OR (? = 0 AND server_id = ?))",
		peerID, peerID, serverID)
	return err
}

func (t *Tx) PruneConnections(before int64) error {
	_, err := t.q.Exec("DELETE FROM connections WHERE ended_at != 0 AND ended_at < ?", before)
	return err
}
