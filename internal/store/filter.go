package store

import "strings"

// Filter narrows a history list, for the Activity page: the rows with each word of Search in one of their names,
// addresses or details, of one server, and of a time range. Limit rows come back, after Offset of them.
type Filter struct {
	Search   string
	ServerID int64
	// the events keep the name of their server, not its id
	ServerName string
	// the rows of [Since, Until): the sessions and the connections that overlap it, the events in it; 0 for no bound
	Since int64
	Until int64
	// the events of these kinds only, or of all the other kinds with ExceptKinds
	Kinds       []string
	ExceptKinds bool
	Limit       int
	Offset      int
}

// where builds the condition of a filter, with its arguments
type where struct {
	parts []string
	args  []any
}

func (w *where) add(condition string, args ...any) {
	w.parts = append(w.parts, condition)
	w.args = append(w.args, args...)
}

// search wants each word in one of the columns. LIKE of SQLite ignores the case of the ASCII letters.
func (w *where) search(text string, columns ...string) {
	for _, word := range strings.Fields(text) {
		pattern := "%" + likeEscaper.Replace(word) + "%"
		matches := make([]string, 0, len(columns))
		for _, column := range columns {
			matches = append(matches, column+` LIKE ? ESCAPE '\'`)
			w.args = append(w.args, pattern)
		}
		w.parts = append(w.parts, "("+strings.Join(matches, " OR ")+")")
	}
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)

func (w *where) String() string {
	if len(w.parts) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(w.parts, " AND ")
}

// page is the rest of the query, ORDER BY order, with the arguments of the condition and of the page
func (w *where) page(order string, f Filter) (string, []any) {
	args := append(append([]any{}, w.args...), f.Limit, f.Offset)
	return w.String() + " ORDER BY " + order + " LIMIT ? OFFSET ?", args
}

func (t *Tx) count(table string, w *where) (int, error) {
	var total int
	err := t.q.QueryRow("SELECT COUNT(*) FROM "+table+" "+w.String(), w.args...).Scan(&total)
	return total, err
}

// HistoryPage returns the ended sessions that match, the latest started first, and how many match in all. Every list
// of Activity has the newest on top, by the time it started.
func (t *Tx) HistoryPage(f Filter) ([]Session, int, error) {
	w := &where{}
	w.add("ended_at != 0")
	if f.ServerID != 0 {
		w.add("server_id = ?", f.ServerID)
	}
	if f.Since != 0 {
		w.add("ended_at >= ?", f.Since)
	}
	if f.Until != 0 {
		w.add("started_at < ?", f.Until)
	}
	w.search(f.Search, "server_name", "peer_name", "username", "address", "endpoint")
	total, err := t.count("sessions", w)
	if err != nil {
		return nil, 0, err
	}
	query, args := w.page("started_at DESC, id DESC", f)
	list, err := t.querySessions(query, args...)
	return list, total, err
}

// ConnectionsPage returns the connections that match, the latest started first, open or not, and how many match in
// all.
func (t *Tx) ConnectionsPage(f Filter) ([]Connection, int, error) {
	w := &where{}
	if f.ServerID != 0 {
		w.add("server_id = ?", f.ServerID)
	}
	if f.Since != 0 {
		w.add("(ended_at = 0 OR ended_at >= ?)", f.Since)
	}
	if f.Until != 0 {
		w.add("started_at < ?", f.Until)
	}
	w.search(f.Search, "server_name", "peer_name", "username", "address", "endpoint")
	total, err := t.count("connections", w)
	if err != nil {
		return nil, 0, err
	}
	query, args := w.page("started_at DESC, id DESC", f)
	list, err := t.queryConnections(query, args...)
	return list, total, err
}

// EventsPage returns the events that match, the newest first, and how many match in all.
func (t *Tx) EventsPage(f Filter) ([]Event, int, error) {
	w := &where{}
	if f.ServerName != "" {
		w.add("server_name = ?", f.ServerName)
	}
	if f.Since != 0 {
		w.add("at >= ?", f.Since)
	}
	if f.Until != 0 {
		w.add("at < ?", f.Until)
	}
	if len(f.Kinds) > 0 {
		marks := strings.TrimSuffix(strings.Repeat("?, ", len(f.Kinds)), ", ")
		args := make([]any, 0, len(f.Kinds))
		for _, kind := range f.Kinds {
			args = append(args, kind)
		}
		if f.ExceptKinds {
			w.add("kind NOT IN ("+marks+")", args...)
		} else {
			w.add("kind IN ("+marks+")", args...)
		}
	}
	w.search(f.Search, "server_name", "peer_name", "username", "actor", "source", "detail")
	total, err := t.count("events", w)
	if err != nil {
		return nil, 0, err
	}
	query, args := w.page("at DESC, id DESC", f)
	list, err := t.queryEvents(query, args...)
	return list, total, err
}
