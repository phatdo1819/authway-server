package admin

import (
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The history lists as CSV, for a spreadsheet: every row that matches the filter, the times in UTC (ISO 8601), the
// bytes as numbers, the reasons and the kinds as codes.

func (a *Admin) historyCSV(w http.ResponseWriter, r *http.Request, who *identity) {
	page, err := a.core.HistoryPage(filter(r, true))
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	rows := [][]string{{"server", "peer", "user", "address", "public_ip", "started", "ended", "end_reason"}}
	for _, s := range page.Items {
		rows = append(rows, []string{s.ServerName, s.PeerName, s.Username, s.Address, s.Endpoint, isoTime(s.StartedAt),
			isoTime(s.EndedAt), s.EndReason})
	}
	writeCSV(w, "authway-logins", rows)
}

func (a *Admin) connectionsCSV(w http.ResponseWriter, r *http.Request, who *identity) {
	page, err := a.core.ConnectionsPage(filter(r, true))
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	rows := [][]string{{"server", "peer", "user", "address", "public_ip", "started", "last_seen", "ended", "received_bytes", "sent_bytes"}}
	for _, c := range page.Items {
		rows = append(rows, []string{c.ServerName, c.PeerName, c.Username, c.Address, c.Endpoint, isoTime(c.StartedAt),
			isoTime(c.LastSeen), isoTime(c.EndedAt), strconv.FormatInt(c.Received, 10), strconv.FormatInt(c.Sent, 10)})
	}
	writeCSV(w, "authway-connections", rows)
}

func (a *Admin) eventsCSV(w http.ResponseWriter, r *http.Request, who *identity) {
	page, err := a.core.EventsPage(filter(r, true), r.URL.Query().Get("type"))
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	rows := [][]string{{"at", "kind", "server", "peer", "user", "by", "from", "detail"}}
	for _, e := range page.Items {
		rows = append(rows, []string{isoTime(e.At), e.Kind, e.ServerName, e.PeerName, e.Username, e.By, e.Source, e.Detail})
	}
	writeCSV(w, "authway-events", rows)
}

func writeCSV(w http.ResponseWriter, name string, rows [][]string) {
	stamp := time.Now().UTC().Format("20060102-1504")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name + "-" + stamp + ".csv"}))
	var out strings.Builder
	for _, row := range rows {
		for index, cell := range row {
			if index > 0 {
				out.WriteByte(',')
			}
			out.WriteString(quoteCell(safeCell(cell)))
		}
		out.WriteString("\r\n")
	}
	w.Write([]byte(out.String()))
}

// quoteCell quotes a cell of RFC 4180 when it needs it: a comma, a quote, a line break, or a space at its edges
func quoteCell(text string) string {
	if text == "" || (!strings.ContainsAny(text, ",\"\r\n") && strings.TrimSpace(text) == text) {
		return text
	}
	return `"` + strings.ReplaceAll(text, `"`, `""`) + `"`
}

// safeCell keeps a spreadsheet from reading a cell as a formula: names, details and typed usernames come from
// outside
func safeCell(text string) string {
	if text != "" && strings.ContainsRune("=+-@\t\r", rune(text[0])) {
		return "'" + text
	}
	return text
}

func isoTime(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
