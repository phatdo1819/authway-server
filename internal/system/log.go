package system

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// the latest lines of the log kept for the System page, and the latest warnings and errors: the logins can push
	// an error out of the first ones in minutes
	LogLines     = 500
	ProblemLines = 200
)

// LogEntry is one line of the log.
type LogEntry struct {
	At      int64  `json:"at"`
	Level   string `json:"level"` // debug, info, warn, error
	Message string `json:"message"`
	// the attributes, as the log of the container writes them: user=alice from=203.0.113.7
	Attrs string `json:"attrs"`
}

// LogRing keeps the latest lines of the log in memory. Nothing secret goes to the log: the password of the first
// administrator is printed apart, never logged.
type LogRing struct {
	mu       sync.Mutex
	all      []LogEntry
	problems []LogEntry
}

func NewLogRing() *LogRing {
	return &LogRing{}
}

// Handler writes to next and keeps what it writes.
func (r *LogRing) Handler(next slog.Handler) slog.Handler {
	return &ringHandler{ring: r, next: next}
}

func (r *LogRing) add(entry LogEntry, problem bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = keep(r.all, entry, LogLines)
	if problem {
		r.problems = keep(r.problems, entry, ProblemLines)
	}
}

func keep(entries []LogEntry, entry LogEntry, limit int) []LogEntry {
	if len(entries) == limit {
		copy(entries, entries[1:])
		entries = entries[:limit-1]
	}
	return append(entries, entry)
}

// Entries are the latest lines, the newest first: only the warnings and the errors, or all.
func (r *LogRing) Entries(all bool) []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	source := r.problems
	if all {
		source = r.all
	}
	entries := make([]LogEntry, len(source))
	for index, entry := range source {
		entries[len(source)-1-index] = entry
	}
	return entries
}

// Errors counts the errors since a moment, and gives the latest.
func (r *LogRing) Errors(since time.Time) (int, LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count, latest := 0, LogEntry{}
	for _, entry := range r.problems {
		if entry.Level == "error" && entry.At >= since.Unix() {
			count++
			latest = entry
		}
	}
	return count, latest
}

type ringHandler struct {
	ring  *LogRing
	next  slog.Handler
	attrs []string
	group string
}

func (h *ringHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *ringHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := append([]string(nil), h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = appendAttr(attrs, h.group, attr)
		return true
	})
	at := record.Time
	if at.IsZero() {
		at = time.Now()
	}
	h.ring.add(LogEntry{At: at.Unix(), Level: levelName(record.Level), Message: record.Message, Attrs: strings.Join(attrs, " ")},
		record.Level >= slog.LevelWarn)
	return h.next.Handle(ctx, record)
}

func (h *ringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept := append([]string(nil), h.attrs...)
	for _, attr := range attrs {
		kept = appendAttr(kept, h.group, attr)
	}
	return &ringHandler{ring: h.ring, next: h.next.WithAttrs(attrs), attrs: kept, group: h.group}
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &ringHandler{ring: h.ring, next: h.next.WithGroup(name), attrs: h.attrs, group: h.group + name + "."}
}

func appendAttr(attrs []string, group string, attr slog.Attr) []string {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		for _, inner := range value.Group() {
			attrs = appendAttr(attrs, group+attr.Key+".", inner)
		}
		return attrs
	}
	if attr.Key == "" {
		return attrs
	}
	text := value.String()
	if text == "" || strings.ContainsAny(text, " \"=") {
		text = strconv.Quote(text)
	}
	return append(attrs, group+attr.Key+"="+text)
}

func levelName(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "error"
	case level >= slog.LevelWarn:
		return "warn"
	case level >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}
