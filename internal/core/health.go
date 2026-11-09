package core

import "time"

const (
	// Tick runs every TickInterval: past this, the loop of the sessions is stuck
	StuckAfter = 6 * TickInterval
	// how long Health waits for the lock of the service
	healthWait = 3 * time.Second
)

// Health is what keeps Authway Server from working, for the health check of the container, by short codes: stuck
// (the loop of the sessions, or the lock of the service), database, configuration (not applied), tunnels (not read).
// Empty: healthy. It says nothing more: anybody who reaches the web UI can ask.
func (s *Service) Health() []string {
	// a lock held for good is the worst case: don't wait for it with the others
	deadline := time.Now().Add(healthWait)
	for !s.mu.TryLock() {
		if time.Now().After(deadline) {
			return []string{"stuck"}
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer s.mu.Unlock()
	failing := []string{}
	if !s.ticked.IsZero() && s.now().Sub(s.ticked) > StuckAfter {
		failing = append(failing, "stuck")
	}
	if _, err := s.db.Q().Meta("password_policy"); err != nil {
		failing = append(failing, "database")
	}
	if s.applyError != "" {
		failing = append(failing, "configuration")
	}
	if s.statsError != "" {
		failing = append(failing, "tunnels")
	}
	return failing
}
