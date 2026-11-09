package core

import (
	"context"
	"time"
)

// TickInterval is the time between two checks of the sessions and of the tunnels: also the longest time a copied
// configuration can share a session with the strict lock.
const TickInterval = 5 * time.Second

// Run checks the sessions until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(TickInterval)
	defer ticker.Stop()
	for {
		s.Tick()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick follows the endpoints of the sessions, watches for copies, ends the sessions that expired, stayed paused too
// long or whose peer stopped its handshakes, and retries a configuration that couldn't be applied.
func (s *Service) Tick() {
	stats, statsErr := s.net.Stats()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.ticked = now
	s.statsError = ""
	if statsErr == nil {
		s.stats = stats
		s.statsAt = now
	} else {
		s.statsError = statsErr.Error()
	}
	if s.applyError != "" {
		s.applyLocked()
	} else {
		// the address of the container, or the file of the helper, may have changed
		s.syncHostRoutesLocked()
	}
	// and the address of the Docker host, which the routers need
	s.watchHostAddressesLocked()
	q := s.db.Q()
	if statsErr == nil {
		s.followLocked(stats, 0)
		s.detectCopiesLocked(stats, now)
		if now.Sub(s.recorded) >= RecordInterval {
			s.recorded = now
			s.recordConnectionsLocked(stats, now)
		}
	}
	s.challenges.prune(now)
	for peer, at := range s.mismatches {
		if now.Sub(at) > CopyReportInterval {
			delete(s.mismatches, peer)
		}
	}
	sessions, err := q.OpenSessions()
	if err != nil {
		s.log.Error("can't read the sessions", "error", err)
		return
	}
	for _, session := range sessions {
		if now.Unix() >= session.ExpiresAt {
			s.endSessionLocked(session, EndExpired, true)
			continue
		}
		if session.PausedAt != 0 && now.Sub(time.Unix(session.PausedAt, 0)) > PauseLimit {
			s.endSessionLocked(session, EndEndpointChanged, true)
			continue
		}
		if statsErr != nil {
			continue
		}
		peer, err := q.Peer(session.PeerID)
		if err != nil {
			s.endSessionLocked(session, EndPeerChanged, true)
			continue
		}
		// since the login, or since this server started: a restart of the container takes the handshakes away
		latest := time.Unix(session.StartedAt, 0)
		if s.started.After(latest) {
			latest = s.started
		}
		if handshake := peerStatsOf(stats, peer).LastHandshake; handshake.After(latest) {
			latest = handshake
		}
		if now.Sub(latest) > IdleTimeout {
			s.endSessionLocked(session, EndIdle, true)
		}
	}
	s.failures.prune(now)
	// the codes of a period stay valid for Skew periods after it
	for user, codes := range s.usedCodes {
		for counter, at := range codes {
			if now.Sub(at) > 3*time.Minute {
				delete(codes, counter)
			}
		}
		if len(codes) == 0 {
			delete(s.usedCodes, user)
		}
	}
	s.pruneAdminCodesLocked(now)
	if now.Sub(s.pruned) > time.Hour {
		s.pruned = now
		before := now.AddDate(0, 0, -s.historyDaysLocked()).Unix()
		for name, prune := range map[string]func(int64) error{
			"sessions": q.PruneSessions, "events": q.PruneEvents, "alerts": q.PruneAlerts, "connections": q.PruneConnections,
		} {
			if err := prune(before); err != nil {
				s.log.Error("can't prune the history", "table", name, "error", err)
			}
		}
	}
}
