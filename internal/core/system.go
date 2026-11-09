package core

import "github.com/phatdo1819/authway-server/internal/system"

// System is the System page now: the resources of the host, the interfaces, and the checks, with what Authway
// Server knows of itself.
func (s *Service) System() (system.Snapshot, error) {
	if s.opts.System == nil {
		return system.Snapshot{}, ErrNotFound
	}
	s.mu.Lock()
	state := system.State{ApplyError: s.applyError, StatsError: s.statsError, StatsAt: s.statsAt}
	servers, err := s.db.Q().Servers()
	s.mu.Unlock()
	if err != nil {
		return system.Snapshot{}, err
	}
	for _, server := range servers {
		if server.Enabled {
			state.Servers = append(state.Servers, system.ServerInterface{Name: server.Name, Interface: server.Interface})
			if server.Network6 != "" {
				state.IPv6Servers = append(state.IPv6Servers, server.Name)
			}
			if server.Routed {
				state.Routed = append(state.Routed, system.RoutedServer{Name: server.Name, Routes: s.routesOf(&server)})
			}
		}
	}
	// it reads files and the disks: outside the lock
	return s.opts.System.Snapshot(state), nil
}

// SystemHistory is the history of the latest seconds, the points after since only.
func (s *Service) SystemHistory(seconds int, since int64) (system.History, error) {
	if s.opts.System == nil {
		return system.History{}, ErrNotFound
	}
	return s.opts.System.History(seconds, since), nil
}

// SystemLog is the latest lines of the log, the newest first: the warnings and the errors, or all.
func (s *Service) SystemLog(all bool) ([]system.LogEntry, error) {
	if s.opts.System == nil {
		return nil, ErrNotFound
	}
	return s.opts.System.Log().Entries(all), nil
}
