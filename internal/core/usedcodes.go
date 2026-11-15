package core

import (
	"encoding/json"
	"time"
)

// The authenticator codes used, of the users and the administrators, are kept in the meta table too: a restart
// doesn't let a code that was just used work a second time.

const (
	metaUsedCodes = "used_codes"
	// the codes of a period stay valid for Skew periods after it: 3 minutes is more than the life of any code
	usedCodeLife = 3 * time.Minute
)

type savedCodes struct {
	Users  map[int64]map[uint64]int64 `json:"users"`
	Admins map[int64]map[uint64]int64 `json:"admins"`
}

func codesToSave(codes map[int64]map[uint64]time.Time) map[int64]map[uint64]int64 {
	saved := map[int64]map[uint64]int64{}
	for id, counters := range codes {
		if len(counters) == 0 {
			continue
		}
		saved[id] = map[uint64]int64{}
		for counter, at := range counters {
			saved[id][counter] = at.Unix()
		}
	}
	return saved
}

func codesSaved(saved map[int64]map[uint64]int64, now time.Time) map[int64]map[uint64]time.Time {
	codes := map[int64]map[uint64]time.Time{}
	for id, counters := range saved {
		for counter, unix := range counters {
			at := time.Unix(unix, 0)
			if now.Sub(at) > usedCodeLife {
				continue
			}
			if codes[id] == nil {
				codes[id] = map[uint64]time.Time{}
			}
			codes[id][counter] = at
		}
	}
	return codes
}

// saveUsedCodesLocked writes the codes used to the database. A failure only weakens the check after a restart.
func (s *Service) saveUsedCodesLocked() {
	data, err := json.Marshal(savedCodes{Users: codesToSave(s.usedCodes), Admins: codesToSave(s.usedAdminCodes)})
	if err == nil {
		err = s.db.Q().SetMeta(metaUsedCodes, string(data))
	}
	if err != nil {
		s.log.Warn("can't save the authenticator codes used", "error", err)
	}
}

// loadUsedCodesLocked reads the codes used before a restart, the ones still valid.
func (s *Service) loadUsedCodesLocked() {
	text, err := s.db.Q().Meta(metaUsedCodes)
	if err != nil || text == "" {
		return
	}
	var saved savedCodes
	if err := json.Unmarshal([]byte(text), &saved); err != nil {
		s.log.Warn("can't read the authenticator codes used", "error", err)
		return
	}
	now := s.now()
	s.usedCodes = codesSaved(saved.Users, now)
	s.usedAdminCodes = codesSaved(saved.Admins, now)
}
