package core

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/phatdo1819/authway-server/internal/names"
	"github.com/phatdo1819/authway-server/internal/store"
)

// The addresses the peers learned for their names, and the stand-in addresses, are kept in the meta table too: a
// restart keeps them, so a device that kept an answer still opens new connections with it, to the same sites. They're
// written NamesSaveInterval after a change at most, at once after a restore, and when Authway Server stops. At the
// start, only what still holds is read: the addresses whose time isn't up, of peers and servers that haven't changed
// since (an older version of Authway Server could have changed them, without writing anything here), inside the
// networks of now, and the stand-in addresses of the stand-in network of now. Not in the backups: they belong to this
// server.

const (
	metaNames = "names"
	// the longest time between a change of the learned addresses and their writing
	NamesSaveInterval = time.Minute
)

type savedNames struct {
	// the network of the stand-in addresses, and each of them
	StandInNetwork string         `json:"stand_in_network,omitempty"`
	StandIns       []savedStandIn `json:"stand_ins,omitempty"`
	Peers          []savedLearned `json:"peers,omitempty"`
}

// savedStandIn is a stand-in address, the internet address it leads to, and until when a peer may use it, in Unix
// seconds
type savedStandIn struct {
	Address string `json:"address"`
	Real    string `json:"real"`
	Until   int64  `json:"until"`
}

// savedLearned is what a peer learned, each address with until when it stays open, in Unix seconds: the address, or
// the address and the ports of the rule of its name after a space; and by the same text, the names that taught it,
// with until when each holds it open (none from an older version). The ids, the creations and the versions of
// the peer and of its server tell that they're the same, unchanged: a new peer can get the id of a deleted one.
type savedLearned struct {
	Peer          int64                       `json:"peer"`
	Created       int64                       `json:"created"`
	Version       int64                       `json:"version"`
	Server        int64                       `json:"server"`
	ServerCreated int64                       `json:"server_created"`
	ServerVersion int64                       `json:"server_version"`
	Interface     string                      `json:"interface"`
	Address       string                      `json:"address"`
	Address6      string                      `json:"address6,omitempty"`
	Learned       map[string]int64            `json:"learned"`
	Names         map[string]map[string]int64 `json:"names,omitempty"`
}

// saveNamesLocked writes the learned and stand-in addresses to the database, when they differ from the last time. A
// failure is tried again NamesSaveInterval later: meanwhile, a restart forgets what changed.
func (s *Service) saveNamesLocked() {
	s.namesSavedAt = s.now()
	saved, err := s.namesToSaveLocked()
	var data []byte
	if err == nil {
		data, err = json.Marshal(saved)
	}
	if err == nil && string(data) != s.namesSaved {
		err = s.db.Q().SetMeta(metaNames, string(data))
	}
	if err != nil {
		s.log.Warn("can't save the addresses learned for names", "error", err)
		return
	}
	s.namesSaved = string(data)
	s.namesChanged = false
}

// namesToSaveLocked is what saveNamesLocked writes
func (s *Service) namesToSaveLocked() (savedNames, error) {
	var saved savedNames
	if validStandIns(s.opts.StandIns) {
		for _, standIn := range s.standInListLocked() {
			saved.StandIns = append(saved.StandIns, savedStandIn{Address: standIn.Address.String(), Real: standIn.Real.String(),
				Until: s.standIns[standIn.Address].until.Unix()})
		}
		if len(saved.StandIns) > 0 {
			saved.StandInNetwork = s.opts.StandIns.Masked().String()
		}
	}
	if len(s.learned) == 0 {
		return saved, nil
	}
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return saved, err
	}
	byInterface := map[string]*store.Server{}
	for index := range servers {
		byInterface[servers[index].Interface] = &servers[index]
	}
	peersOf := map[int64]map[int64]*store.Peer{}
	ids := make([]int64, 0, len(s.learned))
	for id := range s.learned {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	now := s.now()
	for _, id := range ids {
		entry := s.learned[id]
		server := byInterface[entry.iface]
		if server == nil {
			continue
		}
		peers, ok := peersOf[server.ID]
		if !ok {
			list, err := q.Peers(server.ID)
			if err != nil {
				return saved, err
			}
			peers = map[int64]*store.Peer{}
			for index := range list {
				peers[list[index].ID] = &list[index]
			}
			peersOf[server.ID] = peers
		}
		peer := peers[id]
		if peer == nil {
			continue
		}
		record := savedLearned{Peer: peer.ID, Created: peer.CreatedAt, Version: peer.Version, Server: server.ID,
			ServerCreated: server.CreatedAt, ServerVersion: server.Version, Interface: entry.iface,
			Address: entry.peer4.String(), Learned: map[string]int64{}}
		if entry.peer6.IsValid() {
			record.Address6 = entry.peer6.String()
		}
		for learnedAs, until := range entry.until {
			if !now.Before(until) {
				continue
			}
			text := learnedAs.String()
			record.Learned[text] = until.Unix()
			for name, nameUntil := range entry.from[learnedAs] {
				if !now.Before(nameUntil) {
					continue
				}
				if record.Names == nil {
					record.Names = map[string]map[string]int64{}
				}
				if record.Names[text] == nil {
					record.Names[text] = map[string]int64{}
				}
				record.Names[text][name] = nameUntil.Unix()
			}
		}
		if len(record.Learned) > 0 {
			saved.Peers = append(saved.Peers, record)
		}
	}
	return saved, nil
}

// loadNamesLocked reads the learned and stand-in addresses written before the restart, what still holds: before the
// first apply, which writes them in the firewall.
func (s *Service) loadNamesLocked() {
	q := s.db.Q()
	text, err := q.Meta(metaNames)
	if err != nil || text == "" {
		return
	}
	var saved savedNames
	if err := json.Unmarshal([]byte(text), &saved); err != nil {
		s.log.Warn("can't read the addresses learned for names", "error", err)
		return
	}
	now := s.now()
	network := netip.Prefix{}
	if validStandIns(s.opts.StandIns) {
		network = s.opts.StandIns.Masked()
	}
	// the stand-in addresses, of the same stand-in network
	before, _ := netip.ParsePrefix(saved.StandInNetwork)
	if network.IsValid() && before == network {
		for _, record := range saved.StandIns {
			address, err1 := netip.ParseAddr(record.Address)
			real, err2 := netip.ParseAddr(record.Real)
			until := time.Unix(record.Until, 0)
			if err1 != nil || err2 != nil || !address.Is4() || !network.Contains(address) || !real.Is4() || !onInternet(real) ||
				!now.Before(until.Add(StandInGrace)) {
				continue
			}
			if _, taken := s.standIns[address]; taken {
				continue
			}
			if _, taken := s.standInOf[real]; taken {
				continue
			}
			s.standIns[address] = &standIn{real: real, until: until}
			s.standInOf[real] = address
		}
	}
	servers, err := q.Servers()
	if err != nil {
		return
	}
	byID := map[int64]*store.Server{}
	for index := range servers {
		byID[servers[index].ID] = &servers[index]
	}
	peersOf := map[int64]map[int64]*store.Peer{}
	addresses := 0
	for _, record := range saved.Peers {
		server := byID[record.Server]
		if server == nil || !server.Enabled || server.CreatedAt != record.ServerCreated || server.Version != record.ServerVersion ||
			server.Interface != record.Interface {
			continue
		}
		peers, ok := peersOf[server.ID]
		if !ok {
			list, err := q.Peers(server.ID)
			if err != nil {
				continue
			}
			peers = map[int64]*store.Peer{}
			for index := range list {
				peers[list[index].ID] = &list[index]
			}
			peersOf[server.ID] = peers
		}
		peer := peers[record.Peer]
		if peer == nil || !peer.Enabled || peer.Blocked || peer.CreatedAt != record.Created || peer.Version != record.Version ||
			peer.Address != record.Address || !hasNames(peer.Access) {
			continue
		}
		tunnel, err1 := netip.ParsePrefix(server.Network)
		peer4, err2 := netip.ParseAddr(peer.Address)
		if err1 != nil || err2 != nil {
			continue
		}
		peer6, _ := address6(tunnel.Masked(), tunnel6Of(server), peer4)
		if peer6.IsValid() != (record.Address6 != "") || (peer6.IsValid() && peer6.String() != record.Address6) {
			continue
		}
		networks := parsePrefixes(server.Networks)
		standIns := !peer.RouteAll && s.standInsOn(server)
		entry := newLearnedPeer(server.Interface, peer4, peer6)
		// the ports of its rules of names: the peer is unchanged, so they're the same as when it learned
		rules := names.Rules(peer.Access)
		ports := map[string]bool{"": true}
		for _, rule := range rules {
			ports[rule.Ports] = true
		}
		for text, unix := range record.Learned {
			addressText, portsText, _ := strings.Cut(text, " ")
			address, err := netip.ParseAddr(addressText)
			until := time.Unix(unix, 0)
			if err != nil || !ports[portsText] || !now.Before(until) || len(entry.until) >= MaxLearned {
				continue
			}
			if (address.Is6() && !peer6.IsValid()) || address.Is4In6() {
				continue
			}
			switch {
			case insideAny(netip.PrefixFrom(address, address.BitLen()), networks):
			case network.Contains(address):
				// a stand-in address that still leads to its internet address
				if _, ok := s.standIns[address]; !ok || !standIns {
					continue
				}
			case before.IsValid() && before.Contains(address):
				// one of the stand-in network of before
				continue
			case onInternet(address) && !peer.RouteAll:
				// an internet address routed by the Authway app
			default:
				continue
			}
			// a clock set back: a day at most from now
			if limit := now.Add(LearnedMax); until.After(limit) {
				until = limit
			}
			key := learnedKey{address, portsText}
			entry.until[key] = until
			// the names that taught it, those of its rules with these ports
			for name, unix := range record.Names[text] {
				nameUntil := time.Unix(unix, 0)
				if !now.Before(nameUntil) || !slices.Contains(portsOfName(rules, name), portsText) {
					continue
				}
				if nameUntil.After(until) {
					nameUntil = until
				}
				entry.teach(key, name, nameUntil)
			}
		}
		if len(entry.until) > 0 {
			s.learned[peer.ID] = entry
			addresses += len(entry.until)
		}
	}
	if addresses > 0 || len(s.standIns) > 0 {
		s.log.Info("the addresses learned for names before the restart still hold", "addresses", addresses,
			"stand_ins", len(s.standIns))
	}
}
