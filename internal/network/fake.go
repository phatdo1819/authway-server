package network

import (
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Fake keeps the state in memory and changes nothing on the system: for the tests, and to try the web pages on a
// computer without WireGuard.
type Fake struct {
	mu       sync.Mutex
	State    State
	Sessions map[string]map[netip.Addr]bool
	Peers    map[wgtypes.Key]PeerStats
	// ApplyError, when set, is returned by Apply; StatsError by Stats; IPv6Error by IPv6
	ApplyError error
	StatsError error
	IPv6Error  error
	Applied    int
	// the peers whose redirected connections were flushed
	Flushed []netip.Addr
	// see SetLive
	Live      netip.Addr
	liveSince time.Time
}

func NewFake() *Fake {
	return &Fake{Sessions: map[string]map[netip.Addr]bool{}, Peers: map[wgtypes.Key]PeerStats{}}
}

func (f *Fake) Apply(state State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Applied++
	if f.ApplyError != nil {
		return f.ApplyError
	}
	f.State = state
	f.Sessions = map[string]map[netip.Addr]bool{}
	for _, server := range state.Servers {
		set := map[netip.Addr]bool{}
		for _, address := range server.Sessions {
			set[address] = true
		}
		f.Sessions[server.Interface] = set
	}
	return nil
}

func (f *Fake) AddSession(iface string, addresses ...netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Sessions[iface] == nil {
		f.Sessions[iface] = map[netip.Addr]bool{}
	}
	for _, address := range addresses {
		f.Sessions[iface][address] = true
	}
	return nil
}

func (f *Fake) RemoveSession(iface string, addresses ...netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, address := range addresses {
		delete(f.Sessions[iface], address)
	}
	return nil
}

func (f *Fake) FlushRedirected(addresses ...netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Flushed = append(f.Flushed, addresses...)
	return nil
}

// IPv6 returns IPv6Error: nil, the tunnels have IPv6.
func (f *Fake) IPv6() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.IPv6Error
}

// Open tells whether the gate lets a peer through.
func (f *Fake) Open(iface string, address netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Sessions[iface][address]
}

// SetPeer sets what Stats returns for a peer.
func (f *Fake) SetPeer(key wgtypes.Key, stats PeerStats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Peers[key] = stats
}

func (f *Fake) Stats() (map[wgtypes.Key]PeerStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.StatsError != nil {
		return nil, f.StatsError
	}
	copied := make(map[wgtypes.Key]PeerStats, len(f.Peers))
	for key, stats := range f.Peers {
		copied[key] = stats
	}
	if f.Live.IsValid() {
		// the peer of the pages opened from this computer: connected, with the key it has on its interface now
		now := time.Now()
		for _, server := range f.State.Servers {
			for _, peer := range server.Peers {
				if peer.Address == f.Live {
					seconds := now.Unix() - f.liveSince.Unix()
					copied[peer.PublicKey] = PeerStats{Interface: server.Interface, Endpoint: netip.MustParseAddrPort("127.0.0.1:51820"),
						LastHandshake: now.Add(-20 * time.Second), Received: 2400 * seconds, Sent: 9100 * seconds}
				}
			}
		}
	}
	return copied, nil
}

// SetLive makes the peer at an address look connected from this computer, for -dev-peer.
func (f *Fake) SetLive(address netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Live, f.liveSince = address, time.Now()
}

func (f *Fake) Close() error {
	return nil
}
