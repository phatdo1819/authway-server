package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// Device binding: a server can ask that its peers log in only from the device enrolled for them. The device, the
// Authway app, keeps a P-256 key for each VPN that never leaves it and signs a challenge of the login page; with
// the machine ID it also sends an HMAC of the hardware ID of its machine. Once logged in, it can give its peer a
// WireGuard key of its own: the configuration file, and every copy of it, then gets no handshake at all. The same
// protocol as the firewall login of NethSecurity (ns-wgauth), so Authway works with both.

const (
	// a challenge of the login page can be signed this long, once, by the address it was given to
	ChallengeTTL  = time.Minute
	maxChallenges = 4
	// the hours a peer without a device can enroll one: from its creation, its new keys or the binding of its
	// server, or when an administrator allows a new device
	DefaultEnrollHours = 72
	MaxEnrollHours     = 30 * 24
	// between the answer to a device that gives its peer a WireGuard key and the switch of the key: the answer goes
	// back through the tunnel of the old key
	KeySwitchDelay = time.Second

	DeviceMessage       = "ns-wgauth-device-v1"
	WireGuardKeyMessage = "ns-wgauth-wireguard-key-v1"
	// a DER ECDSA P-256 signature has at most 72 bytes
	maxSignature  = 72
	maxDeviceName = 64
	// a line of a signed message: the login body has at most 4 KiB anyway
	maxLine = 512
)

// the states of the device of a peer
const (
	DeviceEnrolled = "enrolled"
	DeviceWaiting  = "waiting" // a device can enroll at the next login
	DeviceClosed   = "closed"  // none can: an administrator allows a new one
)

// the WireGuard key a peer connects with, in the status and the web UI
const (
	KeyOfConfiguration = "configuration"
	KeyOfDevice        = "device"
)

var deviceKinds = map[string]bool{"software": true, "tpm": true, "secure-enclave": true}

// the DER SubjectPublicKeyInfo of a P-256 public key, before its 65 bytes uncompressed point
var p256Prefix = []byte{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
}

// DeviceProof is the `device` object of a login: the signature of the device.
type DeviceProof struct {
	Challenge string `json:"challenge"`
	// DER, base64
	Signature string `json:"signature"`
	// DER SubjectPublicKeyInfo, base64
	PublicKey string `json:"public_key"`
	// where the key is: software, tpm, secure-enclave
	Kind string `json:"kind"`
	// of the computer, for the administrator
	Name string `json:"name"`
	// HMAC-SHA256 of the hardware ID keyed with the public key of the server, hex, when the server asks for it
	MachineID string `json:"machine_id"`
}

// DeviceKeyRequest is POST /api/device-key: the enrolled device gives its peer a WireGuard key of its own.
type DeviceKeyRequest struct {
	Challenge    string `json:"challenge"`
	WireGuardKey string `json:"wireguard_key"`
	Signature    string `json:"signature"`
}

// challenges are the ones given to the addresses of the peers: random, for one address, valid ChallengeTTL and
// for one login. A few are kept for each address: the app can ask the status again while it signs.
type challenges map[netip.Addr][]issuedChallenge

type issuedChallenge struct {
	value string
	at    time.Time
}

func (c challenges) issue(address netip.Addr, now time.Time) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	value := base64.StdEncoding.EncodeToString(raw)
	c.prune(now)
	list := append(c[address], issuedChallenge{value: value, at: now})
	if len(list) > maxChallenges {
		list = list[len(list)-maxChallenges:]
	}
	c[address] = list
	return value
}

// use tells whether a challenge was given to the address and is still valid, and forgets it: it works once
func (c challenges) use(address netip.Addr, value string, now time.Time) bool {
	for index, item := range c[address] {
		if now.Sub(item.at) < ChallengeTTL && subtle.ConstantTimeCompare([]byte(item.value), []byte(value)) == 1 {
			list := c[address]
			c[address] = append(list[:index:index], list[index+1:]...)
			return true
		}
	}
	return false
}

func (c challenges) prune(now time.Time) {
	for address, list := range c {
		var kept []issuedChallenge
		for _, item := range list {
			if now.Sub(item.at) < ChallengeTTL {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(c, address)
		} else {
			c[address] = kept
		}
	}
}

// decodeDeviceKey reads the public key of a device: a P-256 key in DER SubjectPublicKeyInfo, base64 as the device
// writes it.
func decodeDeviceKey(text string) (*ecdsa.PublicKey, bool) {
	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(der) != text || len(der) != len(p256Prefix)+65 ||
		!bytes.HasPrefix(der, p256Prefix) || der[len(p256Prefix)] != 4 {
		return nil, false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, false
	}
	return key, true
}

// DeviceKeyID is the ID of the key of a device as its app computes it: the SHA-256 of its DER public key, in hex.
func DeviceKeyID(text string) string {
	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil || text == "" {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func decodeSignature(text string) ([]byte, bool) {
	signature, err := base64.StdEncoding.DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != text {
		return nil, false
	}
	// a DER sequence of two integers
	if len(signature) < 8 || len(signature) > maxSignature || signature[0] != 0x30 {
		return nil, false
	}
	return signature, true
}

func verifySignature(key *ecdsa.PublicKey, message, signature []byte) bool {
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(key, digest[:], signature)
}

// decodeWireGuardKey checks a WireGuard public key, base64 as WireGuard writes it.
func decodeWireGuardKey(text string) (wgtypes.Key, bool) {
	key, err := wgtypes.ParseKey(text)
	if err != nil || key.String() != text || key == (wgtypes.Key{}) {
		return wgtypes.Key{}, false
	}
	return key, true
}

func isLine(value string) bool {
	return value != "" && len(value) <= maxLine && !strings.ContainsAny(value, "\r\n")
}

func isMachineID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func deviceName(value string) string {
	var b strings.Builder
	count := 0
	for _, char := range value {
		if unicode.IsPrint(char) && count < maxDeviceName {
			b.WriteRune(char)
			count++
		}
	}
	return strings.TrimSpace(b.String())
}

// loginMessage is what a device signs to log in: one challenge, one server, one peer, one user name as sent.
func loginMessage(challenge, serverKey, peerKey, address, username, machineID string) []byte {
	return []byte(strings.Join([]string{DeviceMessage, challenge, serverKey, peerKey, address, username, machineID}, "\n"))
}

// keyMessage is what an enrolled device signs to give its peer a WireGuard key: the peer is named by the key of
// its configuration file.
func keyMessage(challenge, serverKey, peerKey, address, newKey string) []byte {
	return []byte(strings.Join([]string{WireGuardKeyMessage, challenge, serverKey, peerKey, address, newKey}, "\n"))
}

func deviceState(device *store.Device, now time.Time) string {
	switch {
	case device == nil:
		return DeviceClosed
	case device.Enrolled():
		return DeviceEnrolled
	case device.WindowUntil > now.Unix():
		return DeviceWaiting
	default:
		return DeviceClosed
	}
}

func (s *Service) deviceLocked(peerID int64) *store.Device {
	device, err := s.db.Q().Device(peerID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("can't read the device of a peer", "error", err)
		}
		return nil
	}
	return device
}

func serverPublicKey(server *store.Server) string {
	key, err := wgtypes.ParseKey(server.PrivateKey)
	if err != nil {
		return ""
	}
	return key.PublicKey().String()
}

// openEnrollmentLocked forgets the device of a peer and lets a new one enroll at the next login, for some time; 0
// closes the enrollment: nobody can log in until an administrator allows a device.
func (s *Service) openEnrollmentLocked(peerID int64, window time.Duration) error {
	until := int64(0)
	if window > 0 {
		until = s.now().Add(window).Unix()
	}
	return s.db.Q().SaveDevice(&store.Device{PeerID: peerID, WindowUntil: until})
}

func (s *Service) enrollWindowLocked() time.Duration {
	return time.Duration(s.enrollHoursLocked()) * time.Hour
}

// syncDevicesLocked opens the enrollment of the peers of the servers with device binding that have no device yet:
// new peers, or a restored configuration without devices.
func (s *Service) syncDevicesLocked() {
	q := s.db.Q()
	servers, err := q.Servers()
	if err != nil {
		return
	}
	var devices map[int64]store.Device
	for _, server := range servers {
		if !server.DeviceBinding {
			continue
		}
		if devices == nil {
			if devices, err = q.Devices(); err != nil {
				s.log.Error("can't read the devices", "error", err)
				return
			}
		}
		peers, err := q.Peers(server.ID)
		if err != nil {
			continue
		}
		for _, peer := range peers {
			if _, ok := devices[peer.ID]; ok {
				continue
			}
			if err := s.openEnrollmentLocked(peer.ID, s.enrollWindowLocked()); err != nil {
				s.log.Error("can't open the enrollment of a peer", "peer", peer.Name, "error", err)
				continue
			}
			s.log.Info("device enrollment open", "server", server.Name, "peer", peer.Name, "hours", s.enrollHoursLocked())
		}
	}
}

// deviceStatusLocked is the `device` object of the status of a peer of a server with device binding. keyID is the
// ID of the device key the app sent, nil when it sent none.
func (s *Service) deviceStatusLocked(server *store.Server, peer *store.Peer, address netip.Addr, keyID *string,
	endpoint string, now time.Time) map[string]any {
	device := s.deviceLocked(peer.ID)
	state := deviceState(device, now)
	status := map[string]any{
		"required":        true,
		"enrolled":        state == DeviceEnrolled,
		"enrollment_open": state == DeviceWaiting,
		"machine_id":      server.MachineID,
		"challenge":       s.challenges.issue(address, now),
	}
	if state != DeviceEnrolled {
		return status
	}
	status["wireguard_key"] = KeyOfConfiguration
	if device.WireGuardKey != "" {
		status["wireguard_key"] = KeyOfDevice
	}
	if keyID != nil {
		// the app of another device steps back before its handshakes take the session of the enrolled one
		this := *keyID != "" && subtle.ConstantTimeCompare([]byte(*keyID), []byte(DeviceKeyID(device.Key))) == 1
		status["this_device"] = this
		if !this {
			s.reportMismatchLocked(server, peer, endpoint, now, "connected from another device")
		}
	}
	return status
}

// checkDeviceLocked checks the device of a login on a server with device binding, before the password: from
// another device the password is never checked. It returns the error code, "" to go on, and the device to enroll
// after the password when the peer enrolls one.
func (s *Service) checkDeviceLocked(server *store.Server, peer *store.Peer, address netip.Addr, request LoginRequest,
	now time.Time) (string, *store.Device) {
	proof := request.Device
	if proof == nil {
		// the browser: only an app that signs can log in
		return "device_required", nil
	}
	if !s.challenges.use(address, proof.Challenge, now) {
		// the app asks for a new one and tries again
		return "challenge_expired", nil
	}
	device := s.deviceLocked(peer.ID)
	enrolling := !device.Enrolled()
	if enrolling && deviceState(device, now) != DeviceWaiting {
		return "device_not_enrolled", nil
	}
	key, keyOK := decodeDeviceKey(proof.PublicKey)
	signature, signatureOK := decodeSignature(proof.Signature)
	switch {
	case !keyOK || !signatureOK || !isLine(proof.Challenge) || !isLine(request.Username):
		return "device_mismatch", nil
	case proof.MachineID != "" && !isMachineID(proof.MachineID):
		return "device_mismatch", nil
	case server.MachineID && proof.MachineID == "":
		return "device_mismatch", nil
	}
	if !enrolling {
		if proof.PublicKey != device.Key {
			return "device_mismatch", nil
		}
		if server.MachineID && device.MachineID != "" &&
			subtle.ConstantTimeCompare([]byte(device.MachineID), []byte(proof.MachineID)) != 1 {
			return "device_mismatch", nil
		}
	}
	serverKey := serverPublicKey(server)
	if serverKey == "" {
		return "device_mismatch", nil
	}
	// the key of the configuration file, or the WireGuard key the device gave the peer
	peerKeys := []string{peer.PublicKey}
	if !enrolling && device.WireGuardKey != "" {
		peerKeys = append(peerKeys, device.WireGuardKey)
	}
	signed := false
	for _, peerKey := range peerKeys {
		message := loginMessage(proof.Challenge, serverKey, peerKey, peer.Address, request.Username, proof.MachineID)
		if verifySignature(key, message, signature) {
			signed = true
			break
		}
	}
	if !signed {
		return "device_mismatch", nil
	}
	if !enrolling {
		return "", nil
	}
	kind := proof.Kind
	if !deviceKinds[kind] {
		kind = "software"
	}
	machineID := ""
	if server.MachineID {
		machineID = proof.MachineID
	}
	return "", &store.Device{PeerID: peer.ID, Key: proof.PublicKey, Kind: kind, Name: deviceName(proof.Name), MachineID: machineID}
}

// recordDeviceLoginLocked records a login of a device after its password: it enrolls the device, or updates its
// last use. False when that device can't log in anymore: another one enrolled meanwhile, the window closed, or an
// administrator revoked it.
func (s *Service) recordDeviceLoginLocked(server *store.Server, peer *store.Peer, username string, enrolling *store.Device,
	proof *DeviceProof, endpoint string, now time.Time) bool {
	device := s.deviceLocked(peer.ID)
	if enrolling != nil {
		if deviceState(device, now) != DeviceWaiting {
			return false
		}
		enrolling.EnrolledAt, enrolling.LastUsedAt, enrolling.LastFrom = now.Unix(), now.Unix(), endpoint
		if err := s.db.Q().SaveDevice(enrolling); err != nil {
			s.log.Error("can't enroll a device", "peer", peer.Name, "error", err)
			return false
		}
		s.log.Info("device enrolled", "server", server.Name, "peer", peer.Name, "user", username,
			"device", enrolling.Name, "kind", enrolling.Kind, "from", endpoint)
		s.eventLocked(store.Event{Kind: "device_enrolled", ServerName: server.Name, PeerName: peer.Name,
			Username: username, Source: endpoint, Detail: deviceDetail(enrolling)})
		return true
	}
	if !device.Enrolled() || device.Key != proof.PublicKey {
		return false
	}
	device.LastUsedAt, device.LastFrom = now.Unix(), endpoint
	if server.MachineID && device.MachineID == "" && proof.MachineID != "" {
		// the server asks for it since the enrollment
		device.MachineID = proof.MachineID
		s.log.Info("machine ID recorded", "server", server.Name, "peer", peer.Name, "user", username)
	}
	if err := s.db.Q().SaveDevice(device); err != nil {
		s.log.Error("can't save the device of a peer", "peer", peer.Name, "error", err)
	}
	return true
}

func deviceDetail(device *store.Device) string {
	name := device.Name
	if name == "" {
		name = "a device without a name"
	}
	if device.Kind != "software" {
		name += " (" + device.Kind + ")"
	}
	return name
}

// reportMismatchLocked records an alert for another device, at most once an hour for each peer.
func (s *Service) reportMismatchLocked(server *store.Server, peer *store.Peer, endpoint string, now time.Time, what string) {
	if last, ok := s.mismatches[peer.ID]; ok && now.Sub(last) < CopyReportInterval {
		return
	}
	s.mismatches[peer.ID] = now
	username := s.usernameLocked(peer.UserID)
	s.log.Warn("a peer was used from another device than the enrolled one", "server", server.Name, "peer", peer.Name,
		"user", username, "from", endpoint, "what", what)
	var addresses []string
	if endpoint != "" {
		addresses = []string{endpoint}
	}
	if err := s.db.Q().AddAlert(&store.Alert{PeerID: peer.ID, At: now.Unix(), Kind: "device_mismatch", Username: username,
		Addresses: addresses}); err != nil {
		s.log.Error("can't save an alert", "error", err)
	}
	s.eventLocked(store.Event{Kind: "device_mismatch", ServerName: server.Name, PeerName: peer.Name, Username: username,
		Source: endpoint, Detail: what})
}

// DeviceKey is POST /api/device-key: the enrolled device, logged in, gives its peer a WireGuard key of its own. A
// second later the key switches on the interface, after the answer went back through the tunnel of the old key.
func (s *Service) DeviceKey(address netip.Addr, host string, request DeviceKeyRequest) Answer {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, peer, ok := s.findPeerLocked(address, host)
	if !ok {
		return fail(403, "forbidden")
	}
	if !server.DeviceBinding {
		return fail(403, "device_binding_not_required")
	}
	if peer.Blocked {
		return fail(403, "blocked")
	}
	now := s.now()
	session, ok := s.openSessionOfLocked(peer.ID)
	if !ok || session.PausedAt != 0 || now.Unix() >= session.ExpiresAt {
		return fail(401, "not_authenticated")
	}
	if !s.challenges.use(address, request.Challenge, now) {
		return fail(401, "challenge_expired")
	}
	device := s.deviceLocked(peer.ID)
	code := s.checkDeviceKeyLocked(server, peer, device, request)
	if code != "" {
		s.log.Warn("device key refused", "server", server.Name, "peer", peer.Name, "user", session.Username, "reason", code)
		switch code {
		case "invalid_key":
			return fail(400, code)
		case "key_in_use":
			return fail(409, code)
		default:
			return fail(403, code)
		}
	}
	if device.WireGuardKey != request.WireGuardKey {
		device.WireGuardKey, device.WireGuardKeyAt = request.WireGuardKey, now.Unix()
		if err := s.db.Q().SaveDevice(device); err != nil {
			s.log.Error("can't save the key of a device", "peer", peer.Name, "error", err)
			return fail(500, "internal_error")
		}
		s.log.Info("the peer connects with the WireGuard key of its device, its configuration file no longer connects",
			"server", server.Name, "peer", peer.Name, "user", session.Username, "device", device.Name)
		s.eventLocked(store.Event{Kind: "device_key", ServerName: server.Name, PeerName: peer.Name,
			Username: session.Username, Source: endpointIP(peerStatsOf(s.stats, peer)), Detail: deviceDetail(device)})
	}
	s.after(KeySwitchDelay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.applyLocked()
	})
	return Answer{Status: 200, Body: map[string]any{"result": "success"}}
}

func (s *Service) checkDeviceKeyLocked(server *store.Server, peer *store.Peer, device *store.Device, request DeviceKeyRequest) string {
	if !device.Enrolled() {
		return "device_not_enrolled"
	}
	if _, ok := decodeWireGuardKey(request.WireGuardKey); !ok {
		return "invalid_key"
	}
	// the key the peer has already is accepted again, for an app that missed the answer
	if request.WireGuardKey != device.WireGuardKey && s.keyInUseLocked(request.WireGuardKey) {
		return "key_in_use"
	}
	key, keyOK := decodeDeviceKey(device.Key)
	signature, signatureOK := decodeSignature(request.Signature)
	serverKey := serverPublicKey(server)
	if !keyOK || !signatureOK || !isLine(request.Challenge) || serverKey == "" {
		return "device_mismatch"
	}
	message := keyMessage(request.Challenge, serverKey, peer.PublicKey, peer.Address, request.WireGuardKey)
	if !verifySignature(key, message, signature) {
		return "device_mismatch"
	}
	return ""
}

// keyInUseLocked tells whether a WireGuard key is used by a peer, a device, a server or a live interface: WireGuard
// tells the peers apart by their key only, another peer's key would take its place.
func (s *Service) keyInUseLocked(text string) bool {
	q := s.db.Q()
	peers, err := q.Peers(0)
	if err != nil {
		return true
	}
	for _, peer := range peers {
		if peer.PublicKey == text || peer.DeviceKey == text {
			return true
		}
	}
	servers, err := q.Servers()
	if err != nil {
		return true
	}
	for index := range servers {
		if serverPublicKey(&servers[index]) == text {
			return true
		}
	}
	key, _ := wgtypes.ParseKey(text)
	_, live := s.stats[key]
	return live
}

// peerStatsOf is what WireGuard knows of a peer: of the key its device gave it when the interface has that one, else
// of the key of its configuration file. The sessions, the alerts and the history know the peer, not its key.
func peerStatsOf(stats map[wgtypes.Key]network.PeerStats, peer *store.Peer) network.PeerStats {
	if peer.DeviceKey != "" {
		if entry, ok := stats[keyOf(peer.DeviceKey)]; ok {
			return entry
		}
	}
	return stats[keyOf(peer.PublicKey)]
}

// AllowDevice forgets the device of a peer and lets a new one enroll at its next login, for hours (0: the hours of
// the settings), for example after a reinstall. The session of the peer ends, and the key of its configuration
// file connects again until the new device gives its own.
func (s *Service) AllowDevice(by Actor, peerID int64, hours int) (*PeerView, error) {
	if hours < 0 || hours > MaxEnrollHours {
		return nil, &ValidationError{Fields: map[string]string{"hours": "invalid"}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, server, err := s.peerAndServerLocked(peerID)
	if err != nil {
		return nil, err
	}
	if !server.DeviceBinding {
		return nil, &ValidationError{Fields: map[string]string{"device": "device_binding_not_required"}}
	}
	window := s.enrollWindowLocked()
	if hours > 0 {
		window = time.Duration(hours) * time.Hour
	}
	if err := s.openEnrollmentLocked(peer.ID, window); err != nil {
		return nil, err
	}
	s.log.Info("a new device can enroll", "server", server.Name, "peer", peer.Name, "hours", int(window.Hours()))
	s.changeLocked(by, store.Event{Kind: "device_allowed", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID), Detail: fmt.Sprintf("a new device can enroll for %d hours", int(window.Hours()))})
	s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == peer.ID }, EndDeviceChanged)
	delete(s.mismatches, peer.ID)
	s.applyLocked()
	return s.peerViewLocked(peer)
}

// RevokeDevice forgets the device of a peer and ends its session: it can't log in until an administrator allows a
// new device.
func (s *Service) RevokeDevice(by Actor, peerID int64) (*PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, server, err := s.peerAndServerLocked(peerID)
	if err != nil {
		return nil, err
	}
	if !server.DeviceBinding {
		return nil, &ValidationError{Fields: map[string]string{"device": "device_binding_not_required"}}
	}
	if err := s.openEnrollmentLocked(peer.ID, 0); err != nil {
		return nil, err
	}
	s.log.Info("device revoked", "server", server.Name, "peer", peer.Name)
	s.changeLocked(by, store.Event{Kind: "device_revoked", ServerName: server.Name, PeerName: peer.Name,
		Username: s.usernameLocked(peer.UserID)})
	s.endSessionsLocked(func(session store.Session) bool { return session.PeerID == peer.ID }, EndDeviceChanged)
	s.applyLocked()
	return s.peerViewLocked(peer)
}

func (s *Service) peerAndServerLocked(peerID int64) (*store.Peer, *store.Server, error) {
	q := s.db.Q()
	peer, err := q.Peer(peerID)
	if err != nil {
		return nil, nil, notFound(err)
	}
	server, err := q.Server(peer.ServerID)
	if err != nil {
		return nil, nil, notFound(err)
	}
	return peer, server, nil
}

// resetDeviceLocked is for a peer with new keys or another user: on a server with device binding a new device
// enrolls, elsewhere the device is forgotten.
func (s *Service) resetDeviceLocked(server *store.Server, peerID int64) {
	var err error
	if server.DeviceBinding {
		err = s.openEnrollmentLocked(peerID, s.enrollWindowLocked())
	} else {
		err = s.db.Q().DeleteDevice(peerID)
	}
	if err != nil {
		s.log.Error("can't reset the device of a peer", "error", err)
	}
	delete(s.mismatches, peerID)
}
