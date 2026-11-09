package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/store"
)

// testDevice signs like Authway: a P-256 key, its public key in DER SubjectPublicKeyInfo
type testDevice struct {
	key    *ecdsa.PrivateKey
	public string
}

func newDevice(t *testing.T) *testDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testDevice{key: key, public: base64.StdEncoding.EncodeToString(der)}
}

func (d *testDevice) id() string {
	return DeviceKeyID(d.public)
}

func (d *testDevice) sign(message []byte) string {
	digest := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func (d *testDevice) proof(server *ServerView, peer *PeerView, challenge, username, machineID, peerKey string) *DeviceProof {
	message := loginMessage(challenge, server.PublicKey, peerKey, peer.Address, username, machineID)
	return &DeviceProof{Challenge: challenge, Signature: d.sign(message), PublicKey: d.public, Kind: "software",
		Name: "LAPTOP-42", MachineID: machineID}
}

// challenge asks the status of the peer, as the app does before it signs
func (f *fixture) challenge(peer *PeerView) string {
	f.t.Helper()
	answer := f.s.LoginStatus(netip.MustParseAddr(peer.Address), "10.8.0.1", nil)
	device, _ := answer.Body["device"].(map[string]any)
	challenge, _ := device["challenge"].(string)
	if challenge == "" {
		f.t.Fatalf("no challenge: %+v", answer)
	}
	return challenge
}

func (f *fixture) deviceStatus(peer *PeerView, keyID *string) map[string]any {
	f.t.Helper()
	device, ok := f.s.LoginStatus(netip.MustParseAddr(peer.Address), "10.8.0.1", keyID).Body["device"].(map[string]any)
	if !ok {
		f.t.Fatal("no device in the status")
	}
	return device
}

// deviceLogin logs in from a device that sends from a public IP
func (f *fixture) deviceLogin(server *ServerView, peer *PeerView, d *testDevice, from, machineID string) Answer {
	f.t.Helper()
	f.handshake(peer, from)
	proof := d.proof(server, peer, f.challenge(peer), peer.Username, machineID, peer.PublicKey)
	return f.s.Login(netip.MustParseAddr(peer.Address), "10.8.0.1",
		LoginRequest{Username: peer.Username, Password: "Secret,1234", Device: proof})
}

func (f *fixture) peerView(id int64) *PeerView {
	f.t.Helper()
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	peer, err := f.db.Q().Peer(id)
	if err != nil {
		f.t.Fatal(err)
	}
	view, err := f.s.peerViewLocked(peer)
	if err != nil {
		f.t.Fatal(err)
	}
	return view
}

func (f *fixture) eventKinds(prefix string) []string {
	events, _ := f.s.Events(100)
	var kinds []string
	for _, event := range events {
		if strings.HasPrefix(event.Kind, prefix) {
			kinds = append(kinds, event.Kind+": "+event.Detail)
		}
	}
	return kinds
}

func TestDeviceBinding(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DeviceBinding = true })
	if !server.DeviceBinding || server.MachineID {
		t.Fatalf("server %+v", server)
	}
	peer := f.peer(server, f.user("alice"))
	if peer.Device == nil || peer.Device.State != DeviceWaiting || peer.Device.EnrollmentUntil != f.clock.now.Add(72*time.Hour).Unix() {
		t.Fatalf("a new peer enrolls a device: %+v", peer.Device)
	}
	address := netip.MustParseAddr(peer.Address)
	f.handshake(peer, "203.0.113.5")
	empty := ""
	device := f.deviceStatus(peer, &empty)
	if device["required"] != true || device["enrolled"] != false || device["enrollment_open"] != true ||
		device["machine_id"] != false || device["challenge"] == "" {
		t.Fatalf("status %+v", device)
	}
	if _, ok := device["this_device"]; ok {
		t.Fatal("this_device before an enrollment")
	}

	if a := f.login(peer, "203.0.113.5"); a.Status != 403 || a.Body["error"] != "device_required" {
		t.Fatalf("from the browser: %+v", a)
	}
	laptop := newDevice(t)
	proof := laptop.proof(server, peer, "bm90IGdpdmVu", "alice", "", peer.PublicKey)
	login := func(username, password string, proof *DeviceProof) Answer {
		return f.s.Login(address, "10.8.0.1", LoginRequest{Username: username, Password: password, Device: proof})
	}
	if a := login("alice", "Secret,1234", proof); a.Status != 401 || a.Body["error"] != "challenge_expired" {
		t.Fatalf("a challenge never given: %+v", a)
	}
	proof = laptop.proof(server, peer, f.challenge(peer), "alice", "", peer.PublicKey)
	if a := login("alice", "wrong", proof); a.Body["error"] != "invalid_credentials" {
		t.Fatalf("a wrong password: %+v", a)
	}
	if state := f.peerView(peer.ID).Device.State; state != DeviceWaiting {
		t.Fatalf("a failed login enrolled the device: %s", state)
	}
	if a := login("alice", "Secret,1234", proof); a.Body["error"] != "challenge_expired" {
		t.Fatalf("a challenge used twice: %+v", a)
	}
	proof = laptop.proof(server, peer, f.challenge(peer), "alice", "", peer.PublicKey)
	f.clock.advance(ChallengeTTL)
	if a := login("alice", "Secret,1234", proof); a.Body["error"] != "challenge_expired" {
		t.Fatalf("an old challenge: %+v", a)
	}

	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 200 {
		t.Fatalf("the enrollment: %+v", a)
	}
	view := f.peerView(peer.ID).Device
	if view.State != DeviceEnrolled || view.Name != "LAPTOP-42" || view.Kind != "software" || view.LastFrom != "203.0.113.5" ||
		view.WireGuardKey != KeyOfConfiguration || view.MachineID || view.EnrolledAt != f.clock.now.Unix() {
		t.Fatalf("enrolled: %+v", view)
	}
	id := laptop.id()
	device = f.deviceStatus(peer, &id)
	if device["enrolled"] != true || device["enrollment_open"] != false || device["this_device"] != true ||
		device["wireguard_key"] != KeyOfConfiguration {
		t.Fatalf("the status of the enrolled device: %+v", device)
	}
	if _, ok := f.deviceStatus(peer, nil)["this_device"]; ok {
		t.Fatal("this_device without a key ID")
	}
	phone := newDevice(t)
	other := phone.id()
	if f.deviceStatus(peer, &other)["this_device"] != false || f.deviceStatus(peer, &empty)["this_device"] != false {
		t.Fatal("another device")
	}
	if alerts, _ := f.s.Alerts(peer.ID, 10); len(alerts) != 1 || alerts[0].Kind != "device_mismatch" ||
		strings.Join(alerts[0].Addresses, ",") != "203.0.113.5" {
		t.Fatalf("one alert an hour: %+v", alerts)
	}

	// another device with the right password, refused before the password
	if a := f.deviceLogin(server, peer, phone, "198.51.100.7", ""); a.Status != 401 || a.Body["error"] != "device_mismatch" {
		t.Fatalf("another device: %+v", a)
	}
	// signed for another user name, or another peer
	proof = laptop.proof(server, peer, f.challenge(peer), "bob", "", peer.PublicKey)
	if a := login("alice", "Secret,1234", proof); a.Body["error"] != "device_mismatch" {
		t.Fatalf("another user name: %+v", a)
	}
	proof = laptop.proof(server, peer, f.challenge(peer), "alice", "", server.PublicKey)
	if a := login("alice", "Secret,1234", proof); a.Body["error"] != "device_mismatch" {
		t.Fatalf("another peer: %+v", a)
	}
	proof = laptop.proof(server, peer, f.challenge(peer), "alice", "", peer.PublicKey)
	proof.Signature = proof.Signature[:len(proof.Signature)-4] + "AAA="
	if a := login("alice", "Secret,1234", proof); a.Body["error"] != "device_mismatch" {
		t.Fatalf("a damaged signature: %+v", a)
	}
	if events := f.eventKinds("login_failed"); len(events) != 5 || events[0] != "login_failed: another device" {
		t.Fatalf("failed logins: %q", events)
	}
	if alerts, _ := f.s.Alerts(peer.ID, 10); len(alerts) != 1 {
		t.Fatalf("one alert an hour: %+v", alerts)
	}

	f.clock.advance(time.Minute)
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 200 {
		t.Fatalf("the enrolled device again: %+v", a)
	}
	if view := f.peerView(peer.ID).Device; view.LastUsedAt != f.clock.now.Unix() || view.EnrolledAt == view.LastUsedAt {
		t.Fatalf("last use: %+v", view)
	}

	revoked, err := f.s.RevokeDevice(testActor, peer.ID)
	if err != nil || revoked.Device.State != DeviceClosed {
		t.Fatalf("revoked: %+v %v", revoked, err)
	}
	if f.session(peer.ID) != nil || f.lastEnd() != EndDeviceChanged {
		t.Fatalf("the session of a revoked device: %s", f.lastEnd())
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 403 || a.Body["error"] != "device_not_enrolled" {
		t.Fatalf("after the revoke: %+v", a)
	}
	allowed, err := f.s.AllowDevice(testActor, peer.ID, 2)
	if err != nil || allowed.Device.State != DeviceWaiting || allowed.Device.EnrollmentUntil != f.clock.now.Add(2*time.Hour).Unix() {
		t.Fatalf("allowed: %+v %v", allowed, err)
	}
	if a := f.deviceLogin(server, peer, phone, "198.51.100.7", ""); a.Status != 200 {
		t.Fatalf("the new device: %+v", a)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Body["error"] != "device_mismatch" {
		t.Fatalf("the old device: %+v", a)
	}
	if events := f.eventKinds("device_enrolled"); len(events) != 2 || events[0] != "device_enrolled: LAPTOP-42" {
		t.Fatalf("events %q", events)
	}
}

func TestMachineID(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DeviceBinding, input.MachineID = true, true })
	peer := f.peer(server, f.user("alice"))
	laptop := newDevice(t)
	machine := strings.Repeat("ab", 32)
	if f.deviceStatus(peer, nil)["machine_id"] != true {
		t.Fatal("the status asks for the machine ID")
	}
	for _, id := range []string{"", "ABCD", strings.Repeat("AB", 32)} {
		if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", id); a.Body["error"] != "device_mismatch" {
			t.Fatalf("machine ID %q: %+v", id, a)
		}
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", machine); a.Status != 200 {
		t.Fatalf("with the machine ID: %+v", a)
	}
	if !f.peerView(peer.ID).Device.MachineID {
		t.Fatal("the machine ID isn't recorded")
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", strings.Repeat("cd", 32)); a.Body["error"] != "device_mismatch" {
		t.Fatalf("the key on another machine: %+v", a)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", machine); a.Status != 200 {
		t.Fatalf("the same machine: %+v", a)
	}
}

func TestMachineIDAfterEnrollment(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DeviceBinding = true })
	peer := f.peer(server, f.user("alice"))
	laptop := newDevice(t)
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 200 {
		t.Fatalf("enrollment: %+v", a)
	}
	input := inputOf(server)
	input.MachineID = true
	server, err := f.s.UpdateServer(testActor, server.ID, input)
	if err != nil || !server.MachineID {
		t.Fatalf("machine ID on: %+v %v", server, err)
	}
	// still enrolled, and the session stays: the ID is recorded at the next login
	if f.peerView(peer.ID).Device.State != DeviceEnrolled || f.session(peer.ID) == nil {
		t.Fatal("turning the machine ID on reset the device")
	}
	machine := strings.Repeat("0f", 32)
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", machine); a.Status != 200 {
		t.Fatalf("the first login with the ID: %+v", a)
	}
	if !f.peerView(peer.ID).Device.MachineID {
		t.Fatal("the machine ID isn't recorded")
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", strings.Repeat("f0", 32)); a.Body["error"] != "device_mismatch" {
		t.Fatalf("another machine: %+v", a)
	}
}

func TestDeviceKey(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) { input.DeviceBinding = true })
	peer := f.peer(server, f.user("alice"))
	other := f.peer(server, f.user("bob"))
	address := netip.MustParseAddr(peer.Address)
	laptop, phone := newDevice(t), newDevice(t)
	private, _ := wgtypes.GeneratePrivateKey()
	newKey := private.PublicKey().String()
	request := func(key string, d *testDevice) DeviceKeyRequest {
		challenge := f.challenge(peer)
		return DeviceKeyRequest{Challenge: challenge, WireGuardKey: key,
			Signature: d.sign(keyMessage(challenge, server.PublicKey, peer.PublicKey, peer.Address, key))}
	}
	give := func(request DeviceKeyRequest) Answer {
		return f.s.DeviceKey(address, "10.8.0.1", request)
	}
	if a := give(request(newKey, laptop)); a.Status != 401 || a.Body["error"] != "not_authenticated" {
		t.Fatalf("not logged in: %+v", a)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 200 {
		t.Fatalf("enrollment: %+v", a)
	}
	for _, test := range []struct {
		name, key string
		device    *testDevice
		status    int
		code      string
	}{
		{"not a key", "abc", laptop, 400, "invalid_key"},
		{"the zero key", wgtypes.Key{}.String(), laptop, 400, "invalid_key"},
		{"the key of the file", peer.PublicKey, laptop, 409, "key_in_use"},
		{"the key of another peer", other.PublicKey, laptop, 409, "key_in_use"},
		{"the key of the server", server.PublicKey, laptop, 409, "key_in_use"},
		{"signed by another device", newKey, phone, 403, "device_mismatch"},
	} {
		if a := give(request(test.key, test.device)); a.Status != test.status || a.Body["error"] != test.code {
			t.Fatalf("%s: %+v", test.name, a)
		}
	}
	signed := request(newKey, laptop)
	if a := give(signed); a.Status != 200 {
		t.Fatalf("the key: %+v", a)
	}
	if a := give(signed); a.Body["error"] != "challenge_expired" {
		t.Fatalf("the same challenge again: %+v", a)
	}
	// the answer goes back through the tunnel of the old key first
	wired := func() string {
		for _, entry := range f.net.State.Servers[0].Peers {
			if entry.Address == address {
				return entry.PublicKey.String()
			}
		}
		return ""
	}
	if wired() != peer.PublicKey {
		t.Fatal("the key switched before the answer")
	}
	f.runTimers()
	if wired() != newKey {
		t.Fatalf("the key of the device isn't on the interface: %s", wired())
	}
	if f.deviceStatus(peer, nil)["wireguard_key"] != KeyOfDevice || f.peerView(peer.ID).Device.WireGuardKey != KeyOfDevice {
		t.Fatal("the status says the key of the configuration")
	}
	if a := give(request(newKey, laptop)); a.Status != 200 {
		t.Fatalf("the same key again, for an app that missed the answer: %+v", a)
	}
	if events := f.eventKinds("device_key"); len(events) != 1 {
		t.Fatalf("events %q", events)
	}

	// the device connects with its key: the session and the views follow the peer
	device, _ := wgtypes.ParseKey(newKey)
	delete(f.net.Peers, keyOf(peer.PublicKey))
	for range 3 {
		f.clock.advance(2 * time.Minute)
		f.net.SetPeer(device, network.PeerStats{Interface: "wg0", Endpoint: netip.MustParseAddrPort("203.0.113.5:40000"),
			LastHandshake: f.clock.now, Received: 10, Sent: 20})
		f.s.Tick()
	}
	if f.session(peer.ID) == nil {
		t.Fatal("the session ended: the handshakes of the device key aren't seen")
	}
	if view := f.peerView(peer.ID); !view.Connected || view.Endpoint != "203.0.113.5:40000" || view.Received != 10 {
		t.Fatalf("view %+v", view)
	}
	// a login signed with the key the device gave
	proof := laptop.proof(server, peer, f.challenge(peer), "alice", "", newKey)
	if a := f.s.Login(address, "10.8.0.1", LoginRequest{Username: "alice", Password: "Secret,1234", Device: proof}); a.Status != 200 {
		t.Fatalf("a login with the key of the device: %+v", a)
	}

	// binding off: the file connects again; on again: the device and its key are still there
	input := inputOf(server)
	input.DeviceBinding = false
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	if wired() != peer.PublicKey {
		t.Fatal("binding off: the key of the file")
	}
	// without binding the status gives no challenge: the request is refused before
	if a := give(DeviceKeyRequest{Challenge: "x", WireGuardKey: newKey, Signature: "x"}); a.Body["error"] != "device_binding_not_required" {
		t.Fatalf("without binding: %+v", a)
	}
	input.DeviceBinding = true
	if _, err := f.s.UpdateServer(testActor, server.ID, input); err != nil {
		t.Fatal(err)
	}
	if wired() != newKey || f.peerView(peer.ID).Device.State != DeviceEnrolled {
		t.Fatal("binding on again: the device and its key")
	}
	// new keys: the device and its key go, a device enrolls with the new file
	renewed, err := f.s.RegeneratePeerKeys(testActor, peer.ID)
	if err != nil || renewed.Device.State != DeviceWaiting || wired() != renewed.PublicKey {
		t.Fatalf("new keys: %+v %v", renewed, err)
	}
}

func TestEnrollmentWindow(t *testing.T) {
	f := setup(t)
	adminID := f.admin()
	server := f.server(store.AuthPassword)
	alice := f.user("alice")
	peer := f.peer(server, alice)
	if peer.Device != nil {
		t.Fatal("a device without binding")
	}
	if a := f.login(peer, "203.0.113.5"); a.Status != 200 {
		t.Fatalf("the browser without binding: %+v", a)
	}
	hours := 1
	if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{EnrollHours: &hours}); err != nil {
		t.Fatal(err)
	}
	input := inputOf(server)
	input.DeviceBinding = true
	server, err := f.s.UpdateServer(testActor, server.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if f.session(peer.ID) != nil {
		t.Fatal("binding on: the peers log in again, from their device")
	}
	if device := f.peerView(peer.ID).Device; device.State != DeviceWaiting || device.EnrollmentUntil != f.clock.now.Add(time.Hour).Unix() {
		t.Fatalf("binding on: %+v", device)
	}
	f.clock.advance(61 * time.Minute)
	if state := f.peerView(peer.ID).Device.State; state != DeviceClosed {
		t.Fatalf("after the window: %s", state)
	}
	laptop := newDevice(t)
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Body["error"] != "device_not_enrolled" {
		t.Fatalf("after the window: %+v", a)
	}
	for _, bad := range []int{0, MaxEnrollHours + 1} {
		if _, err := f.s.SetSettings(Actor{ID: adminID}, SettingsInput{EnrollHours: &bad}); fields(t, err)["enroll_hours"] != "invalid" {
			t.Fatalf("%d hours: %v", bad, err)
		}
		if bad != 0 {
			if _, err := f.s.AllowDevice(testActor, peer.ID, bad); fields(t, err)["hours"] != "invalid" {
				t.Fatalf("allow %d hours: %v", bad, err)
			}
		}
	}
	if _, err := f.s.AllowDevice(testActor, peer.ID, 0); err != nil {
		t.Fatal(err)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 200 {
		t.Fatalf("enrollment: %+v", a)
	}
	// another user: the device of alice isn't the one of bob
	bob := f.user("bob")
	changed, err := f.s.UpdatePeer(testActor, peer.ID, PeerInput{Name: peer.Name, Enabled: true, UserID: bob.ID})
	if err != nil || changed.Device.State != DeviceWaiting {
		t.Fatalf("another user: %+v %v", changed, err)
	}
	// without a login there's nothing to bind
	input.AuthMode = store.AuthKey
	if server, err = f.s.UpdateServer(testActor, server.ID, input); err != nil || server.DeviceBinding || server.MachineID {
		t.Fatalf("key only: %+v %v", server, err)
	}
	if _, err := f.s.AllowDevice(testActor, peer.ID, 1); fields(t, err)["device"] != "device_binding_not_required" {
		t.Fatalf("allow without binding: %v", err)
	}
}

// Signed by the Windows key of Authway (a CNG key of the Microsoft Software KSP), for the test configuration of
// its sources: the server checks what the app really sends.
func TestAuthwaySignatures(t *testing.T) {
	const (
		serverKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
		peerKey   = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
		address   = "10.103.1.2"
		device    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYFF2QHTbDPtCGXX8S3bXMy7Ezha/N5SFmxueqLf+FHBBHSh1tAckGWvdd8UBXnuNA9pb61tsO/YwGgZ+AUkEeg=="
		login     = "MEYCIQCpzFaw82G7EqpBo6ux0lKGNYvx7Q3ItylWKZ7rFu2r/wIhAJXewleoej8DWWkgWKhqD4B9FuZXwNigsqOWrhaKRdeD"
		newKey    = "wpUtcntrxjacoXR8oiXXpc9cq/v3BYRyIbmpfvWXBjc="
		keyChange = "MEYCIQCrq7nQ7jhLX3K05jkWThTnq1Z5zipfvt4EwB+/yVZZOAIhAK8j3V7nx1zkD9zYbwukOnkOiuqxs5gaXoHPPn8Mw0q4"
	)
	key, ok := decodeDeviceKey(device)
	if !ok {
		t.Fatal("the key of Authway isn't read")
	}
	signature, ok := decodeSignature(login)
	if !ok || !verifySignature(key, loginMessage("Q2hhbGxlbmdl", serverKey, peerKey, address, "alice", ""), signature) {
		t.Fatal("the login of Authway isn't accepted")
	}
	if verifySignature(key, loginMessage("Q2hhbGxlbmdl", serverKey, peerKey, address, "Alice", ""), signature) {
		t.Fatal("another user name is accepted")
	}
	signature, ok = decodeSignature(keyChange)
	if !ok || !verifySignature(key, keyMessage("Q2hhbGxlbmdlMg==", serverKey, peerKey, address, newKey), signature) {
		t.Fatal("the key of Authway isn't accepted")
	}
	if _, ok := decodeWireGuardKey(newKey); !ok {
		t.Fatal("the WireGuard key of Authway isn't read")
	}
	if verifySignature(key, keyMessage("Q2hhbGxlbmdlMg==", serverKey, peerKey, "10.103.1.3", newKey), signature) {
		t.Fatal("another address is accepted")
	}
	for _, bad := range []string{"", "not base64", device + "\n", strings.Replace(device, "MFkw", "MFkx", 1)} {
		if _, ok := decodeDeviceKey(bad); ok {
			t.Fatalf("%q is read as a device key", bad)
		}
	}
}

func TestChallenges(t *testing.T) {
	c := challenges{}
	now := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	a, b := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.3")
	var issued []string
	for range maxChallenges + 1 {
		issued = append(issued, c.issue(a, now))
	}
	if c.use(a, issued[0], now) {
		t.Fatal("the oldest of five is kept")
	}
	if c.use(b, issued[1], now) {
		t.Fatal("a challenge of another address")
	}
	if !c.use(a, issued[2], now) || c.use(a, issued[2], now) {
		t.Fatal("a challenge works once")
	}
	if !c.use(a, issued[1], now.Add(ChallengeTTL-time.Second)) || c.use(a, issued[3], now.Add(ChallengeTTL)) {
		t.Fatal("a challenge lasts ChallengeTTL")
	}
	c.prune(now.Add(ChallengeTTL))
	if len(c) != 0 {
		t.Fatalf("pruned: %v", c)
	}
}
