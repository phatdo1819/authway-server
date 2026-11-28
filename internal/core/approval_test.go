package core

import (
	"slices"
	"strings"
	"testing"

	"github.com/phatdo1819/authway-server/internal/store"
)

// Device approval: the server gives its choice to its new peers, each peer keeps its own. A new device of a peer that
// needs it logs in with the right password, then waits: no session, no other device in its place, until an
// administrator approves it (it logs in from then on) or rejects it (the next device waits in its place). A peer
// that no longer needs it enrolls the device that waits at its next login.
func TestDeviceApproval(t *testing.T) {
	f := setup(t)
	server := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.DeviceBinding = true
		input.DeviceApproval = true
	})
	if !server.DeviceApproval {
		t.Fatalf("server %+v", server)
	}
	// without binding, no approval
	other := f.serverWith(store.AuthPassword, func(input *ServerInput) {
		input.Name, input.ListenPort, input.Network = "other", 51821, "10.9.0.0/24"
		input.DeviceApproval = true
	})
	if other.DeviceApproval {
		t.Fatalf("approval without binding: %+v", other)
	}

	// a new peer takes the server's choice, unless the form says otherwise
	alice, bob := f.user("alice"), f.user("bob")
	peer := f.peer(server, alice)
	if !peer.DeviceApproval {
		t.Fatalf("peer %+v", peer)
	}
	off := false
	bobPeer, err := f.s.CreatePeer(testActor, server.ID, PeerInput{Name: "bob", Enabled: true, UserID: bob.ID, DeviceApproval: &off})
	if err != nil || bobPeer.DeviceApproval {
		t.Fatalf("bob: %+v %v", bobPeer, err)
	}
	if e := f.lastEvent("peer_added"); strings.Contains(e.Detail, "approval") {
		t.Errorf("event of a peer without approval: %+v", e)
	}

	// the first device logs in with the right password: it waits
	laptop, thief := newDevice(t), newDevice(t)
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.5", ""); a.Status != 403 || a.Body["error"] != "device_pending" {
		t.Fatalf("first login: %+v", a)
	}
	if f.session(peer.ID) != nil {
		t.Fatal("a session for a device that waits")
	}
	view := f.peerView(peer.ID)
	if view.Device.State != DevicePending || view.Device.Name != "LAPTOP-42" || view.Device.LastFrom != "203.0.113.5" ||
		view.Device.KeyID != laptop.id() {
		t.Fatalf("device %+v", view.Device)
	}
	if kinds := f.eventKinds("device_"); !slices.Contains(kinds, "device_waiting: LAPTOP-42") {
		t.Errorf("events: %v", kinds)
	}
	// the status tells the app it waits, and whether it's this device
	id, otherID := laptop.id(), thief.id()
	if status := f.deviceStatus(peer, &id); status["pending"] != true || status["enrolled"] != false ||
		status["enrollment_open"] != false || status["this_device"] != true {
		t.Fatalf("status: %+v", status)
	}
	if status := f.deviceStatus(peer, &otherID); status["this_device"] != false {
		t.Fatalf("status of another device: %+v", status)
	}
	// again: still waiting, and nothing counts as a failure
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.6", ""); a.Status != 403 || a.Body["error"] != "device_pending" {
		t.Fatalf("again: %+v", a)
	}
	if f.peerView(peer.ID).Device.LastFrom != "203.0.113.6" {
		t.Error("the latest try isn't recorded")
	}
	// another device, even with the password: refused, an alert
	if a := f.deviceLogin(server, peer, thief, "198.51.100.9", ""); a.Status != 401 || a.Body["error"] != "device_mismatch" {
		t.Fatalf("another device: %+v", a)
	}
	if f.peerView(peer.ID).Device.KeyID != laptop.id() {
		t.Fatal("another device took the place")
	}

	// approved: only the device the page showed
	if _, err := f.s.ApproveDevice(testActor, peer.ID, thief.id()); fields(t, err)["device"] != "not_waiting" {
		t.Fatalf("approve another device: %v", err)
	}
	if _, err := f.s.ApproveDevice(testActor, bobPeer.ID, laptop.id()); fields(t, err)["device"] != "not_waiting" {
		t.Fatalf("approve a peer without a device that waits: %v", err)
	}
	view, err = f.s.ApproveDevice(testActor, peer.ID, laptop.id())
	if err != nil || view.Device.State != DeviceEnrolled || view.Device.EnrolledAt != f.clock.now.Unix() {
		t.Fatalf("approved: %+v %v", view, err)
	}
	if e := f.lastEvent("device_approved"); e.Detail != "LAPTOP-42" || e.By != testActor.Username {
		t.Errorf("event: %+v", e)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.6", ""); a.Status != 200 {
		t.Fatalf("login once approved: %+v", a)
	}
	if _, err := f.s.ApproveDevice(testActor, peer.ID, laptop.id()); fields(t, err)["device"] != "not_waiting" {
		t.Fatalf("approved twice: %v", err)
	}

	// a new device after Replace waits too; rejected, the next one waits in its place
	if _, err := f.s.AllowDevice(testActor, peer.ID, 0); err != nil {
		t.Fatal(err)
	}
	if a := f.deviceLogin(server, peer, thief, "198.51.100.9", ""); a.Body["error"] != "device_pending" {
		t.Fatalf("after Replace: %+v", a)
	}
	view, err = f.s.RejectDevice(testActor, peer.ID, thief.id())
	if err != nil || view.Device.State != DeviceWaiting {
		t.Fatalf("rejected: %+v %v", view, err)
	}
	if e := f.lastEvent("device_rejected"); e.Detail != "LAPTOP-42" {
		t.Errorf("event: %+v", e)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.6", ""); a.Body["error"] != "device_pending" ||
		f.peerView(peer.ID).Device.KeyID != laptop.id() {
		t.Fatalf("after the rejection: %+v", a)
	}

	// the approval turned off for the peer: the device that waits is enrolled at its next login
	update := PeerInput{Name: peer.Name, Enabled: true, UserID: alice.ID, DeviceApproval: &off, Version: f.peerView(peer.ID).Version}
	if _, err := f.s.UpdatePeer(testActor, peer.ID, update); err != nil {
		t.Fatal(err)
	}
	if e := f.lastEvent("peer_changed"); !strings.Contains(e.Detail, "approval of new devices off") {
		t.Errorf("event: %+v", e)
	}
	if a := f.deviceLogin(server, peer, laptop, "203.0.113.6", ""); a.Status != 200 || f.peerView(peer.ID).Device.State != DeviceEnrolled {
		t.Fatalf("without approval: %+v", a)
	}
	// and a peer without approval enrolls its first device at once, as before
	if a := f.deviceLogin(server, bobPeer, newDevice(t), "203.0.113.8", ""); a.Status != 200 {
		t.Fatalf("bob: %+v", a)
	}

	// the backups keep the choices, and the device that waits
	carol := f.peer(server, f.user("carol"))
	if a := f.deviceLogin(server, carol, newDevice(t), "203.0.113.9", ""); a.Body["error"] != "device_pending" {
		t.Fatalf("carol: %+v", a)
	}
	adminID := f.admin()
	backup := f.sealed(adminID, func(c *backupContent) {
		if c.Version != BackupVersion || !c.Servers[0].DeviceApproval || !c.Peers[slices.IndexFunc(c.Peers, func(p backupPeer) bool { return p.ID == carol.ID })].DeviceApproval {
			t.Errorf("backup: %+v", c)
		}
		found := false
		for _, d := range c.Devices {
			if d.PeerID == carol.ID {
				found = d.Pending && d.Key != ""
			}
		}
		if !found {
			t.Errorf("the device that waits isn't in the backup: %+v", c.Devices)
		}
	})
	if _, err := f.s.Restore(Actor{ID: adminID}, "Admin password 1", backup, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if view := f.peerView(carol.ID); !view.DeviceApproval || view.Device.State != DevicePending {
		t.Fatalf("after the restore: %+v", view.Device)
	}
}
