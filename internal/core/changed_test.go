package core

import (
	"errors"
	"testing"

	"github.com/phatdo1819/authway-server/internal/store"
)

// changedBy returns the refusal of a form saved over a change made since it opened, and fails without one.
func changedBy(t *testing.T, err error) *ChangedError {
	t.Helper()
	var changed *ChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("not refused as changed: %v", err)
	}
	return changed
}

// Two administrators edit the same thing: the second form, opened before the first was saved, is refused with what
// it is now, instead of undoing the change of the first. Without a version the save goes through, as before.
func TestChangedSince(t *testing.T) {
	f := setup(t)
	alice := Actor{ID: 1, Username: "alice", From: "192.0.2.10"}
	bob := Actor{ID: 2, Username: "bob", From: "192.0.2.11"}

	t.Run("user", func(t *testing.T) {
		user := f.user("carol")
		if user.Version != 1 || user.UpdatedBy != "tester" {
			t.Fatalf("new: %d %q", user.Version, user.UpdatedBy)
		}
		saved, err := f.s.UpdateUser(alice, user.ID, UserInput{Username: "carol", FullName: "Carol A", Version: user.Version})
		if err != nil {
			t.Fatal(err)
		}
		if saved.Version != 2 || saved.UpdatedBy != "alice" {
			t.Fatalf("saved: %d %q", saved.Version, saved.UpdatedBy)
		}
		_, err = f.s.UpdateUser(bob, user.ID, UserInput{Username: "carol", Disabled: true, Version: user.Version})
		changed := changedBy(t, err)
		current, ok := changed.Current.(*UserView)
		if !ok || current.Version != 2 || current.FullName != "Carol A" || current.Disabled || changed.By != "alice" ||
			changed.At != saved.UpdatedAt {
			t.Fatalf("refusal: %+v %+v", changed, changed.Current)
		}
		// nothing saved: the full name of alice stays
		if view := f.userView(user.ID); view.FullName != "Carol A" || view.Disabled || view.Version != 2 {
			t.Fatalf("after the refusal: %+v", view)
		}
		// again with the version of now: saved
		if saved, err = f.s.UpdateUser(bob, user.ID, UserInput{Username: "carol", FullName: "Carol A", Disabled: true,
			Version: current.Version}); err != nil || saved.Version != 3 || saved.UpdatedBy != "bob" {
			t.Fatalf("again: %v %+v", err, saved)
		}
		// an authenticator is a change too
		if _, err := f.s.SetupTOTP(alice, user.ID); err != nil {
			t.Fatal(err)
		}
		_, err = f.s.UpdateUser(bob, user.ID, UserInput{Username: "carol", Version: 3})
		if changed := changedBy(t, err); changed.Current.(*UserView).Version != 4 || !changed.Current.(*UserView).TOTP {
			t.Fatalf("after the authenticator: %+v", changed.Current)
		}
		// no version: no check, and the authenticator stays
		if saved, err = f.s.UpdateUser(bob, user.ID, UserInput{Username: "carol"}); err != nil || !saved.TOTP || saved.Version != 5 {
			t.Fatalf("without a version: %v %+v", err, saved)
		}
	})

	t.Run("peer", func(t *testing.T) {
		office := f.server(store.AuthPassword)
		dave := f.user("dave")
		peer := f.peer(office, dave)
		if peer.Version != 1 {
			t.Fatalf("new: %d", peer.Version)
		}
		input := PeerInput{Name: "dave laptop", Enabled: true, UserID: dave.ID, Version: peer.Version}
		saved, err := f.s.UpdatePeer(alice, peer.ID, PeerInput{Name: "dave pc", Enabled: true, UserID: dave.ID, Version: peer.Version})
		if err != nil || saved.Version != 2 {
			t.Fatalf("saved: %v %+v", err, saved)
		}
		input.RouteAll = true
		_, err = f.s.UpdatePeer(bob, peer.ID, input)
		if changed := changedBy(t, err); changed.Current.(*PeerView).Name != "dave pc" || changed.By != "alice" {
			t.Fatalf("refusal: %+v", changed)
		}
		// new keys change the peer: a form opened before is refused
		renewed, err := f.s.RegeneratePeerKeys(alice, peer.ID)
		if err != nil || renewed.Version != 3 {
			t.Fatalf("new keys: %v %+v", err, renewed)
		}
		input.Version = 2
		if _, err := f.s.UpdatePeer(bob, peer.ID, input); changedBy(t, err).Current.(*PeerView).Version != 3 {
			t.Fatal("not the version of now")
		}
	})

	t.Run("server", func(t *testing.T) {
		server := f.server(store.AuthKey)
		first := inputOf(server)
		first.Version = server.Version
		first.Keepalive = 15
		saved, err := f.s.UpdateServer(alice, server.ID, first)
		if err != nil || saved.Version != server.Version+1 || saved.UpdatedBy != "alice" {
			t.Fatalf("saved: %v %+v", err, saved)
		}
		second := inputOf(server)
		second.Version = server.Version
		second.Name = "Renamed"
		_, err = f.s.UpdateServer(bob, server.ID, second)
		if changed := changedBy(t, err); changed.Current.(*ServerView).Keepalive != 15 || changed.By != "alice" {
			t.Fatalf("refusal: %+v", changed)
		}
		if view, _ := f.s.Server(server.ID); view.Name == "Renamed" || view.Keepalive != 15 {
			t.Fatalf("after the refusal: %+v", view)
		}
	})

	t.Run("administrator", func(t *testing.T) {
		adminID := f.admin()
		admin := Actor{ID: adminID, Username: "admin"}
		created, err := f.s.CreateAdmin(admin, AdminInput{Username: "erin", Role: store.RoleOperator, Password: "Second admin pass 1"})
		if err != nil || created.Version != 1 || created.UpdatedBy != "admin" {
			t.Fatalf("new: %v %+v", err, created)
		}
		saved, err := f.s.UpdateAdmin(admin, created.ID, AdminInput{FullName: "Erin", Role: store.RoleViewer, Version: 1})
		if err != nil || saved.Version != 2 {
			t.Fatalf("saved: %v %+v", err, saved)
		}
		_, err = f.s.UpdateAdmin(admin, created.ID, AdminInput{Role: store.RoleAdmin, Version: 1})
		if changed := changedBy(t, err); changed.Current.(*AdminView).Role != store.RoleViewer {
			t.Fatalf("refusal: %+v", changed.Current)
		}
	})
}

func (f *fixture) userView(id int64) UserView {
	f.t.Helper()
	users, err := f.s.Users()
	if err != nil {
		f.t.Fatal(err)
	}
	for _, user := range users {
		if user.ID == id {
			return user
		}
	}
	f.t.Fatalf("no user %d", id)
	return UserView{}
}
