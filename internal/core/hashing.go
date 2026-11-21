package core

import "github.com/phatdo1819/authway-server/internal/secret"

// The hashes that aren't logins of the VPN take turns at one of the two slots of the hashing (secret.Shared): the
// passwords that the changes of the web UI ask for, the users and administrators given a password, the keys of the
// backups. However many an administrator sends at once, the other slot stays for the logins of the VPN.
//
// Never with mu held: a login of the web UI has the turn while it waits for mu. For the same reason AdminLogin, which
// runs in the turn of its caller, and the hashes made under mu (EnsureAdmin, a row of an import added late) use the
// slots directly.

// verifyShared is secret.VerifyPassword in the turn of the hashes of the web UI.
func verifyShared(password, hash string) bool {
	valid := false
	secret.Shared(nil, func() { valid = secret.VerifyPassword(password, hash) })
	return valid
}

// hashShared is secret.HashPassword in the turn of the hashes of the web UI.
func hashShared(password string) (string, error) {
	var hash string
	var err error
	secret.Shared(nil, func() { hash, err = secret.HashPassword(password) })
	return hash, err
}
