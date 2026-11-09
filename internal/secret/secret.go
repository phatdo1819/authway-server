// Package secret hashes the passwords and makes the random tokens.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// argon2id with the second set of parameters of RFC 9106, for machines with little memory: 64 MiB for each check
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// at most two checks at once: each one takes 64 MiB
var slots = make(chan struct{}, 2)

var b64 = base64.RawStdEncoding

// HashPassword returns the argon2id hash of a password in the PHC string format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := derive(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

type parsedHash struct {
	salt, key    []byte
	memory, time uint32
	threads      uint8
}

func parseHash(encoded string) (parsedHash, bool) {
	var h parsedHash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return h, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return h, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.time, &h.threads); err != nil {
		return h, false
	}
	// the hashes come from the database or a backup, but a damaged one must not take all the memory
	if h.memory < 1024 || h.memory > 1024*1024 || h.time < 1 || h.time > 16 || h.threads < 1 {
		return h, false
	}
	var err error
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) < 8 {
		return h, false
	}
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) < 16 || len(h.key) > 64 {
		return h, false
	}
	return h, true
}

// VerifyPassword tells whether the password matches the hash made by HashPassword.
func VerifyPassword(password, encoded string) bool {
	h, ok := parseHash(encoded)
	if !ok {
		return false
	}
	other := derive(password, h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(h.key, other) == 1
}

// ValidHash tells whether a hash has the form of the ones of HashPassword, without checking any password: for the
// hashes of a backup.
func ValidHash(encoded string) bool {
	h, ok := parseHash(encoded)
	// a hash of a file must not make every login take more than 256 MiB: the ones of HashPassword take 64
	return ok && h.memory <= 256*1024
}

// DeriveKey makes a key of length bytes from a passphrase with argon2id, in the same slots as the password checks.
func DeriveKey(passphrase string, salt []byte, time, memory uint32, threads uint8, length uint32) []byte {
	return derive(passphrase, salt, time, memory, threads, length)
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// SpendCheck takes the time of a check, for the logins of unknown users: the answer comes as late as for a known one.
func SpendCheck(password string) {
	dummyOnce.Do(func() {
		dummyHash, _ = HashPassword(Token(16))
	})
	VerifyPassword(password, dummyHash)
}

func derive(password string, salt []byte, time, memory uint32, threads uint8, length uint32) []byte {
	slots <- struct{}{}
	defer func() { <-slots }()
	return argon2.IDKey([]byte(password), salt, time, memory, threads, length)
}

// Token returns random bytes in base64url, for cookies and challenges.
func Token(bytes int) string {
	data := make([]byte, bytes)
	if _, err := rand.Read(data); err != nil {
		// the system has no randomness left: nothing safe can go on
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// Fingerprint is the SHA-256 of a token, in hex: the tokens are kept by it, never in clear.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Password returns a random password that is easy to type: letters and digits, without the ones that look alike.
func Password(length int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	// 256 isn't a multiple of the alphabet: skip the bytes past the last full round, so every letter is as likely
	limit := byte(256 - 256%len(alphabet))
	out := make([]byte, 0, length)
	for len(out) < length {
		for _, b := range data {
			if b < limit && len(out) < length {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
		if _, err := rand.Read(data); err != nil {
			panic(err)
		}
	}
	return string(out)
}
