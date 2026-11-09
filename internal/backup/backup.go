// Package backup seals the configuration of Authway Server in a file that only its passphrase opens.
//
// The file is JSON: a header in clear (the format, its version, the date, how the key is made) and the content,
// encrypted with AES-256-GCM. The key comes from the passphrase through argon2id, and the header is authenticated
// with the content: a header changed, a wrong passphrase or a damaged file all fail the same way.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/phatdo1819/authway-server/internal/secret"
)

const (
	Format = "authway-server-backup"
	// the version of the envelope, how the file is sealed: the version of the content is inside
	envelopeVersion = 1
	kdfName         = "argon2id"
	cipherName      = "aes-256-gcm"
	// the passphrases that people choose
	MinPassphrase = 12
	MaxPassphrase = 1024
	// a larger file isn't a backup: a thousand peers make less than 2 MiB
	MaxSize = 8 << 20
)

var (
	ErrFormat     = errors.New("not a backup of Authway Server")
	ErrNewer      = errors.New("a backup of a newer version of Authway Server")
	ErrPassphrase = errors.New("wrong passphrase, or a damaged file")
)

// the cost of the key: argon2id with 64 MiB and 3 passes, like the passwords; the tests make it cheaper
var params = kdf{Time: 3, Memory: 64 * 1024, Threads: 2}

type kdf struct {
	Name    string `json:"name"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// header is authenticated with the content: the order of its fields is the one of encoding/json, fixed
type header struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	CreatedAt int64  `json:"created_at"`
	KDF       kdf    `json:"kdf"`
	Cipher    string `json:"cipher"`
	Nonce     string `json:"nonce"`
}

type envelope struct {
	header
	Data string `json:"data"`
}

// CheckPassphrase returns what's wrong with a passphrase chosen for a backup: "too_short", "too_long" or "".
func CheckPassphrase(passphrase string) string {
	switch {
	case len([]rune(passphrase)) < MinPassphrase:
		return "too_short"
	case len(passphrase) > MaxPassphrase:
		return "too_long"
	}
	return ""
}

// Seal encrypts the content of a backup with a passphrase.
func Seal(content []byte, passphrase string, at time.Time) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h := header{Format: Format, Version: envelopeVersion, CreatedAt: at.Unix(), KDF: params, Cipher: cipherName}
	h.KDF.Name = kdfName
	h.KDF.Salt = base64.StdEncoding.EncodeToString(salt)
	aead, err := newAEAD(passphrase, salt, h.KDF)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	h.Nonce = base64.StdEncoding.EncodeToString(nonce)
	aad, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, content, aad)
	data, err := json.MarshalIndent(envelope{header: h, Data: base64.StdEncoding.EncodeToString(sealed)}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Open decrypts a backup and returns its content and when it was made. The parameters of the key come from the file:
// they must stay in the range of the ones Seal uses, so a file can't make the server take all its memory.
func Open(data []byte, passphrase string) ([]byte, time.Time, error) {
	if len(data) > MaxSize {
		return nil, time.Time{}, ErrFormat
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil || e.Format != Format {
		return nil, time.Time{}, ErrFormat
	}
	if e.Version > envelopeVersion {
		return nil, time.Time{}, ErrNewer
	}
	k := e.KDF
	if e.Version < 1 || e.Cipher != cipherName || k.Name != kdfName || k.Time < 1 || k.Time > 10 ||
		k.Memory < 8*1024 || k.Memory > 256*1024 || k.Threads < 1 || k.Threads > 16 {
		return nil, time.Time{}, ErrFormat
	}
	salt, err1 := base64.StdEncoding.DecodeString(k.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(e.Nonce)
	sealed, err3 := base64.StdEncoding.DecodeString(e.Data)
	if errors.Join(err1, err2, err3) != nil || len(salt) < 16 || len(salt) > 64 {
		return nil, time.Time{}, ErrFormat
	}
	aead, err := newAEAD(passphrase, salt, k)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, time.Time{}, ErrFormat
	}
	aad, err := json.Marshal(e.header)
	if err != nil {
		return nil, time.Time{}, err
	}
	content, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, time.Time{}, ErrPassphrase
	}
	return content, time.Unix(e.CreatedAt, 0), nil
}

func newAEAD(passphrase string, salt []byte, k kdf) (cipher.AEAD, error) {
	key := secret.DeriveKey(passphrase, salt, k.Time, k.Memory, k.Threads, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
