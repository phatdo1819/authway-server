// Package totp makes and checks the codes of the authenticator apps (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Digits = 6
	Period = 30
	// the codes of the previous and of the next period count too: the clock of a phone can be a little off
	Skew = 1
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns 160 random bits in base32, the length RFC 4226 recommends.
func NewSecret() string {
	data := make([]byte, 20)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return encoding.EncodeToString(data)
}

func decode(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	return encoding.DecodeString(clean)
}

// ValidSecret tells whether a secret can make codes: base32, 80 bits at least (RFC 4226 asks 128, the apps take 80).
func ValidSecret(secret string) bool {
	key, err := decode(secret)
	return err == nil && len(key) >= 10 && len(key) <= 64
}

// Code returns the code of a period.
func Code(secret string, counter uint64) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha1.New, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, value%1_000_000), nil
}

// Verify checks a code at the time `now` and returns its period: a code must work only once, see the caller.
func Verify(secret, code string, now time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	current := uint64(now.Unix()) / Period
	for delta := -Skew; delta <= Skew; delta++ {
		counter := current + uint64(int64(delta))
		expected, err := Code(secret, counter)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

// URI is the content of the QR code that the authenticator apps scan.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprint(Digits))
	query.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + label + "?" + query.Encode()
}
