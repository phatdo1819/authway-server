package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// the SHA-1 vectors of RFC 6238, cut to 6 digits
func TestRFC6238(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range cases {
		got, err := Code(secret, uint64(unix)/Period)
		if err != nil || got != want {
			t.Errorf("time %d: got %q (%v), want %q", unix, got, err, want)
		}
	}
}

func TestVerify(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := Code(secret, uint64(now.Unix())/Period)
	counter, ok := Verify(secret, code, now)
	if !ok || counter != uint64(now.Unix())/Period {
		t.Fatalf("the current code fails: %v %d", ok, counter)
	}
	if _, ok := Verify(secret, code, now.Add(Period*time.Second)); !ok {
		t.Error("the code of the previous period must still work")
	}
	if _, ok := Verify(secret, code, now.Add(3*Period*time.Second)); ok {
		t.Error("an old code works")
	}
	if _, ok := Verify(strings.ToLower(secret), code, now); !ok {
		t.Error("a secret in lower case fails")
	}
	for _, wrong := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(secret, wrong, now); ok {
			t.Errorf("%q is accepted", wrong)
		}
	}
}

func TestURI(t *testing.T) {
	uri := URI("Authway", "alice@example.com", "ABC")
	if !strings.HasPrefix(uri, "otpauth://totp/Authway:alice@example.com?") || !strings.Contains(uri, "secret=ABC") {
		t.Fatal(uri)
	}
}
