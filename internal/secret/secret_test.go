package secret

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	hash, err := HashPassword("Secret,1234")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if !VerifyPassword("Secret,1234", hash) {
		t.Error("the right password fails")
	}
	if VerifyPassword("Secret,12345", hash) || VerifyPassword("", hash) {
		t.Error("a wrong password works")
	}
	other, _ := HashPassword("Secret,1234")
	if other == hash {
		t.Error("two hashes of the same password are equal: no salt")
	}
	for _, broken := range []string{"", "plain", "$argon2id$v=19$m=999999999,t=3,p=2$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", hash[:len(hash)-4]} {
		if VerifyPassword("Secret,1234", broken) {
			t.Errorf("%q verifies", broken)
		}
	}
}

func TestRandom(t *testing.T) {
	if Token(32) == Token(32) {
		t.Error("two tokens are equal")
	}
	password := Password(16)
	if len(password) != 16 || strings.ContainsAny(password, "0O1lIo") {
		t.Errorf("bad password %q", password)
	}
	if Fingerprint("a") == Fingerprint("b") || len(Fingerprint("a")) != 64 {
		t.Error("bad fingerprint")
	}
}
