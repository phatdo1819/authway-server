package backup

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func init() {
	// cheaper keys for the tests: Open takes any cost in the range
	params = kdf{Time: 1, Memory: 8 * 1024, Threads: 1}
}

func TestSealOpen(t *testing.T) {
	at := time.Date(2026, 11, 7, 9, 30, 0, 0, time.UTC)
	content := []byte(`{"servers":[{"private_key":"secret"}]}`)
	sealed, err := Seal(content, "correct horse battery", at)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private_key")) {
		t.Fatal("the content is in clear")
	}
	opened, when, err := Open(sealed, "correct horse battery")
	if err != nil || !bytes.Equal(opened, content) || !when.Equal(at) {
		t.Fatalf("open: %q %v %v", opened, when, err)
	}
	if _, _, err := Open(sealed, "correct horse batterY"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}

	edit := func(change func(map[string]any)) []byte {
		var e map[string]any
		if err := json.Unmarshal(sealed, &e); err != nil {
			t.Fatal(err)
		}
		change(e)
		data, _ := json.Marshal(e)
		return data
	}
	for _, test := range []struct {
		name   string
		data   []byte
		expect error
	}{
		// the header is authenticated with the content
		{"date changed", edit(func(e map[string]any) { e["created_at"] = 1 }), ErrPassphrase},
		{"content changed", edit(func(e map[string]any) { e["data"] = "AAAA" + e["data"].(string)[4:] }), ErrPassphrase},
		{"newer", edit(func(e map[string]any) { e["version"] = 2 }), ErrNewer},
		{"4 GiB key", edit(func(e map[string]any) { e["kdf"].(map[string]any)["memory"] = 4 << 20 }), ErrFormat},
		{"another cipher", edit(func(e map[string]any) { e["cipher"] = "none" }), ErrFormat},
		{"short nonce", edit(func(e map[string]any) { e["nonce"] = "AAAA" }), ErrFormat},
		{"another format", edit(func(e map[string]any) { e["format"] = "other" }), ErrFormat},
		{"not JSON", []byte("PK\x03\x04"), ErrFormat},
		{"too large", make([]byte, MaxSize+1), ErrFormat},
	} {
		if _, _, err := Open(test.data, "correct horse battery"); !errors.Is(err, test.expect) {
			t.Fatalf("%s: %v", test.name, err)
		}
	}

	again, _ := Seal(content, "correct horse battery", at)
	if bytes.Equal(again, sealed) {
		t.Fatal("two backups of the same content are the same: the salt or the nonce don't change")
	}
}

func TestCheckPassphrase(t *testing.T) {
	for passphrase, expect := range map[string]string{
		"":                         "too_short",
		"eleven char":              "too_short",
		"twelve chars":             "",
		"çàé ünïcödé ok":           "",
		string(make([]byte, 1025)): "too_long",
	} {
		if got := CheckPassphrase(passphrase); got != expect {
			t.Fatalf("%q: %q", passphrase, got)
		}
	}
}
