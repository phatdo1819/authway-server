package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a certificate of a name, valid until notAfter, signed by itself
func writePair(t *testing.T, dir, name string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: notAfter.AddDate(-1, 0, 0), NotAfter: notAfter, DNSNames: []string{name},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

// serving is the certificate a handshake gets now
func serving(t *testing.T, c *certificates) *x509.Certificate {
	t.Helper()
	pair, err := c.get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A self-signed certificate is made the first time, and made again 30 days before its end; a pair of your own is
// loaded without a restart, never replaced, and one that doesn't load leaves the one before in use.
func TestCertificates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	clock := &testClock{now: time.Now()}
	certs, created, err := loadCertificates(dir, []string{"vpn.example.com", "10.0.0.5"}, nil, clock.Now)
	if err != nil || !created {
		t.Fatalf("first start: %v %v", created, err)
	}
	first := serving(t, certs)
	info := certs.info()
	if !info.SelfSigned || first.NotAfter.Before(clock.now.AddDate(1, 11, 0)) || len(info.Names) != 4 || info.Error != "" {
		t.Fatalf("self-signed: %+v", info)
	}
	// a restart keeps it
	again, created, err := loadCertificates(dir, nil, nil, clock.Now)
	if err != nil || created || serving(t, again).SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("second start: %v %v", created, err)
	}

	// near its end: a new one, at the next reading of the files
	clock.now = first.NotAfter.Add(-20 * 24 * time.Hour)
	renewed := serving(t, certs)
	if renewed.SerialNumber.Cmp(first.SerialNumber) == 0 || renewed.NotAfter.Before(clock.now.AddDate(1, 11, 0)) {
		t.Fatalf("not renewed: until %v", renewed.NotAfter)
	}
	// the files have it too, for the next start
	if reloaded, created, _ := loadCertificates(dir, nil, nil, clock.Now); created || serving(t, reloaded).SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Error("the new certificate isn't in the files")
	}

	// a pair of your own: loaded within certCheckEvery, without a restart
	writePair(t, dir, "vpn.example.com", clock.now.AddDate(0, 0, 20))
	if serving(t, certs).SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Error("read again before certCheckEvery")
	}
	clock.now = clock.now.Add(certCheckEvery)
	own := serving(t, certs)
	if own.Subject.CommonName != "vpn.example.com" {
		t.Fatalf("own certificate not loaded: %s", own.Subject.CommonName)
	}
	// near its end too, but never replaced
	clock.now = clock.now.Add(certCheckEvery)
	if serving(t, certs).SerialNumber.Cmp(own.SerialNumber) != 0 {
		t.Error("own certificate replaced")
	}
	if info := certs.info(); info.SelfSigned || info.Names[0] != "vpn.example.com" || info.Error != "" {
		t.Errorf("own: %+v", info)
	}

	// a broken file: the one before stays, and the error is said
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not a certificate"), 0o644)
	clock.now = clock.now.Add(certCheckEvery)
	if serving(t, certs).SerialNumber.Cmp(own.SerialNumber) != 0 || certs.info().Error == "" {
		t.Errorf("broken file: %+v", certs.info())
	}
	// both deleted: a new self-signed one
	os.Remove(filepath.Join(dir, "cert.pem"))
	os.Remove(filepath.Join(dir, "key.pem"))
	clock.now = clock.now.Add(certCheckEvery)
	if leaf := serving(t, certs); !selfSigned(leaf) || certs.info().Error != "" {
		t.Errorf("after the files were deleted: %s %+v", leaf.Subject.CommonName, certs.info())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("files left: %v", entries)
	}
}
