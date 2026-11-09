package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/phatdo1819/authway-server/internal/system"
)

// selfSignedName is the name of the certificates that Authway Server makes: only those are made again
const selfSignedName = "Authway Server"

// the files are read at most this often during the handshakes, and at least every minute
const certCheckEvery = 30 * time.Second

// certificates is the certificate of the web UI, cert.pem and key.pem in dir. Replace both with a certificate of your
// own to remove the warning of the browsers: they're read again when they change, within a minute and without a
// restart, and a pair that doesn't load leaves the one before in use. The self-signed certificate that Authway
// Server makes when there is none, or when they're deleted, is made again 30 days before it expires; a certificate
// of your own is never replaced.
type certificates struct {
	dir   string
	hosts []string
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	pair    *tls.Certificate
	leaf    *x509.Certificate
	stamp   [32]byte
	checked time.Time
	err     string
}

// loadCertificates loads the pair of dir, or makes a self-signed one there; created tells the latter.
func loadCertificates(dir string, hosts []string, log *slog.Logger, now func() time.Time) (*certificates, bool, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if now == nil {
		now = time.Now
	}
	c := &certificates{dir: dir, hosts: hosts, log: log, now: now}
	c.mu.Lock()
	defer c.mu.Unlock()
	created, err := c.loadLocked()
	if err != nil {
		return nil, false, err
	}
	if c.renewLocked() {
		created = true
	}
	c.checked = c.now()
	return c, created, nil
}

func (c *certificates) paths() (string, string) {
	return filepath.Join(c.dir, "cert.pem"), filepath.Join(c.dir, "key.pem")
}

// loadLocked reads the pair, and makes a self-signed one when both files are missing
func (c *certificates) loadLocked() (bool, error) {
	certPath, keyPath := c.paths()
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	created := false
	switch {
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		var err error
		if certPEM, keyPEM, err = c.makeLocked(); err != nil {
			return false, err
		}
		created = true
	case certErr != nil:
		return false, certErr
	case keyErr != nil:
		return false, keyErr
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Errorf("%s: %w", c.dir, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("%s: %w", c.dir, err)
	}
	c.pair, c.leaf = &pair, leaf
	c.stamp = stampOf(certPEM, keyPEM)
	c.err = ""
	return created, nil
}

func stampOf(certPEM, keyPEM []byte) [32]byte {
	return sha256.Sum256(append(append([]byte{}, certPEM...), keyPEM...))
}

// selfSigned tells a certificate that Authway Server made
func selfSigned(leaf *x509.Certificate) bool {
	return leaf.Subject.CommonName == selfSignedName && bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
}

// renewLocked makes the self-signed certificate again when it's near its end
func (c *certificates) renewLocked() bool {
	if !selfSigned(c.leaf) || c.leaf.NotAfter.Sub(c.now()) > system.RenewBefore {
		return false
	}
	ends := c.leaf.NotAfter
	certPEM, keyPEM, err := c.makeLocked()
	if err == nil {
		var pair tls.Certificate
		if pair, err = tls.X509KeyPair(certPEM, keyPEM); err == nil {
			var leaf *x509.Certificate
			if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err == nil {
				c.pair, c.leaf = &pair, leaf
				c.stamp = stampOf(certPEM, keyPEM)
			}
		}
	}
	if err != nil {
		c.err = "can't make a new self-signed certificate: " + err.Error()
		c.log.Error("can't make a new self-signed certificate for the web UI", "ends", ends, "error", err)
		return false
	}
	c.err = ""
	c.log.Info("new self-signed certificate for the web UI: the browsers warn about it once more", "until", c.leaf.NotAfter)
	return true
}

// refreshLocked reads the files again when they changed, and renews the self-signed certificate
func (c *certificates) refreshLocked() {
	c.checked = c.now()
	certPath, keyPath := c.paths()
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	missing := errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist)
	switch {
	case missing || certErr == nil && keyErr == nil && stampOf(certPEM, keyPEM) != c.stamp:
		before := c.leaf
		if _, err := c.loadLocked(); err != nil {
			if c.err != err.Error() {
				c.log.Error("can't load the new certificate of the web UI, the one before stays", "error", err)
			}
			c.err = err.Error()
			return
		}
		if !bytes.Equal(before.Raw, c.leaf.Raw) {
			c.log.Info("certificate of the web UI loaded", "subject", c.leaf.Subject.CommonName, "until", c.leaf.NotAfter)
		}
	case certErr != nil || keyErr != nil:
		err := errors.Join(certErr, keyErr)
		if c.err != err.Error() {
			c.log.Error("can't read the certificate of the web UI, the one before stays", "error", err)
		}
		c.err = err.Error()
		return
	}
	c.renewLocked()
}

// get is GetCertificate of the TLS configuration
func (c *certificates) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now().Sub(c.checked) >= certCheckEvery {
		c.refreshLocked()
	}
	return c.pair, nil
}

// Run reads the files every minute: a renewal and a new pair don't wait for a handshake
func (c *certificates) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			c.refreshLocked()
			c.mu.Unlock()
		}
	}
}

// info is the certificate for the System page
func (c *certificates) info() *system.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := append([]string{}, c.leaf.DNSNames...)
	for _, ip := range c.leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && c.leaf.Subject.CommonName != "" {
		names = append(names, c.leaf.Subject.CommonName)
	}
	return &system.Certificate{NotAfter: c.leaf.NotAfter, SelfSigned: selfSigned(c.leaf), Names: names, Error: c.err}
}

// makeLocked writes a new self-signed certificate, valid 2 years, for localhost, the hosts and 127.0.0.1
func (c *certificates) makeLocked() ([]byte, []byte, error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := c.now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: selfSignedName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	for _, host := range append([]string{"localhost"}, c.hosts...) {
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	if !seen["127.0.0.1"] {
		template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1))
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath := c.paths()
	// each file whole or not at all: a reader never gets half of one
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}
