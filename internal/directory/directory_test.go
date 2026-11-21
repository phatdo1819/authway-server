package directory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// userAccountControl and accountExpires: a disabled account, or one past its end
func TestDisabled(t *testing.T) {
	at := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	// 2026-01-01 and 2027-01-01, in 100 ns since 1601
	past, future := "134116992000000000", "134432352000000000"
	for _, test := range []struct {
		control, expires string
		disabled         bool
	}{
		{"512", "0", false},
		{"514", "0", true},
		{"66048", "9223372036854775807", false},
		{"66050", "9223372036854775807", true},
		{"512", past, true},
		{"512", future, false},
		{"", "", false},
	} {
		if got := disabled(test.control, test.expires, at); got != test.disabled {
			t.Errorf("%s %s: disabled %v, want %v", test.control, test.expires, got, test.disabled)
		}
	}
	if got := fileTime(134432352000000000); !got.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("file time: %s", got)
	}
}

// The values in the filters are escaped: a group or a GUID can't change the filter.
func TestFilters(t *testing.T) {
	if got := memberOf("CN=VPN (all)*,OU=Groups,DC=example,DC=com"); got != `(memberOf:1.2.840.113556.1.4.1941:=CN=VPN \28all\29\2a,OU=Groups,DC=example,DC=com)` {
		t.Errorf("memberOf: %s", got)
	}
	if got := escapeBytes([]byte{0x00, 0x2a, 0xff}); got != `\00\2a\ff` {
		t.Errorf("bytes: %s", got)
	}
}

func TestParseServer(t *testing.T) {
	for _, test := range []struct {
		server, security, host, port string
		ok                           bool
	}{
		{"dc1.example.com", SecurityLDAPS, "dc1.example.com", "636", true},
		{"dc1.example.com", SecurityStartTLS, "dc1.example.com", "389", true},
		{"dc1.example.com:3269", SecurityLDAPS, "dc1.example.com", "3269", true},
		{"192.168.1.10", SecurityLDAPS, "192.168.1.10", "636", true},
		{"[fd00::10]:636", SecurityLDAPS, "fd00::10", "636", true},
		{"fd00::10", SecurityLDAPS, "fd00::10", "636", true},
		{"dc1.example.com:0", SecurityLDAPS, "", "", false},
		{"dc1.example.com:ldaps", SecurityLDAPS, "", "", false},
		{"ldaps://dc1.example.com", SecurityLDAPS, "", "", false},
		{"", SecurityLDAPS, "", "", false},
	} {
		host, port, ok := ParseServer(test.server, test.security)
		if host != test.host || port != test.port || ok != test.ok {
			t.Errorf("%q: %q %q %v", test.server, host, port, ok)
		}
	}
}

func TestValidDN(t *testing.T) {
	for text, valid := range map[string]bool{
		"DC=example,DC=com": true, "CN=VPN Users,OU=Groups,DC=example,DC=com": true,
		"": false, "example.com": false, "CN=a,=b": false, "svc-authway@example.com": false, `EXAMPLE\svc-authway`: false,
	} {
		if ValidDN(text) != valid {
			t.Errorf("%q: valid %v", text, !valid)
		}
	}
}

func TestCAPool(t *testing.T) {
	if pool, err := CAPool("  "); pool != nil || err != nil {
		t.Errorf("no certificates: %v %v", pool, err)
	}
	if _, err := CAPool("not a certificate"); err == nil {
		t.Error("text without a certificate")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if pool, err := CAPool(text); pool == nil || err != nil {
		t.Errorf("a CA certificate: %v %v", pool, err)
	}
	if _, err := CAPool(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))); err == nil {
		t.Error("a damaged certificate")
	}
}

// Active Directory says why it refuses a password in the message of the error.
func TestPasswordError(t *testing.T) {
	refused := func(data string) error {
		return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials,
			Err: errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data " + data + ", v4f7c")}
	}
	for data, want := range map[string]error{
		"52e": ErrWrongPassword, "775": ErrLocked, "532": ErrPasswordExpired, "773": ErrPasswordExpired,
		"533": ErrDisabled, "701": ErrDisabled, "52f": ErrWrongPassword,
	} {
		if got := passwordError(refused(data)); !errors.Is(got, want) {
			t.Errorf("data %s: %v, want %v", data, got, want)
		}
	}
	// anything else: the directory couldn't answer
	other := passwordError(&ldap.Error{ResultCode: ldap.LDAPResultBusy, Err: errors.New("busy")})
	for _, known := range []error{ErrWrongPassword, ErrLocked, ErrPasswordExpired, ErrDisabled, ErrNotMember} {
		if errors.Is(other, known) {
			t.Errorf("a busy server: %v", other)
		}
	}
}

// A domain controller that doesn't answer: the error says where and why, without the result code of go-ldap.
func TestConnectionError(t *testing.T) {
	cfg := Config{Servers: []string{"127.0.0.1:1", "127.0.0.1:2"}, Security: SecurityLDAPS, Timeout: time.Second}
	_, err := LDAP{}.Members(cfg)
	if err == nil || strings.Contains(err.Error(), "Result Code") || !strings.Contains(err.Error(), "127.0.0.1:1: ") ||
		!strings.Contains(err.Error(), "127.0.0.1:2: ") || !strings.HasPrefix(err.Error(), "can't connect to the directory: ") {
		t.Errorf("error: %v", err)
	}
}

// stallingServer is a domain controller that accepts connections and then stops answering. With startTLS it first
// answers the StartTLS request, then never completes the TLS handshake.
func stallingServer(t *testing.T, startTLS bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				if startTLS {
					request := make([]byte, 512)
					n, _ := conn.Read(request)
					id := byte(1)
					if n > 4 {
						id = request[4]
					}
					// an ExtendedResponse with the same message ID: success
					conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
				}
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// within runs fn, and fails when it takes longer than limit
func within(t *testing.T, name string, limit time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if took := time.Since(start); took > limit {
			t.Errorf("%s took %s, more than %s", name, took, limit)
		}
		return err
	case <-time.After(limit + 5*time.Second):
		t.Fatalf("%s still waits after %s", name, limit+5*time.Second)
		return nil
	}
}

// A domain controller that stops answering, at any step, holds a login or a sync no longer than the connect timeout:
// then the next one is tried. go-ldap has no timeout for the TLS handshake of StartTLS.
func TestStallingServers(t *testing.T) {
	for _, test := range []struct {
		name, security string
		startTLS       bool
	}{
		{"LDAPS, no TLS handshake", SecurityLDAPS, false},
		{"StartTLS, no answer", SecurityStartTLS, false},
		{"StartTLS answered, no TLS handshake", SecurityStartTLS, true},
	} {
		first, address := stallingServer(t, test.startTLS), stallingServer(t, test.startTLS)
		cfg := Config{Servers: []string{first, address}, Security: test.security, Timeout: 300 * time.Millisecond}
		err := within(t, test.name, 2*time.Second, func() error {
			_, err := LDAP{}.Authenticate(cfg, "00112233445566778899aabbccddeeff", "secret")
			return err
		})
		// both tried, one line each
		if lines := strings.Split(fmt.Sprint(err), "\n"); err == nil || len(lines) != 2 || !strings.HasPrefix(lines[1], address+": ") {
			t.Errorf("%s: %v", test.name, err)
		}
		if err := within(t, test.name+", members", 2*time.Second, func() error { _, err := LDAP{}.Members(cfg); return err }); err == nil {
			t.Errorf("%s: members without an answer", test.name)
		}
	}
}

// However many domain controllers stop answering, a login ends by its deadline, before the login page has to answer.
func TestLoginDeadline(t *testing.T) {
	before := loginDeadline
	loginDeadline = time.Second
	defer func() { loginDeadline = before }()
	var servers []string
	for range 4 {
		servers = append(servers, stallingServer(t, false))
	}
	cfg := Config{Servers: servers, Security: SecurityLDAPS, Timeout: 600 * time.Millisecond}
	err := within(t, "four stalled domain controllers", 2*time.Second, func() error {
		_, err := LDAP{}.Authenticate(cfg, "00112233445566778899aabbccddeeff", "secret")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "not tried") {
		t.Errorf("error: %v", err)
	}
}

// An empty password is an anonymous bind, which LDAP accepts: it's refused before anything is sent. So is an ID that
// isn't a GUID.
func TestAuthenticateRefusesAtOnce(t *testing.T) {
	cfg := Config{Servers: []string{"192.0.2.1"}, Security: SecurityLDAPS, Timeout: time.Millisecond}
	if _, err := (LDAP{}).Authenticate(cfg, "00112233445566778899aabbccddeeff", ""); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("empty password: %v", err)
	}
	if _, err := (LDAP{}).Authenticate(cfg, "not-a-guid", "secret"); !errors.Is(err, ErrNotMember) {
		t.Errorf("bad ID: %v", err)
	}
}

// fakeController is a domain controller with TLS that refuses every bind, as for a wrong password of the service
// account; with hang, it never answers a request instead. It returns its address, and its certificate to trust.
func fakeController(t *testing.T, hang bool) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dc"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				request := make([]byte, 1024)
				for {
					n, err := conn.Read(request)
					if err != nil {
						return
					}
					if hang {
						continue
					}
					id := byte(1)
					if n > 4 && request[1] < 0x80 {
						id = request[4]
					}
					// a BindResponse with the same message ID: invalidCredentials
					conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, id, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00})
				}
			}()
		}
	}()
	return listener.Addr().String(), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A login tries first the domain controllers that answered lately: one that's down makes only the first login wait.
// A sync tries them in order, to find when the first ones answer again.
func TestAnsweringFirst(t *testing.T) {
	down := stallingServer(t, false)
	up, certificate := fakeController(t, false)
	cfg := Config{Servers: []string{down, up}, Security: SecurityLDAPS, CACertificates: certificate,
		BindUser: "svc", BindPassword: "pw", Timeout: 300 * time.Millisecond}
	timed := func(call func() error) (time.Duration, error) {
		start := time.Now()
		err := call()
		return time.Since(start), err
	}
	login := func() error {
		_, err := LDAP{}.Authenticate(cfg, "00112233445566778899aabbccddeeff", "secret")
		return err
	}
	// the service account is refused: the one that answers was reached
	reached := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "check its name and password")
	}
	if took, err := timed(login); !reached(err) || took < 300*time.Millisecond {
		t.Errorf("first login, after the one that's down: %s %v", took, err)
	}
	if took, err := timed(login); !reached(err) || took >= 300*time.Millisecond {
		t.Errorf("second login, straight to the one that answers: %s %v", took, err)
	}
	if took, err := timed(func() error { _, err := LDAP{}.Members(cfg); return err }); !reached(err) || took < 300*time.Millisecond {
		t.Errorf("sync, in order: %s %v", took, err)
	}

	// it answers again: back in its place
	a, b := "192.0.2.10:636", "192.0.2.11:636"
	markAnswering(a, false)
	if got := answeringFirst([]string{a, b}); got[0] != b || got[1] != a {
		t.Errorf("one down: %v", got)
	}
	markAnswering(a, true)
	if got := answeringFirst([]string{a, b}); got[0] != a || got[1] != b {
		t.Errorf("answering again: %v", got)
	}
}

// A domain controller that's connected, and then stops answering a request, is passed over by a sync for the next
// one, and by the next login.
func TestMembersPassesStalledServer(t *testing.T) {
	before := requestTimeout
	requestTimeout = 300 * time.Millisecond
	defer func() { requestTimeout = before }()
	hung, first := fakeController(t, true)
	up, second := fakeController(t, false)
	cfg := Config{Servers: []string{hung, up}, Security: SecurityLDAPS, CACertificates: first + second,
		BindUser: "svc", BindPassword: "pw", Timeout: time.Second}
	err := within(t, "sync", 2*time.Second, func() error { _, err := LDAP{}.Members(cfg); return err })
	if err == nil || !strings.Contains(err.Error(), "check its name and password") {
		t.Errorf("sync: %v", err)
	}
	err = within(t, "login", 250*time.Millisecond, func() error {
		_, err := LDAP{}.Authenticate(cfg, "00112233445566778899aabbccddeeff", "secret")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "check its name and password") {
		t.Errorf("login: %v", err)
	}
}

// Why the service account can't log in, as Active Directory says it.
func TestServiceError(t *testing.T) {
	refused := func(data string) error {
		return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials,
			Err: errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data " + data + ", v4f7c")}
	}
	for data, want := range map[string]string{
		"52e": "check its name and password", "532": "its password has expired", "773": "must be changed",
		"775": "locked out", "533": "disabled", "701": "disabled or expired",
	} {
		if got := serviceError(refused(data)).Error(); !strings.HasPrefix(got, "the service account can't log in: ") || !strings.Contains(got, want) {
			t.Errorf("data %s: %s", data, got)
		}
	}
	if got := serviceError(&ldap.Error{ResultCode: ldap.LDAPResultBusy, Err: errors.New("busy")}).Error(); strings.Contains(got, "password") {
		t.Errorf("busy: %s", got)
	}
}

// The domain of a search base, where the service account is looked for.
func TestDomainOf(t *testing.T) {
	for dn, want := range map[string]string{
		"DC=example,DC=com":                  "DC=example,DC=com",
		"OU=Staff,DC=example,DC=com":         "DC=example,DC=com",
		"ou=Staff,dc=corp,dc=example,dc=com": "DC=corp,DC=example,DC=com",
		"OU=Staff,O=Example":                 "OU=Staff,O=Example",
		"DC=old,OU=Staff,DC=example,DC=com":  "DC=example,DC=com",
	} {
		if got := domainOf(dn); got != want {
			t.Errorf("%s: %s, want %s", dn, got, want)
		}
	}
}
