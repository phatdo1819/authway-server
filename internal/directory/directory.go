// Package directory reads Active Directory over LDAP: the members of the group of the VPN users, for the sync, and
// the password of one of them, for a login of the VPN. It never writes to the directory.
package directory

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// How the connection to the domain controllers is encrypted. There's no plain LDAP: the passwords cross it.
const (
	SecurityLDAPS    = "ldaps"    // TLS from the start, port 636 by default
	SecurityStartTLS = "starttls" // LDAP upgraded with StartTLS, port 389 by default
)

// The attributes a username can come from.
const (
	AttributeAccountName = "sAMAccountName"    // alice
	AttributePrincipal   = "userPrincipalName" // alice@example.com
)

const (
	// a group with more members was chosen by mistake
	MaxMembers = 10000
	// to connect to one domain controller, TLS included: one that's switched off or stops answering is passed over
	// after it, for the next one
	DefaultConnectTimeout = 5 * time.Second
	// each request, once connected
	RequestTimeout = 10 * time.Second
	pageSize       = 500
	// the members of a group and of the groups in it, at any depth: LDAP_MATCHING_RULE_IN_CHAIN of Active Directory
	inChain = "1.2.840.113556.1.4.1941"
	// userAccountControl: the account is disabled
	accountDisabled = 0x2
	// accountExpires: never, as 0
	neverExpires = 0x7FFFFFFFFFFFFFFF
)

// Why a password isn't accepted. Any other error means the directory couldn't answer.
var (
	ErrWrongPassword   = errors.New("wrong password")
	ErrLocked          = errors.New("the account is locked out in the directory")
	ErrPasswordExpired = errors.New("the password has expired in the directory")
	ErrDisabled        = errors.New("the account is disabled in the directory")
	ErrNotMember       = errors.New("the account is no longer in the directory group")
)

// Config is how to reach the directory, and which of its users are the users of Authway Server.
type Config struct {
	// the domain controllers, host or host:port, tried in order
	Servers  []string
	Security string
	// the certificates, in PEM, of the certification authorities that signed the ones of the domain controllers;
	// empty for the ones the system trusts
	CACertificates string
	// the account that reads the directory: a DN, or user@domain
	BindUser     string
	BindPassword string
	// where the users are searched
	BaseDN string
	// the DN of the group whose members, in nested groups too, are the users of Authway Server
	Group string
	// AttributeAccountName or AttributePrincipal
	UsernameAttribute string
	// to connect to each domain controller; 0: DefaultConnectTimeout
	Timeout time.Duration
}

// User is an account of the directory.
type User struct {
	// its objectGUID, in hex: it stays when the account is renamed or moved
	ID       string
	Username string
	FullName string
	// disabled, or expired
	Disabled bool
}

// Group is what a sync reads: the members of the group, and what it learned of the directory on the way.
type Group struct {
	// the disabled ones too
	Members []User
	// when the password of the service account expires; zero when it never does, or the directory doesn't tell
	PasswordExpires time.Time
	// the domain controllers tried before the one that answered, and why they didn't
	Unanswered []string
}

// Client reads the directory. LDAP is the real one.
type Client interface {
	// Members reads the members of the group.
	Members(cfg Config) (Group, error)
	// Authenticate checks the password of a member of the group, by its ID. The errors of the package say why a
	// password isn't accepted; any other means the directory couldn't answer.
	Authenticate(cfg Config, id, password string) (User, error)
}

// LDAP is the Client of a real directory: one connection for each call.
type LDAP struct{}

var now = time.Now

// How long a whole call can take, whatever the domain controllers do: a login ends before the 15 seconds the login
// page has to answer, a sync or a test before the minute an answer of the web UI has. Variables for the tests.
var (
	loginDeadline   = 12 * time.Second
	membersDeadline = 50 * time.Second
	requestTimeout  = RequestTimeout
)

func (LDAP) Members(cfg Config) (Group, error) {
	// in order: a sync finds when the first domain controllers answer again
	a := cfg.attempt(membersDeadline, false)
	for {
		conn, address, err := cfg.connect(a)
		if err != nil {
			return Group{}, err
		}
		group, err := cfg.members(conn)
		conn.Close()
		if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			// connected, and then it stopped answering: the next one, while there's time
			a.fail(address, err)
			continue
		}
		if err != nil {
			return Group{}, err
		}
		for _, err := range a.failed {
			group.Unanswered = append(group.Unanswered, err.Error())
		}
		return group, nil
	}
}

func (cfg Config) members(conn *ldap.Conn) (Group, error) {
	if err := conn.Bind(cfg.BindUser, cfg.BindPassword); err != nil {
		return Group{}, serviceError(err)
	}
	filter := "(&(objectCategory=person)(objectClass=user)" + memberOf(cfg.Group) + ")"
	result, err := conn.SearchWithPaging(cfg.search(filter, 0), pageSize)
	if err != nil {
		return Group{}, fmt.Errorf("can't search the directory: %w", err)
	}
	if len(result.Entries) > MaxMembers {
		return Group{}, fmt.Errorf("the group has more than %d members", MaxMembers)
	}
	group := Group{Members: make([]User, 0, len(result.Entries))}
	for _, entry := range result.Entries {
		if user, ok := cfg.userOf(entry); ok {
			group.Members = append(group.Members, user)
		}
	}
	group.PasswordExpires = cfg.passwordExpires(conn)
	return group, nil
}

func (LDAP) Authenticate(cfg Config, id, password string) (User, error) {
	// an empty password is an anonymous bind, which succeeds: never send one
	if password == "" {
		return User{}, ErrWrongPassword
	}
	guid, err := hex.DecodeString(id)
	if err != nil || len(guid) != 16 {
		return User{}, ErrNotMember
	}
	// the domain controllers that answer first: one that's down doesn't make every login wait for it
	conn, address, err := cfg.connect(cfg.attempt(loginDeadline, true))
	if err != nil {
		return User{}, err
	}
	defer conn.Close()
	user, err := cfg.authenticate(conn, guid, password)
	// one that stops answering is passed over at the next login. Not now: the time is short, and a second try of the
	// password could count twice in the lockout of the directory
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		markAnswering(address, false)
	}
	return user, err
}

func (cfg Config) authenticate(conn *ldap.Conn, guid []byte, password string) (User, error) {
	if err := conn.Bind(cfg.BindUser, cfg.BindPassword); err != nil {
		return User{}, serviceError(err)
	}
	filter := "(&(objectCategory=person)(objectClass=user)(objectGUID=" + escapeBytes(guid) + ")" + memberOf(cfg.Group) + ")"
	result, err := conn.Search(cfg.search(filter, 2))
	if err != nil {
		return User{}, fmt.Errorf("can't search the directory: %w", err)
	}
	if len(result.Entries) != 1 {
		return User{}, ErrNotMember
	}
	entry := result.Entries[0]
	user, _ := cfg.userOf(entry)
	if user.Disabled {
		return user, ErrDisabled
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		return user, passwordError(err)
	}
	return user, nil
}

// The domain controllers that didn't answer, by address, since when: a login tries the others first, so that one
// that's down doesn't make every login wait for it. A sync tries them in order, and so finds when they answer again.
var unanswering = struct {
	sync.Mutex
	since map[string]time.Time
}{since: map[string]time.Time{}}

func markAnswering(address string, answers bool) {
	unanswering.Lock()
	defer unanswering.Unlock()
	if answers {
		delete(unanswering.since, address)
	} else if _, ok := unanswering.since[address]; !ok {
		unanswering.since[address] = time.Now()
	}
}

// answeringFirst puts the domain controllers that didn't answer lately after the others, both in their order
func answeringFirst(addresses []string) []string {
	unanswering.Lock()
	defer unanswering.Unlock()
	var first, last []string
	for _, address := range addresses {
		if _, down := unanswering.since[address]; down {
			last = append(last, address)
		} else {
			first = append(first, address)
		}
	}
	return append(first, last...)
}

// attempt is one call's way through the domain controllers: until when, and the ones that didn't answer, and why
type attempt struct {
	deadline        time.Time
	preferAnswering bool
	failed          []error
	tried           map[string]bool
}

func (cfg Config) attempt(limit time.Duration, preferAnswering bool) *attempt {
	return &attempt{deadline: time.Now().Add(limit), preferAnswering: preferAnswering, tried: map[string]bool{}}
}

// fail passes over a domain controller for the rest of the call, and the next ones
func (a *attempt) fail(address string, err error) {
	markAnswering(address, false)
	a.tried[address] = true
	a.failed = append(a.failed, fmt.Errorf("%s: %w", address, networkError(err)))
}

// connect opens a connection to the next domain controller that answers, encrypted and checked, and says which one
// it is. Each one gets the connect timeout; the connection ends at the deadline, and the domain controllers left then
// aren't tried.
func (cfg Config) connect(a *attempt) (*ldap.Conn, string, error) {
	pool, err := CAPool(cfg.CACertificates)
	if err != nil {
		return nil, "", err
	}
	var addresses []string
	hosts := map[string]string{}
	for _, server := range cfg.Servers {
		host, port, ok := ParseServer(server, cfg.Security)
		if !ok {
			if !a.tried[server] {
				a.tried[server] = true
				a.failed = append(a.failed, fmt.Errorf("%s: not a host or host:port", server))
			}
			continue
		}
		address := net.JoinHostPort(host, port)
		if _, twice := hosts[address]; !twice && !a.tried[address] {
			hosts[address] = host
			addresses = append(addresses, address)
		}
	}
	if a.preferAnswering {
		addresses = answeringFirst(addresses)
	}
	for _, address := range addresses {
		left := time.Until(a.deadline)
		if left <= 0 {
			a.tried[address] = true
			a.failed = append(a.failed, fmt.Errorf("%s: not tried, the time is up", address))
			continue
		}
		tlsConfig := &tls.Config{ServerName: hosts[address], RootCAs: pool, MinVersion: tls.VersionTLS12}
		conn, err := cfg.open(address, tlsConfig, min(cfg.connectTimeout(), left), a.deadline)
		if err != nil {
			a.fail(address, err)
			continue
		}
		markAnswering(address, true)
		a.tried[address] = true
		return conn, address, nil
	}
	if len(a.failed) == 0 {
		return nil, "", errors.New("no domain controller is set")
	}
	return nil, "", fmt.Errorf("can't connect to the directory: %w", errors.Join(a.failed...))
}

// open connects to one domain controller and encrypts the connection within timeout; the connection then ends at the
// deadline. The deadlines are on the connection itself: go-ldap has none for the TLS handshake of StartTLS, which a
// domain controller that stops answering would hold forever.
func (cfg Config) open(address string, tlsConfig *tls.Config, timeout time.Duration, deadline time.Time) (*ldap.Conn, error) {
	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	setup := time.Now().Add(timeout)
	if setup.After(deadline) {
		setup = deadline
	}
	if err := raw.SetDeadline(setup); err != nil {
		raw.Close()
		return nil, err
	}
	var conn *ldap.Conn
	if cfg.Security == SecurityLDAPS {
		secure := tls.Client(raw, tlsConfig)
		if err := secure.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		conn = ldap.NewConn(secure, true)
		conn.Start()
	} else {
		conn = ldap.NewConn(raw, false)
		conn.Start()
		conn.SetTimeout(timeout)
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, err
		}
	}
	// encrypted: each request has RequestTimeout, and all of them end at the deadline
	if err := raw.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetTimeout(requestTimeout)
	return conn, nil
}

func (cfg Config) connectTimeout() time.Duration {
	if cfg.Timeout > 0 {
		return cfg.Timeout
	}
	return DefaultConnectTimeout
}

func (cfg Config) search(filter string, sizeLimit int) *ldap.SearchRequest {
	attributes := []string{"objectGUID", cfg.usernameAttribute(), "displayName", "cn", "userAccountControl", "accountExpires"}
	return ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, sizeLimit,
		int(RequestTimeout.Seconds()), false, filter, attributes, nil)
}

func (cfg Config) usernameAttribute() string {
	if cfg.UsernameAttribute == AttributePrincipal {
		return AttributePrincipal
	}
	return AttributeAccountName
}

// userOf reads an account; false without an objectGUID
func (cfg Config) userOf(entry *ldap.Entry) (User, bool) {
	guid := entry.GetRawAttributeValue("objectGUID")
	if len(guid) != 16 {
		return User{}, false
	}
	name := entry.GetAttributeValue("displayName")
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	return User{
		ID:       hex.EncodeToString(guid),
		Username: entry.GetAttributeValue(cfg.usernameAttribute()),
		FullName: name,
		Disabled: disabled(entry.GetAttributeValue("userAccountControl"), entry.GetAttributeValue("accountExpires"), now()),
	}, true
}

// disabled reads userAccountControl and accountExpires: a disabled account, or one past its end
func disabled(control, expires string, at time.Time) bool {
	if flags, err := strconv.ParseUint(control, 10, 32); err == nil && flags&accountDisabled != 0 {
		return true
	}
	end, err := strconv.ParseInt(expires, 10, 64)
	return err == nil && end != 0 && end != neverExpires && fileTime(end).Before(at)
}

// fileTime is a time of Windows: 100 nanoseconds since 1601
func fileTime(value int64) time.Time {
	const since1601 = 11644473600
	return time.Unix(value/10_000_000-since1601, value%10_000_000*100)
}

func memberOf(group string) string {
	return "(memberOf:" + inChain + ":=" + ldap.EscapeFilter(group) + ")"
}

// escapeBytes writes bytes for a filter, each one escaped
func escapeBytes(data []byte) string {
	var b strings.Builder
	for _, value := range data {
		fmt.Fprintf(&b, `\%02x`, value)
	}
	return b.String()
}

// networkError is a connection that failed, without the "LDAP Result Code 200" of go-ldap in front of what happened
func networkError(err error) error {
	var result *ldap.Error
	if errors.As(err, &result) && result.ResultCode == ldap.ErrorNetwork && result.Err != nil {
		return result.Err
	}
	return err
}

// serviceError is a bind of the service account that failed: Active Directory says why, as for the users
func serviceError(err error) error {
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return fmt.Errorf("the service account can't log in: %w", err)
	}
	switch passwordError(err) {
	case ErrPasswordExpired:
		return fmt.Errorf("the service account can't log in: its password has expired or must be changed. Set a new one in Active Directory, then here: %w", err)
	case ErrLocked:
		return fmt.Errorf("the service account can't log in: it's locked out in Active Directory: %w", err)
	case ErrDisabled:
		return fmt.Errorf("the service account can't log in: it's disabled or expired in Active Directory: %w", err)
	}
	return fmt.Errorf("the service account can't log in: check its name and password: %w", err)
}

// msDS-UserPasswordExpiryTimeComputed: when the password of an account expires, computed by Active Directory, and
// Samba, from its domain's policy or its password settings object
const passwordExpiry = "msDS-UserPasswordExpiryTimeComputed"

// passwordExpires reads when the password of the service account expires; zero when it never does, or the directory
// doesn't tell. The account is looked up by the name it logs in with, in the whole domain of the search base: a
// service account is often outside of it.
func (cfg Config) passwordExpires(conn *ldap.Conn) time.Time {
	name := strings.TrimSpace(cfg.BindUser)
	var filters []string
	switch {
	case ValidDN(name):
		return readExpiry(conn, ldap.NewSearchRequest(name, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
			int(RequestTimeout.Seconds()), false, "(objectClass=user)", []string{passwordExpiry}, nil))
	case strings.Contains(name, `\`):
		// DOMAIN\name
		_, account, _ := strings.Cut(name, `\`)
		filters = []string{"(sAMAccountName=" + ldap.EscapeFilter(account) + ")"}
	case strings.Contains(name, "@"):
		// the user principal name, or the logon name at the domain, which Active Directory takes too
		account, _, _ := strings.Cut(name, "@")
		filters = []string{"(userPrincipalName=" + ldap.EscapeFilter(name) + ")", "(sAMAccountName=" + ldap.EscapeFilter(account) + ")"}
	default:
		filters = []string{"(sAMAccountName=" + ldap.EscapeFilter(name) + ")"}
	}
	for _, filter := range filters {
		expires := readExpiry(conn, ldap.NewSearchRequest(domainOf(cfg.BaseDN), ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 2, int(RequestTimeout.Seconds()), false,
			"(&(objectCategory=person)(objectClass=user)"+filter+")", []string{passwordExpiry}, nil))
		if !expires.IsZero() {
			return expires
		}
	}
	return time.Time{}
}

// readExpiry reads the expiry of the password of the only account a search finds
func readExpiry(conn *ldap.Conn, request *ldap.SearchRequest) time.Time {
	result, err := conn.Search(request)
	if err != nil || len(result.Entries) != 1 {
		return time.Time{}
	}
	value, err := strconv.ParseInt(result.Entries[0].GetAttributeValue(passwordExpiry), 10, 64)
	// 0: the password must be changed at the next login, which the bind would have said
	if err != nil || value <= 0 || value == neverExpires {
		return time.Time{}
	}
	return fileTime(value)
}

// domainOf is the domain of a DN, its DC parts at the end: DC=example,DC=com of OU=Staff,DC=example,DC=com. A DN
// without them is its own domain.
func domainOf(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return dn
	}
	var parts []string
	for _, rdn := range parsed.RDNs {
		if len(rdn.Attributes) == 1 && strings.EqualFold(rdn.Attributes[0].Type, "DC") {
			parts = append(parts, "DC="+ldap.EscapeDN(rdn.Attributes[0].Value))
		} else {
			parts = nil
		}
	}
	if len(parts) == 0 {
		return dn
	}
	return strings.Join(parts, ",")
}

// passwordError says why the directory refused the password of a user. Active Directory tells why in the message:
// data 52e is a wrong password, 775 a locked account, 532 and 773 an expired password, 533 and 701 a disabled or
// expired account.
func passwordError(err error) error {
	var result *ldap.Error
	if !errors.As(err, &result) || result.ResultCode != ldap.LDAPResultInvalidCredentials {
		return fmt.Errorf("can't check the password: %w", err)
	}
	text := result.Error()
	switch {
	case strings.Contains(text, "data 775"):
		return ErrLocked
	case strings.Contains(text, "data 532"), strings.Contains(text, "data 773"):
		return ErrPasswordExpired
	case strings.Contains(text, "data 533"), strings.Contains(text, "data 701"):
		return ErrDisabled
	}
	return ErrWrongPassword
}

// ParseServer reads a domain controller, host or host:port, with the default port of the security.
func ParseServer(server, security string) (string, string, bool) {
	server = strings.TrimSpace(server)
	port := "636"
	if security == SecurityStartTLS {
		port = "389"
	}
	host := server
	if h, p, err := net.SplitHostPort(server); err == nil {
		value, err := strconv.Atoi(p)
		if err != nil || value < 1 || value > 65535 {
			return "", "", false
		}
		host, port = h, p
	}
	if host == "" || strings.ContainsAny(host, " /\\[]") {
		return "", "", false
	}
	return host, port, true
}

// ValidDN tells whether a text is a distinguished name: CN=VPN Users,OU=Groups,DC=example,DC=com.
func ValidDN(text string) bool {
	dn, err := ldap.ParseDN(text)
	return err == nil && len(dn.RDNs) > 0
}

// CAPool is the system's certification authorities, with the ones of the PEM text; nil, the system's, without text.
func CAPool(text string) (*x509.CertPool, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	rest := []byte(text)
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a CA certificate can't be read: %w", err)
		}
		pool.AddCert(certificate)
		count++
	}
	if count == 0 {
		return nil, errors.New("no certificate in the CA certificates")
	}
	return pool, nil
}
