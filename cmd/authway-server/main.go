// Authway Server: WireGuard servers whose peers log in with a password and an authenticator code before their
// traffic passes. It speaks the login protocol of Authway, the client for Windows and macOS.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	// run calls its network net
	stdnet "net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/phatdo1819/authway-server/internal/admin"
	"github.com/phatdo1819/authway-server/internal/core"
	"github.com/phatdo1819/authway-server/internal/hostroute"
	"github.com/phatdo1819/authway-server/internal/network"
	"github.com/phatdo1819/authway-server/internal/portal"
	"github.com/phatdo1819/authway-server/internal/secret"
	"github.com/phatdo1819/authway-server/internal/store"
	"github.com/phatdo1819/authway-server/internal/system"
)

// version is the one of this source; a build can add to it, -ldflags "-X main.version=0.1.0+abc1234"
var version = "0.1.0"

type config struct {
	data          string
	adminListen   string
	adminTLS      bool
	adminUser     string
	adminPassword string
	loginPort     int
	redirectPort  int
	dnsPort       int
	publicHost    string
	logLevel      string
	fakeNetwork   bool
	devPeer       string
	hostRoutes    string
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value, err := strconv.ParseBool(env(name, strconv.FormatBool(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(env(name, strconv.Itoa(fallback)))
	if err != nil {
		return fallback
	}
	return value
}

func parseConfig(args []string) (config, bool, error) {
	var c config
	flags := flag.NewFlagSet("authway-server", flag.ContinueOnError)
	flags.StringVar(&c.data, "data", env("AUTHWAY_DATA", "/data"), "the folder of the database and of the certificate (AUTHWAY_DATA)")
	flags.StringVar(&c.adminListen, "admin-listen", env("AUTHWAY_ADMIN_LISTEN", ":8443"), "the address of the web UI (AUTHWAY_ADMIN_LISTEN)")
	flags.BoolVar(&c.adminTLS, "admin-tls", envBool("AUTHWAY_ADMIN_TLS", true), "serve the web UI with HTTPS; turn it off only behind a reverse proxy with HTTPS (AUTHWAY_ADMIN_TLS)")
	flags.StringVar(&c.adminUser, "admin-username", env("AUTHWAY_ADMIN_USERNAME", "admin"), "the name of the first administrator (AUTHWAY_ADMIN_USERNAME)")
	flags.IntVar(&c.loginPort, "login-port", envInt("AUTHWAY_LOGIN_PORT", 8181), "the port of the login page on the address of each server (AUTHWAY_LOGIN_PORT)")
	flags.IntVar(&c.redirectPort, "redirect-port", envInt("AUTHWAY_REDIRECT_PORT", 8180), "where the web requests of the peers not logged in are redirected (AUTHWAY_REDIRECT_PORT)")
	flags.IntVar(&c.dnsPort, "dns-port", envInt("AUTHWAY_DNS_PORT", 8153), "where the DNS queries of the peers not logged in are redirected (AUTHWAY_DNS_PORT)")
	flags.StringVar(&c.publicHost, "public-host", env("AUTHWAY_PUBLIC_HOST", ""), "the public name or IP of this server, the default for new WireGuard servers (AUTHWAY_PUBLIC_HOST)")
	flags.StringVar(&c.logLevel, "log-level", env("AUTHWAY_LOG_LEVEL", "info"), "debug, info, warn or error (AUTHWAY_LOG_LEVEL)")
	flags.StringVar(&c.hostRoutes, "host-routes", env("AUTHWAY_HOST_ROUTES", ""), "the folder shared with the helper of compose.host-routes.yaml, which routes the tunnels of the routed servers through the Docker host (AUTHWAY_HOST_ROUTES)")
	flags.BoolVar(&c.fakeNetwork, "fake-network", false, "change nothing on the system, to try the web pages on a computer without WireGuard")
	flags.StringVar(&c.devPeer, "dev-peer", "", "with -fake-network: the requests to the login page from this computer count as coming from this peer address")
	showVersion := flags.Bool("version", false, "print the version")
	if err := flags.Parse(args); err != nil {
		return c, false, err
	}
	if *showVersion {
		fmt.Println("authway-server", version)
		return c, true, nil
	}
	// the password of the first administrator is read once: the commands started later (ip, nft) don't get it
	c.adminPassword = os.Getenv("AUTHWAY_ADMIN_PASSWORD")
	os.Unsetenv("AUTHWAY_ADMIN_PASSWORD")
	ports := map[int]bool{}
	for _, port := range []int{c.loginPort, c.redirectPort, c.dnsPort} {
		if port < 1 || port > 65535 {
			return c, false, errors.New("the ports must be between 1 and 65535")
		}
		ports[port] = true
	}
	if len(ports) != 3 {
		return c, false, errors.New("the login, redirect and DNS ports must differ")
	}
	if c.devPeer != "" && !c.fakeNetwork {
		return c, false, errors.New("-dev-peer works only with -fake-network")
	}
	return c, false, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "reset-admin-password" || os.Args[1] == "reset-admin-mfa") {
		os.Exit(resetAdmin(os.Args[1], os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if len(os.Args) > 1 && os.Args[1] == "host-routes" {
		os.Exit(hostRoutes(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

// hostRoutes is the helper of compose.host-routes.yaml, on the network of the Docker host: while Authway Server asks
// for them, the routes of the tunnels of its routed servers through the container, and the way through the rules of
// Docker for the connections started from the networks. Stopped, it takes them away.
//
//	authway-server host-routes [-dir folder] [-health]
func hostRoutes(args []string) int {
	flags := flag.NewFlagSet("host-routes", flag.ContinueOnError)
	dir := flags.String("dir", env("AUTHWAY_HOST_ROUTES", "/host-routes"), "the folder shared with Authway Server (AUTHWAY_HOST_ROUTES)")
	health := flags.Bool("health", false, "only tell whether the helper works, for the health check of its container")
	logLevel := flags.String("log-level", env("AUTHWAY_LOG_LEVEL", "info"), "debug, info, warn or error (AUTHWAY_LOG_LEVEL)")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return 2
	}
	if *health {
		if err := hostroute.Health(*dir, time.Now()); err != nil {
			fmt.Println("unhealthy:", err)
			return 1
		}
		fmt.Println("ok")
		return 0
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	log.Info("starting the helper of the Docker host", "version", version)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Error("can't create the shared folder", "path", *dir, "error", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hostroute.NewHelper(*dir, hostroute.System{}, log).Run(ctx)
	return 0
}

// healthcheck asks /healthz of the web UI of this container, for the HEALTHCHECK of the image: 0 when healthy.
//
//	docker exec authway-server authway-server healthcheck
func healthcheck() int {
	host, port, err := stdnet.SplitHostPort(env("AUTHWAY_ADMIN_LISTEN", ":8443"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "AUTHWAY_ADMIN_LISTEN:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "https"
	if !envBool("AUTHWAY_ADMIN_TLS", true) {
		scheme = "http"
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		// its own certificate, from this host: there's nothing to check, and a certificate of your own has no name
		// for 127.0.0.1
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	response, err := client.Get(scheme + "://" + stdnet.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Println("unhealthy:", err)
		return 1
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	fmt.Println(strings.TrimSpace(string(body)))
	if response.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// newLogger writes to the standard output, the log of the container, and keeps the latest lines for the System page
func newLogger(level string, ring *system.LogRing) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(ring.Handler(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l})))
}

func run(args []string) int {
	c, done, err := parseConfig(args)
	if done {
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ring := system.NewLogRing()
	log := newLogger(c.logLevel, ring)
	log.Info("starting", "version", version)
	if err := os.MkdirAll(c.data, 0o700); err != nil {
		log.Error("can't create the data folder", "path", c.data, "error", err)
		return 1
	}
	// the database holds the keys of the tunnels and the password hashes: only root on the host reads them. Docker
	// creates the folder of a bind mount readable by all
	if err := os.Chmod(c.data, 0o700); err != nil {
		log.Warn("can't make the data folder private", "path", c.data, "error", err)
	}
	var certs *certificates
	if c.adminTLS {
		hostname, _ := os.Hostname()
		var created bool
		if certs, created, err = loadCertificates(filepath.Join(c.data, "tls"), []string{c.publicHost, hostname}, log, nil); err != nil {
			log.Error("can't load the certificate of the web UI", "error", err)
			return 1
		}
		if created {
			log.Info("self-signed certificate made for the web UI: replace tls/cert.pem and tls/key.pem in the data folder with your own, no restart needed")
		}
	}
	systemOptions := system.Options{DataDir: c.data, Version: version, Log: ring, Now: time.Now}
	if certs != nil {
		systemOptions.Certificate = certs.info
	}
	// from the start: the uptime of Authway Server and the first lines of its log
	monitor := system.New(systemOptions)
	db, err := store.Open(filepath.Join(c.data, "authway.db"))
	if err != nil {
		log.Error("can't open the database", "error", err)
		return 1
	}
	defer db.Close()

	var net network.Network
	if c.fakeNetwork {
		log.Warn("fake network: nothing changes on this system, no tunnel works")
		net = network.NewFake()
	} else if net, err = network.NewSystem(log); err != nil {
		log.Error("can't manage the network", "error", err)
		return 1
	}
	defer net.Close()

	if c.hostRoutes != "" {
		if err := os.MkdirAll(c.hostRoutes, 0o700); err != nil {
			log.Error("can't create the folder shared with the helper of the Docker host", "path", c.hostRoutes, "error", err)
			return 1
		}
	}
	service, err := core.New(db, net, core.Options{
		LoginPort: c.loginPort, RedirectPort: c.redirectPort, DNSPort: c.dnsPort, PublicHost: c.publicHost,
		Version: version, Log: log, System: monitor, HostRoutes: c.hostRoutes,
	})
	if err != nil {
		log.Error("can't start", "error", err)
		return 1
	}
	password, err := service.EnsureAdmin(c.adminUser, c.adminPassword)
	if err != nil {
		log.Error("can't create the first administrator", "error", err)
		return 1
	}
	switch {
	case password != "" && c.adminPassword == "":
		fmt.Printf("\n  First administrator of the web UI: %s\n  Password: %s\n  The web UI asks for a new one at the first login.\n\n", c.adminUser, password)
	case password != "":
		log.Info("first administrator created with the password of AUTHWAY_ADMIN_PASSWORD", "user", c.adminUser)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go service.Run(ctx)
	go monitor.Run(ctx)

	var devPeer netip.Addr
	if c.devPeer != "" {
		if devPeer, err = netip.ParseAddr(c.devPeer); err != nil {
			log.Error("invalid -dev-peer", "error", err)
			return 2
		}
		// it looks connected, from this computer
		if fake, ok := net.(*network.Fake); ok {
			fake.SetLive(devPeer)
		}
	}
	// nftables lets only the peers reach these; without it, on the fake network, only this computer
	host := ""
	if c.fakeNetwork {
		host = "127.0.0.1"
	}
	loginAddress := host + ":" + strconv.Itoa(c.loginPort)
	redirectAddress := host + ":" + strconv.Itoa(c.redirectPort)
	dnsAddress := host + ":" + strconv.Itoa(c.dnsPort)
	pages := portal.New(service, portal.Options{Log: log, DevPeer: devPeer})
	loginServer := &http.Server{
		Addr:              loginAddress,
		Handler:           pages.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	redirectServer := &http.Server{
		Addr:              redirectAddress,
		Handler:           pages.RedirectHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	adminServer := &http.Server{
		Addr:              c.adminListen,
		Handler:           admin.New(service, admin.Options{Log: log, Secure: c.adminTLS}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if certs != nil {
		// the certificate of now at each handshake: a new pair in the data folder needs no restart
		adminServer.TLSConfig = &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}
		go certs.Run(ctx)
	}

	errs := make(chan error, 4)
	go func() {
		log.Info("login page listening", "address", loginAddress)
		errs <- fmt.Errorf("login page: %w", loginServer.ListenAndServe())
	}()
	go func() {
		errs <- fmt.Errorf("redirect: %w", redirectServer.ListenAndServe())
	}()
	go func() {
		if err := pages.ServeDNS(ctx, dnsAddress); err != nil {
			errs <- fmt.Errorf("DNS answers: %w", err)
		}
	}()
	go func() {
		scheme := "http"
		if c.adminTLS {
			scheme = "https"
		}
		log.Info("web UI listening", "address", scheme+"://"+displayAddress(c.adminListen))
		if c.adminTLS {
			errs <- fmt.Errorf("web UI: %w", adminServer.ListenAndServeTLS("", ""))
		} else {
			errs <- fmt.Errorf("web UI: %w", adminServer.ListenAndServe())
		}
	}()

	code := 0
	select {
	case <-ctx.Done():
		log.Info("stopping")
	case err := <-errs:
		log.Error("server stopped", "error", err)
		code = 1
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stop()
	loginServer.Shutdown(shutdown)
	redirectServer.Shutdown(shutdown)
	adminServer.Shutdown(shutdown)
	return code
}

func displayAddress(address string) string {
	if strings.HasPrefix(address, ":") {
		return "<this host>" + address
	}
	return address
}

// resetAdmin helps an administrator locked out, from the Docker host:
//
//	docker exec <container> authway-server reset-admin-password [username]
//	docker exec <container> authway-server reset-admin-mfa [username]
//
// The first gives a new password, printed once and changed at the next login; the second removes the
// authenticator. Without a username: the first administrator with the role Administrator.
func resetAdmin(command string, args []string) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	data := flags.String("data", env("AUTHWAY_DATA", "/data"), "the folder of the database (AUTHWAY_DATA)")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "usage: authway-server %s [-data folder] [username]\n", command)
	}
	if err := flags.Parse(args); err != nil || flags.NArg() > 1 {
		return 2
	}
	db, err := store.Open(filepath.Join(*data, "authway.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't open the database:", err)
		return 1
	}
	defer db.Close()
	admins, err := db.Q().Admins()
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't read the administrators:", err)
		return 1
	}
	var target *store.Admin
	for index := range admins {
		admin := &admins[index]
		if flags.NArg() == 1 {
			if strings.EqualFold(admin.Username, flags.Arg(0)) {
				target = admin
				break
			}
		} else if admin.Role == store.RoleAdmin && (target == nil || target.Disabled && !admin.Disabled) {
			target = admin
		}
	}
	if target == nil {
		fmt.Fprintln(os.Stderr, "no such administrator: start the server once to create the first one")
		return 1
	}
	now := time.Now().Unix()
	if command == "reset-admin-mfa" {
		if err := db.Q().SetAdminTOTP(target.ID, "", now); err != nil {
			fmt.Fprintln(os.Stderr, "can't remove the authenticator:", err)
			return 1
		}
		db.Q().AddEvent(&store.Event{At: now, Kind: "admin_mfa_removed", Username: target.Username, Detail: "from the command line"})
		fmt.Printf("The authenticator of %s is removed: the next login asks only for the password.\n", target.Username)
		return 0
	}
	password := secret.Password(16)
	hash, err := secret.HashPassword(password)
	if err == nil {
		err = db.Q().SetAdminPassword(target.ID, hash, true, now)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "can't change the password:", err)
		return 1
	}
	db.Q().AddEvent(&store.Event{At: now, Kind: "admin_password_reset", Username: target.Username, Detail: "from the command line"})
	fmt.Printf("New password of %s: %s\nThe web UI asks for a new one at the next login, and the open sessions can do nothing else.\n", target.Username, password)
	return 0
}
