// Command ssobench is a local SAML service provider and OpenID Connect relying
// party for testing identity providers. Sign in, then see what the provider
// sent and what is wrong with it.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ryanhebert/ssobench/internal/decode"
	"github.com/ryanhebert/ssobench/internal/web"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `SSOBench tests SAML and OpenID Connect sign-ins against your identity provider.

Usage:
  ssobench [flags]            start the web UI (default http://localhost:8080)
  ssobench decode [input]     decode a JWT or SAML message (file, value, or - for stdin)
  ssobench version            print the version

Flags:
`

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "decode":
			os.Exit(runDecode(args[1:]))
		case "version", "--version", "-version":
			fmt.Println("ssobench", version)
			return
		case "help", "-h", "--help":
		default:
			if !strings.HasPrefix(args[0], "-") {
				fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
				args = []string{"-h"}
			}
		}
	}
	if err := serve(args); err != nil {
		log.Fatal("ssobench: ", err)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("ssobench", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), usage); fs.PrintDefaults() }
	port := fs.Int("port", 8080, "port to listen on")
	listen := fs.String("listen", "", "address to listen on (default 127.0.0.1:<port>)")
	baseURL := fs.String("base-url", "", "public URL of this tool, if it differs from the listen address\n(for example behind a reverse proxy)")
	useTLS := fs.Bool("tls", false, "serve HTTPS with a generated self-signed certificate")
	certFile := fs.String("cert", "", "TLS certificate file (PEM); implies HTTPS. A renewed certificate\nis picked up within a minute, without a restart")
	keyFile := fs.String("key", "", "TLS private key file (PEM)")
	skew := fs.Duration("skew", 2*time.Minute, "allowed clock skew when checking token lifetimes")
	noOpen := fs.Bool("no-open", false, "do not open a browser on start")
	var allowHosts []string
	fs.Func("allow-host", "another host name SSOBench answers to, such as a DNS alias (repeatable).\nIP addresses, localhost and this machine's names are always accepted", func(v string) error {
		allowHosts = append(allowHosts, strings.ToLower(strings.TrimSuffix(v, ".")))
		return nil
	})
	statePath := fs.String("state", "", "file that keeps your apps across restarts (default: ssobench/state.json in the\nuser config folder; \"off\" keeps nothing). Client secrets are written only for apps that opt in.")
	passFile := fs.String("admin-password-file", "", "file holding a password for the console, besides any set under Settings.\nThe SSOBENCH_ADMIN_PASSWORD environment variable works too")
	resetAccess := fs.Bool("reset-console-sign-in", false, "remove the console password and passkeys saved under Settings, for an\nadmin who is locked out")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		os.Exit(2)
	}

	addr := *listen
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", *port)
	}
	https := *useTLS || *certFile != ""
	// The URL to open (and print). Unless -base-url pins it, the URLs SSOBench
	// hands to the IdP follow whatever address the browser used.
	host, p, _ := net.SplitHostPort(addr)
	if host == "" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	openURL := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, p))
	if *baseURL != "" {
		openURL = strings.TrimRight(*baseURL, "/")
	}

	srv, err := web.New(*baseURL, *skew, version)
	if err != nil {
		return err
	}
	srv.StatePath = resolveStatePath(*statePath)
	srv.AdminPassword = os.Getenv("SSOBENCH_ADMIN_PASSWORD")
	if *passFile != "" {
		b, err := os.ReadFile(*passFile)
		if err != nil {
			return fmt.Errorf("console password: %w", err)
		}
		srv.AdminPassword = strings.TrimRight(string(b), "\r\n")
		if srv.AdminPassword == "" {
			return fmt.Errorf("console password: %s is empty", *passFile)
		}
	}
	// Host names to answer to: protects against DNS rebinding.
	names, _ := certNames(*baseURL, addr)
	srv.AllowedHosts = append(append(names, allowHosts...), "localhost")
	if err := srv.LoadState(); err != nil {
		log.Printf("warning: ignoring saved state: %v", err)
	}
	if *resetAccess {
		if srv.ResetConsoleAccess() {
			log.Printf("Removed the console password and passkeys: the console no longer asks for sign-in.")
		} else {
			log.Printf("No console password or passkeys were saved; nothing to reset.")
		}
	}
	if err := srv.LoadHistory(); err != nil {
		log.Printf("warning: ignoring saved history: %v", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}

	if https {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if *certFile != "" {
			kp, err := newKeyPairReloader(*certFile, *keyFile)
			if err != nil {
				return err
			}
			cfg.GetCertificate = kp.get
		} else {
			c, err := loadOrCreateCert(srv.StatePath, *baseURL, addr)
			if err != nil {
				return err
			}
			cfg.Certificates = []tls.Certificate{c}
		}
		ln = tls.NewListener(ln, cfg)
	}

	if !loopback(addr) && !srv.Protected() {
		log.Printf("warning: listening on %s, reachable from other machines, with no console sign-in. Anyone who can reach it can change your apps and read the tokens it shows; add a password or passkey under Settings.", addr)
	}
	log.Printf("SSOBench %s running at %s (press Ctrl+C to stop)", version, openURL)
	if *baseURL == "" {
		log.Printf("URLs given to the IdP follow the address in the browser; use -base-url to pin them")
	}
	if !*noOpen {
		openBrowser(openURL)
	}
	// Stop cleanly on Ctrl+C or a service stop, saving what is in memory
	// only (activity from SCIM reads).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Printf("stopping")
	shctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hs.Shutdown(shctx)
	srv.Flush()
	return nil
}

func runDecode(args []string) int {
	var in []byte
	var err error
	switch {
	case len(args) == 0 || args[0] == "-":
		in, err = io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
	default:
		if b, ferr := os.ReadFile(args[0]); ferr == nil {
			in = b
		} else {
			in = []byte(strings.Join(args, " "))
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ssobench:", err)
		return 1
	}
	res, err := decode.Auto(string(in), time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "ssobench:", err)
		return 1
	}
	for i, p := range res.Parts {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("== %s ==\n%s\n", p.Title, strings.TrimRight(p.Body, "\n"))
	}
	return 0
}

// selfSigned makes a self-signed certificate (loadOrCreateCert saves it
// beside the state file). It covers every name and address this machine is likely to be reached by
// (localhost, the hostname and its DNS names, each interface address, and
// the -base-url host), so the only browser warning is the self-signed issuer.
func selfSigned(baseURL, listenAddr string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "SSOBench localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	names, ips := certNames(baseURL, listenAddr)
	tmpl.DNSNames = append(tmpl.DNSNames, names...)
	tmpl.IPAddresses = append(tmpl.IPAddresses, ips...)
	if len(names) > 0 {
		tmpl.Subject.CommonName = "SSOBench " + names[0]
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return
		}
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}

// certNames lists the extra DNS names and IPs for the self-signed certificate.
func certNames(baseURL, listenAddr string) ([]string, []net.IP) {
	var names []string
	var ips []net.IP
	addName := func(n string) {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if n != "" && n != "localhost" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	addIP := func(ip net.IP) {
		if ip != nil && !ip.IsLoopback() && !slices.ContainsFunc(ips, ip.Equal) {
			ips = append(ips, ip)
		}
	}
	if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			addIP(ip)
		} else {
			addName(u.Hostname())
		}
	}
	if h, _, err := net.SplitHostPort(listenAddr); err == nil {
		if ip := net.ParseIP(h); ip != nil && !ip.IsUnspecified() {
			addIP(ip)
		}
	}
	if h, err := os.Hostname(); err == nil {
		addName(h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				addIP(ipn.IP)
			}
		}
	}
	// Reverse lookups give the DNS names (dc1.example.local and so on); keep
	// them quick so a slow resolver does not delay start-up.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, ip := range ips {
		if found, err := net.DefaultResolver.LookupAddr(ctx, ip.String()); err == nil {
			for _, n := range found {
				addName(n)
			}
		}
	}
	return names, ips
}

// resolveStatePath applies the -state default: a file in the user config
// folder, created on first save. "off" disables saving.
func resolveStatePath(flagValue string) string {
	switch flagValue {
	case "off", "none":
		return ""
	case "":
		dir, err := os.UserConfigDir()
		if err != nil {
			log.Printf("warning: no user config folder (%v); apps will not be saved", err)
			return ""
		}
		dir = filepath.Join(dir, "ssobench")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("warning: %v; apps will not be saved", err)
			return ""
		}
		return filepath.Join(dir, "state.json")
	}
	return flagValue
}

// loadOrCreateCert reuses the self-signed certificate saved beside the state
// file, so browsers accept it once instead of after every restart. A new one
// is made when there is none, it is about to expire, or it no longer covers
// this machine's names and addresses.
func loadOrCreateCert(statePath, baseURL, listenAddr string) (tls.Certificate, error) {
	if statePath == "" {
		return selfSigned(baseURL, listenAddr)
	}
	base := strings.TrimSuffix(statePath, filepath.Ext(statePath))
	certPath, keyPath := base+"-tls-cert.pem", base+"-tls-key.pem"
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil && time.Until(leaf.NotAfter) > 7*24*time.Hour && coversNames(leaf, baseURL, listenAddr) {
			return c, nil
		}
	}
	c, err := selfSigned(baseURL, listenAddr)
	if err != nil {
		return c, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err == nil {
		err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600)
	}
	if err == nil {
		err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600)
	}
	if err != nil {
		log.Printf("warning: could not save the TLS certificate: %v", err)
	}
	return c, nil
}

// coversNames reports whether leaf names everything a new certificate would.
func coversNames(leaf *x509.Certificate, baseURL, listenAddr string) bool {
	names, ips := certNames(baseURL, listenAddr)
	for _, n := range names {
		if !slices.Contains(leaf.DNSNames, n) {
			return false
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
			return false
		}
	}
	return true
}

// loopback reports whether addr only accepts connections from this machine.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
