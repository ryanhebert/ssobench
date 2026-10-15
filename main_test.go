package main

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSelfSignedCoversBaseURLHost(t *testing.T) {
	c, err := selfSigned("https://sso-test.example.com:9444", "127.0.0.1:9444")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"localhost", "sso-test.example.com", "127.0.0.1"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	c, _ = selfSigned("https://10.1.2.3:9444", "0.0.0.0:9444")
	leaf, _ = x509.ParseCertificate(c.Certificate[0])
	if err := leaf.VerifyHostname("10.1.2.3"); err != nil {
		t.Errorf("ip: %v", err)
	}
}

func TestCertIsReused(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	a, err := loadOrCreateCert(state, "https://sso-test.example.com:9444", "127.0.0.1:9444")
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateCert(state, "https://sso-test.example.com:9444", "127.0.0.1:9444")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Certificate[0], b.Certificate[0]) {
		t.Error("certificate regenerated on restart")
	}
	c, _ := loadOrCreateCert(state, "https://other-name.example.com:9444", "127.0.0.1:9444")
	if bytes.Equal(a.Certificate[0], c.Certificate[0]) {
		t.Error("certificate not renewed for a new host name")
	}
	if fi, _ := os.Stat(strings.TrimSuffix(state, ".json") + "-tls-key.pem"); !ownerOnly(fi) {
		t.Error("TLS key missing or not owner-only")
	}
}

// Every module the binary depends on must have its license in
// THIRD_PARTY_NOTICES.txt, which ships with every release.
func TestThirdPartyNoticesCoverDependencies(t *testing.T) {
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	notices, err := os.ReadFile("THIRD_PARTY_NOTICES.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(mod), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(f) < 2 || !strings.Contains(f[0], ".") || !strings.HasPrefix(f[1], "v") {
			continue
		}
		if !strings.Contains(string(notices), f[0]+" "+f[1]+" (") {
			t.Errorf("THIRD_PARTY_NOTICES.txt lacks %s %s", f[0], f[1])
		}
	}
}

// ownerOnly reports whether a saved file exists and only its owner can
// read it. Windows has no Unix modes: files inherit the folder's access
// list, so only existence is checked there.
func ownerOnly(fi os.FileInfo) bool {
	return fi != nil && (runtime.GOOS == "windows" || fi.Mode().Perm()&0o077 == 0)
}

// A busy default port moves to the next free one; a port someone chose is
// refused with a way out.
func TestListenOnBusyPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	addr := busy.Addr().String()
	_, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)

	ln, got, err := listenOn(addr, true)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	ln.Close()
	_, gp, _ := net.SplitHostPort(got)
	if n, _ := strconv.Atoi(gp); n <= port || n >= port+portTries {
		t.Errorf("fallback chose %s, want a port after %d", got, port)
	}

	if _, _, err := listenOn(addr, false); err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "-port") {
		t.Errorf("chosen busy port: %v", err)
	}
}
