package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, dir, host string, mod time.Time) []byte {
	t.Helper()
	c, err := selfSigned("https://"+host, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for f, b := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(p, mod, mod)
	}
	return c.Certificate[0]
}

func TestKeyPairReloadsRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	old := writePair(t, dir, "old.example", time.Now().Add(-time.Hour))
	k, err := newKeyPairReloader(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := k.get(nil); !bytes.Equal(c.Certificate[0], old) {
		t.Fatal("first certificate not served")
	}
	renewed := writePair(t, dir, "new.example", time.Now())
	if c, _ := k.get(nil); !bytes.Equal(c.Certificate[0], old) {
		t.Fatal("reloaded before the check interval")
	}
	k.checked = time.Time{}
	if c, _ := k.get(nil); !bytes.Equal(c.Certificate[0], renewed) {
		t.Fatal("renewed certificate not picked up")
	}

	// A broken file keeps the current certificate.
	os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("garbage"), 0o600)
	k.checked = time.Time{}
	if c, _ := k.get(nil); !bytes.Equal(c.Certificate[0], renewed) {
		t.Fatal("a broken renewal replaced the working certificate")
	}
}
