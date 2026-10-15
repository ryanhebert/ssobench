package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// keyPairReloader serves the certificate given with -cert and -key, and
// picks up a renewed one (for example from an ACME client) without a
// restart: at most once a minute it checks whether either file changed.
type keyPairReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	mod     time.Time
	checked time.Time
}

func newKeyPairReloader(certFile, keyFile string) (*keyPairReloader, error) {
	k := &keyPairReloader{certFile: certFile, keyFile: keyFile}
	if err := k.load(); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *keyPairReloader) modTime() time.Time {
	var latest time.Time
	for _, f := range []string{k.certFile, k.keyFile} {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(latest) {
			latest = st.ModTime()
		}
	}
	return latest
}

func (k *keyPairReloader) load() error {
	mod := k.modTime()
	c, err := tls.LoadX509KeyPair(k.certFile, k.keyFile)
	if err != nil {
		return err
	}
	k.cert, k.mod = &c, mod
	return nil
}

func (k *keyPairReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.checked) >= time.Minute {
		k.checked = time.Now()
		if k.modTime().After(k.mod) {
			// A half-written pair fails to load; keep serving the old
			// certificate and try again on a later check.
			if err := k.load(); err != nil {
				log.Printf("warning: keeping the current TLS certificate, the new one did not load: %v", err)
			} else {
				log.Printf("loaded the renewed TLS certificate from %s", k.certFile)
			}
		}
	}
	return k.cert, nil
}
