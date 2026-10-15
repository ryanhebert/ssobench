package webauthn_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/ryanhebert/ssobench/internal/webauthn"
	"github.com/ryanhebert/ssobench/internal/webauthn/webauthntest"
)

const origin, rpID = "https://bench.example:8443", "bench.example"

func TestRegisterAndSignIn(t *testing.T) {
	a := webauthntest.New(rpID)
	ch := []byte("register-challenge-0123456789abc")
	cd, att := a.Create(ch, origin)
	cred, err := webauthn.VerifyRegistration(cd, att, ch, origin, rpID)
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.ID) != string(a.ID) {
		t.Fatal("credential ID")
	}
	login := []byte("login-challenge-0123456789abcdef")
	a.Count = 5
	cd, ad, sig := a.Get(login, origin)
	n, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
	if err != nil || n != 5 {
		t.Fatalf("sign-in: %d %v", n, err)
	}
	cred.SignCount = n

	for _, c := range []struct {
		name string
		run  func() error
		want string
	}{
		{"replayed counter", func() error {
			cd, ad, sig := a.Get(login, origin)
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "counter"},
		{"wrong challenge", func() error {
			cd, ad, sig := a.Get([]byte("other"), origin)
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "challenge"},
		{"wrong origin", func() error {
			cd, ad, sig := a.Get(login, "https://evil.example")
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "origin"},
		{"other site", func() error {
			b := webauthntest.New("evil.example")
			b.Key, b.Count = a.Key, 99
			cd, ad, sig := b.Get(login, origin)
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "another site"},
		{"tampered signature", func() error {
			a.Count++
			cd, ad, sig := a.Get(login, origin)
			sig[len(sig)-1] ^= 1
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "signature"},
		{"no user verification", func() error {
			a.Count++
			a.Flags = 0x01
			defer func() { a.Flags = 0 }()
			cd, ad, sig := a.Get(login, origin)
			_, err := webauthn.VerifyAssertion(cred, cd, ad, sig, login, origin, rpID)
			return err
		}, "verify the person"},
		{"create used as get", func() error {
			cd, att := a.Create(login, origin)
			_, err := webauthn.VerifyAssertion(cred, cd, att, nil, login, origin, rpID)
			return err
		}, "type"},
	} {
		if err := c.run(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error about %q", c.name, err, c.want)
		}
	}
}

func TestEd25519Key(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cose := webauthntest.Encode(map[any]any{int64(1): int64(1), int64(3): int64(-8), int64(-1): int64(6), int64(-2): []byte(pub)})
	a := webauthntest.New(rpID)
	ch := []byte("c")
	cd, ad, _ := a.Get(ch, origin)
	sum := sha256.Sum256(cd)
	sig := ed25519.Sign(priv, append(append([]byte(nil), ad...), sum[:]...))
	if _, err := webauthn.VerifyAssertion(webauthn.Credential{PublicKey: cose}, cd, ad, sig, ch, origin, rpID); err != nil {
		t.Errorf("Ed25519: %v", err)
	}
}

func FuzzVerifyRegistration(f *testing.F) {
	a := webauthntest.New(rpID)
	_, att := a.Create([]byte("c"), origin)
	f.Add(att)
	f.Fuzz(func(t *testing.T, att []byte) {
		cd := []byte(`{"type":"webauthn.create","challenge":"Yw","origin":"` + origin + `"}`)
		webauthn.VerifyRegistration(cd, att, []byte("c"), origin, rpID)
	})
}
