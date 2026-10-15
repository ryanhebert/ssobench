package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

func enc(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(t *testing.T, alg, kid string, claims map[string]any, key crypto.Signer) string {
	t.Helper()
	in := enc(map[string]any{"alg": alg, "kid": kid}) + "." + enc(claims)
	var sig []byte
	var err error
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(in))
	case *ecdsa.PrivateKey:
		h, _ := HashFor(alg)
		hw := h.New()
		hw.Write([]byte(in))
		r, s, e := ecdsa.Sign(rand.Reader, k, hw.Sum(nil))
		err = e
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = append(leftPad(r.Bytes(), size), leftPad(s.Bytes(), size)...)
	case *rsa.PrivateKey:
		h, _ := HashFor(alg)
		hw := h.New()
		hw.Write([]byte(in))
		if strings.HasPrefix(alg, "PS") {
			sig, err = rsa.SignPSS(rand.Reader, k, h, hw.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, h, hw.Sum(nil))
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestVerifyAlgorithms(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	ecdh, _ := ek.PublicKey.ECDH()
	pt := ecdh.Bytes() // 0x04 || X || Y

	jwks := &JWKS{Keys: []JWK{
		{Kty: "RSA", Kid: "r", N: b64(rk.N.Bytes()), E: b64(big.NewInt(int64(rk.E)).Bytes())},
		{Kty: "EC", Kid: "e", Crv: "P-256", X: b64(pt[1:33]), Y: b64(pt[33:])},
		{Kty: "OKP", Kid: "d", Crv: "Ed25519", X: b64(edk.Public().(ed25519.PublicKey))},
	}}
	claims := map[string]any{"sub": "u"}
	cases := []struct {
		alg, kid string
		key      crypto.Signer
	}{
		{"RS256", "r", rk}, {"PS256", "r", rk}, {"ES256", "e", ek}, {"EdDSA", "d", edk},
	}
	for _, c := range cases {
		tok := sign(t, c.alg, c.kid, claims, c.key)
		j, err := ParseJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		k, ok := jwks.Find(j.Kid())
		if !ok {
			t.Fatalf("%s: kid not found", c.alg)
		}
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Verify(pub, nil); err != nil {
			t.Errorf("%s: %v", c.alg, err)
		}
		// Tamper with the payload: the signature must fail.
		parts := strings.Split(tok, ".")
		bad, _ := ParseJWT(parts[0] + "." + enc(map[string]any{"sub": "admin"}) + "." + parts[2])
		if bad.Verify(pub, nil) == nil {
			t.Errorf("%s: tampered token verified", c.alg)
		}
	}
}

func TestCheckIDToken(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := &JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k1", N: b64(rk.N.Bytes()), E: b64(big.NewInt(int64(rk.E)).Bytes())}}}
	now := time.Unix(1_800_000_000, 0)
	at := "access-token-value"
	atHash, _ := HalfHash("RS256", at)
	base := map[string]any{
		"iss": "https://idp.example/", "aud": "client", "sub": "u1", "nonce": "n",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "at_hash": atHash,
	}
	e := Expect{
		Config:   Config{ClientID: "client"},
		Provider: &Provider{Issuer: "https://idp.example/"},
		JWKS:     jwks, Nonce: "n", Now: now, Skew: time.Minute,
	}
	run := func(mut func(m map[string]any), kid string) []check.Result {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		j, err := ParseJWT(sign(t, "RS256", kid, m, rk))
		if err != nil {
			t.Fatal(err)
		}
		return CheckIDToken(j, e, at)
	}
	failed := func(rs []check.Result) []string {
		var out []string
		for _, r := range rs {
			if r.Status == check.Fail {
				out = append(out, r.Name)
			}
		}
		return out
	}

	if f := failed(run(func(map[string]any) {}, "k1")); len(f) != 0 {
		t.Fatalf("good token failed: %v", f)
	}
	tests := map[string]struct {
		mut  func(map[string]any)
		kid  string
		want string
	}{
		"wrong aud":   {func(m map[string]any) { m["aud"] = "other" }, "k1", "Audience (aud)"},
		"expired":     {func(m map[string]any) { m["exp"] = now.Add(-time.Hour).Unix() }, "k1", "Lifetime (nbf/exp)"},
		"bad nonce":   {func(m map[string]any) { m["nonce"] = "x" }, "k1", "Nonce"},
		"wrong iss":   {func(m map[string]any) { m["iss"] = "https://idp.example" }, "k1", "Issuer (iss)"},
		"rotated key": {func(map[string]any) {}, "k2", "Signature"},
		"future iat":  {func(m map[string]any) { m["iat"] = now.Add(10 * time.Minute).Unix() }, "k1", "Issued at (iat)"},
	}
	for name, tc := range tests {
		f := failed(run(tc.mut, tc.kid))
		if len(f) != 1 || f[0] != tc.want {
			t.Errorf("%s: failed checks %v, want [%s]", name, f, tc.want)
		}
	}
}

func TestIssuerTemplate(t *testing.T) {
	if !IssuerMatches("https://login.example/{tenantid}/v2.0", "https://login.example/abc/v2.0", "abc") {
		t.Error("tenant template not expanded")
	}
}

func TestDiscoveryTrailingComma(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"issuer":"x","authorization_endpoint":"a","token_endpoint":"t",}`)
	}))
	defer srv.Close()
	p, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if p.Invalid == "" || p.TokenEndpoint != "t" {
		t.Fatalf("%+v", p)
	}
}
