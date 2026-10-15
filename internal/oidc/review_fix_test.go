package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

// hs256 signs claims with key, as a forger would with an empty one.
func hs256(kid string, claims map[string]any, key []byte) string {
	in := enc(map[string]any{"alg": "HS256", "kid": kid}) + "." + enc(claims)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func status(rs []check.Result, name string) (check.Status, string) {
	for _, r := range rs {
		if r.Name == name {
			return r.Status, r.Detail
		}
	}
	return "", ""
}

func TestHMACWithoutSecretIsNotTrusted(t *testing.T) {
	now := time.Now()
	claims := map[string]any{"iss": "https://idp.example/", "aud": "client", "sub": "u1", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	j, _ := ParseJWT(hs256("", claims, nil))
	if err := j.Verify(nil, nil); err == nil {
		t.Fatal("Verify accepted an HMAC with an empty key")
	}
	rs := CheckIDToken(j, Expect{Config: Config{ClientID: "client"}, Provider: &Provider{Issuer: "https://idp.example/"}, Now: now, Skew: time.Minute}, "")
	if st, d := status(rs, "Signature"); st != check.Fail {
		t.Errorf("forged ID token signature: %s %s", st, d)
	}
	// With the real secret it still verifies.
	j, _ = ParseJWT(hs256("", claims, []byte("s3cret")))
	rs = CheckIDToken(j, Expect{Config: Config{ClientID: "client", ClientSecret: "s3cret"}, Provider: &Provider{Issuer: "https://idp.example/"}, Now: now, Skew: time.Minute}, "")
	if st, d := status(rs, "Signature"); st != check.Pass {
		t.Errorf("HS256 with the right secret: %s %s", st, d)
	}
}

func TestAccessTokenChecks(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := &JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k1", N: b64(rk.N.Bytes()), E: b64(big.NewInt(int64(rk.E)).Bytes())}}}
	now := time.Now()
	e := ExpectAT{Issuer: "https://idp.example/", ClientID: "client", JWKS: jwks, Now: now, Skew: time.Minute, Scopes: []string{"User.Read"}}

	j, _ := ParseJWT(hs256("k1", map[string]any{"iss": e.Issuer, "exp": now.Add(time.Hour).Unix()}, nil))
	if st, _ := status(CheckAccessToken(j, e), "Access token signature"); st != check.Fail {
		t.Errorf("HS256 access token with a JWKS kid: %s, want fail", st)
	}

	// Expired and issued for days: both reported.
	j, _ = ParseJWT(sign(t, "RS256", "k1", map[string]any{"iss": e.Issuer, "iat": now.Add(-72 * time.Hour).Unix(), "exp": now.Add(-time.Hour).Unix(), "scp": "User.Read Mail.Read"}, rk))
	rs := CheckAccessToken(j, e)
	var lifetimes []string
	for _, r := range rs {
		if r.Name == "Access token lifetime" {
			lifetimes = append(lifetimes, string(r.Status)+" "+r.Detail)
		}
	}
	if len(lifetimes) != 2 || !strings.HasPrefix(lifetimes[0], "fail") {
		t.Errorf("lifetime checks: %v", lifetimes)
	}
	if st, d := status(rs, "Scopes in the token"); st != check.Pass {
		t.Errorf("scp as a string: %s %s", st, d)
	}
}
