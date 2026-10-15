package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWT is a parsed (not yet verified) JSON Web Token.
type JWT struct {
	Raw       string
	Header    map[string]any
	Claims    map[string]any
	HeaderRaw []byte
	ClaimsRaw []byte

	signingInput []byte
	sig          []byte
}

// LooksLikeJWT reports whether s has the three-part compact JWS shape.
func LooksLikeJWT(s string) bool {
	return strings.Count(strings.TrimSpace(s), ".") == 2
}

func ParseJWT(s string) (*JWT, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) == 5 {
		return nil, errors.New("this is an encrypted JWT (JWE); it cannot be read without the decryption key")
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 dot-separated parts, got %d", len(parts))
	}
	j := &JWT{Raw: s, signingInput: []byte(parts[0] + "." + parts[1])}
	var err error
	if j.HeaderRaw, err = b64url(parts[0]); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if j.ClaimsRaw, err = b64url(parts[1]); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if j.sig, err = b64url(parts[2]); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if err := unmarshal(j.HeaderRaw, &j.Header); err != nil {
		return nil, fmt.Errorf("header is not JSON: %w", err)
	}
	if err := unmarshal(j.ClaimsRaw, &j.Claims); err != nil {
		return nil, fmt.Errorf("payload is not JSON: %w", err)
	}
	return j, nil
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// unmarshal keeps numbers as json.Number so large values display exactly.
func unmarshal(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(v)
}

func (j *JWT) Alg() string { s, _ := j.Header["alg"].(string); return s }
func (j *JWT) Kid() string { s, _ := j.Header["kid"].(string); return s }

func (j *JWT) Str(claim string) string { s, _ := j.Claims[claim].(string); return s }

// Time returns a NumericDate claim (seconds since the epoch).
func (j *JWT) Time(claim string) (time.Time, bool) {
	return NumericDate(j.Claims[claim])
}

func NumericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}

// Audiences returns aud, which may be a string or an array.
func (j *JWT) Audiences() []string {
	switch v := j.Claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// JWK is the subset of RFC 7517 needed to verify signatures.
type JWK struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5c []string `json:"x5c"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Find returns the key for kid. With no kid, a single-key set is accepted.
func (s *JWKS) Find(kid string) (JWK, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid && (k.Use == "" || k.Use == "sig") {
			return k, true
		}
	}
	if kid == "" && len(s.Keys) == 1 {
		return s.Keys[0], true
	}
	return JWK{}, false
}

func (s *JWKS) Kids() []string {
	var out []string
	for _, k := range s.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64url(k.N)
		e, err2 := b64url(k.E)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("bad RSA key: %w", err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		x, err1 := b64url(k.X)
		y, err2 := b64url(k.Y)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("bad EC key: %w", err)
		}
		size := (c.Params().BitSize + 7) / 8
		pt := append([]byte{4}, append(leftPad(x, size), leftPad(y, size)...)...)
		return ecdsa.ParseUncompressedPublicKey(c, pt)
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := b64url(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	if len(k.X5c) > 0 {
		der, err := base64.StdEncoding.DecodeString(k.X5c[0])
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	return append(make([]byte, n-len(b)), b...)
}

// HashFor returns the hash used by a JWS algorithm.
func HashFor(alg string) (crypto.Hash, bool) {
	if alg == "EdDSA" {
		return crypto.SHA512, true
	}
	if len(alg) != 5 {
		return 0, false
	}
	switch alg[2:] {
	case "256":
		return crypto.SHA256, true
	case "384":
		return crypto.SHA384, true
	case "512":
		return crypto.SHA512, true
	}
	return 0, false
}

// Verify checks the signature with key (asymmetric algs) or secret (HS*).
func (j *JWT) Verify(key crypto.PublicKey, secret []byte) error {
	alg := j.Alg()
	if alg == "" || alg == "none" {
		return errors.New("token is unsigned (alg=none)")
	}
	if alg == "EdDSA" {
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("alg EdDSA but key is %T", key)
		}
		if !ed25519.Verify(pub, j.signingInput, j.sig) {
			return errors.New("signature does not match")
		}
		return nil
	}
	h, ok := HashFor(alg)
	if !ok {
		return fmt.Errorf("unsupported alg %q", alg)
	}
	hw := h.New()
	hw.Write(j.signingInput)
	digest := hw.Sum(nil)

	var err error
	switch alg[:2] {
	case "HS":
		// An empty key would let anyone forge the token.
		if len(secret) == 0 {
			return errors.New("there is no client secret to check the HMAC against")
		}
		m := hmac.New(h.New, secret)
		m.Write(j.signingInput)
		if !hmac.Equal(m.Sum(nil), j.sig) {
			err = errors.New("HMAC does not match the client secret")
		}
	case "RS", "PS":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s but key is %T", alg, key)
		}
		if alg[0] == 'R' {
			err = rsa.VerifyPKCS1v15(pub, h, digest, j.sig)
		} else {
			err = rsa.VerifyPSS(pub, h, digest, j.sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
	case "ES":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s but key is %T", alg, key)
		}
		n := len(j.sig) / 2
		r, s := new(big.Int).SetBytes(j.sig[:n]), new(big.Int).SetBytes(j.sig[n:])
		if len(j.sig)%2 != 0 || !ecdsa.Verify(pub, digest, r, s) {
			err = errors.New("signature does not match")
		}
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
	return err
}

// HalfHash computes at_hash / c_hash: the left half of the hash of v.
func HalfHash(alg, v string) (string, bool) {
	h, ok := HashFor(alg)
	if !ok {
		return "", false
	}
	hw := h.New()
	hw.Write([]byte(v))
	sum := hw.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), true
}
