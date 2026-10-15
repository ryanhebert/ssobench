// Package webauthn verifies passkey registrations and sign-ins (WebAuthn
// Level 2, relying party side) with the standard library. Attestation is not
// verified: SSOBench accepts any authenticator its admin chooses to add.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// COSE algorithms SSOBench accepts, in order of preference.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

var Algorithms = []int{AlgES256, AlgEdDSA, AlgRS256}

// Credential is a registered passkey.
type Credential struct {
	ID        []byte
	PublicKey []byte // COSE_Key
	SignCount uint32
}

// Authenticator data flags.
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagAT = 0x40 // attested credential data included
)

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// Challenge returns the challenge in clientDataJSON, so the caller can look
// up what it issued before verifying.
func Challenge(clientDataJSON []byte) (string, error) {
	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return "", errors.New("client data is not JSON")
	}
	return strings.TrimRight(cd.Challenge, "="), nil
}

func checkClientData(raw []byte, typ string, challenge []byte, origin string) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("client data is not JSON")
	}
	if cd.Type != typ {
		return fmt.Errorf("client data type is %q, not %q", cd.Type, typ)
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(cd.Challenge, "="))
	if err != nil || !bytes.Equal(got, challenge) {
		return errors.New("challenge does not match")
	}
	if cd.Origin != origin {
		return fmt.Errorf("origin is %s, not %s", cd.Origin, origin)
	}
	return nil
}

type authData struct {
	flags     byte
	signCount uint32
	credID    []byte
	coseKey   []byte
}

func parseAuthData(b []byte, rpID string, attested bool) (authData, error) {
	var ad authData
	if len(b) < 37 {
		return ad, errors.New("authenticator data is too short")
	}
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(b[:32], want[:]) {
		return ad, fmt.Errorf("the passkey is for another site, not %s", rpID)
	}
	ad.flags, ad.signCount = b[32], binary.BigEndian.Uint32(b[33:37])
	if ad.flags&flagUP == 0 {
		return ad, errors.New("the authenticator did not confirm a person was present")
	}
	if ad.flags&flagUV == 0 {
		return ad, errors.New("the authenticator did not verify the person (PIN or biometrics)")
	}
	if !attested {
		return ad, nil
	}
	if ad.flags&flagAT == 0 || len(b) < 55 {
		return ad, errors.New("no credential in the authenticator data")
	}
	n := int(binary.BigEndian.Uint16(b[53:55]))
	if n == 0 || n > 1023 || len(b) < 55+n {
		return ad, errors.New("bad credential ID length")
	}
	ad.credID = b[55 : 55+n]
	rest := b[55+n:]
	_, after, err := decodeCBOR(rest)
	if err != nil {
		return ad, errors.New("credential public key is not valid CBOR")
	}
	ad.coseKey = append([]byte(nil), rest[:len(rest)-len(after)]...)
	return ad, nil
}

// VerifyRegistration checks a navigator.credentials.create() response and
// returns the new credential.
func VerifyRegistration(clientDataJSON, attestationObject, challenge []byte, origin, rpID string) (Credential, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, origin); err != nil {
		return Credential{}, err
	}
	v, _, err := decodeCBOR(attestationObject)
	m, ok := v.(map[any]any)
	if err != nil || !ok {
		return Credential{}, errors.New("attestation object is not a CBOR map")
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return Credential{}, errors.New("attestation object has no authenticator data")
	}
	ad, err := parseAuthData(raw, rpID, true)
	if err != nil {
		return Credential{}, err
	}
	if _, _, err := publicKey(ad.coseKey); err != nil {
		return Credential{}, err
	}
	return Credential{ID: append([]byte(nil), ad.credID...), PublicKey: ad.coseKey, SignCount: ad.signCount}, nil
}

// VerifyAssertion checks a navigator.credentials.get() response against a
// registered credential and returns the new signature counter.
func VerifyAssertion(cred Credential, clientDataJSON, authenticatorData, signature, challenge []byte, origin, rpID string) (uint32, error) {
	if err := checkClientData(clientDataJSON, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(authenticatorData, rpID, false)
	if err != nil {
		return 0, err
	}
	pub, alg, err := publicKey(cred.PublicKey)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte(nil), authenticatorData...), sum[:]...)
	if !verify(pub, alg, signed, signature) {
		return 0, errors.New("the signature does not verify")
	}
	// A counter that does not go up means a cloned authenticator. Passkeys
	// that sync report 0 every time.
	if ad.signCount != 0 && ad.signCount <= cred.SignCount {
		return 0, errors.New("the signature counter went backwards: the authenticator may be cloned")
	}
	return ad.signCount, nil
}

func verify(pub crypto.PublicKey, alg int, data, sig []byte) bool {
	switch alg {
	case AlgES256:
		h := sha256.Sum256(data)
		return ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), h[:], sig)
	case AlgRS256:
		h := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, h[:], sig) == nil
	case AlgEdDSA:
		return ed25519.Verify(pub.(ed25519.PublicKey), data, sig)
	}
	return false
}

// publicKey reads a COSE_Key.
func publicKey(cose []byte) (crypto.PublicKey, int, error) {
	v, _, err := decodeCBOR(cose)
	m, ok := v.(map[any]any)
	if err != nil || !ok {
		return nil, 0, errors.New("public key is not a COSE key")
	}
	num := func(k int64) int64 { n, _ := m[k].(int64); return n }
	bin := func(k int64) []byte { b, _ := m[k].([]byte); return b }
	kty, alg := num(1), int(num(3))
	switch {
	case kty == 2 && alg == AlgES256 && num(-1) == 1:
		x, y := bin(-2), bin(-3)
		if len(x) != 32 || len(y) != 32 {
			return nil, 0, errors.New("bad P-256 key")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, 0, errors.New("the P-256 key is not on the curve")
		}
		return pub, alg, nil
	case kty == 1 && alg == AlgEdDSA && num(-1) == 6:
		x := bin(-2)
		if len(x) != ed25519.PublicKeySize {
			return nil, 0, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), alg, nil
	case kty == 3 && alg == AlgRS256:
		n, e := bin(-1), bin(-2)
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, 0, errors.New("bad RSA key (2048 bits or more needed)")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, alg, nil
	}
	return nil, 0, fmt.Errorf("unsupported key type %d with algorithm %d", kty, alg)
}
