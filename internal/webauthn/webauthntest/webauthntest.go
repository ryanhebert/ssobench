// Package webauthntest is a software passkey for tests.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"sort"
)

// Authenticator is a P-256 passkey that always verifies the user.
type Authenticator struct {
	Key   *ecdsa.PrivateKey
	ID    []byte
	RPID  string
	Count uint32 // signature counter; 0 behaves like a synced passkey
	Flags byte   // authenticator data flags; 0 means user present and verified
}

func New(rpID string) *Authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &Authenticator{Key: k, ID: id, RPID: rpID}
}

func (a *Authenticator) clientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin})
	return b
}

func (a *Authenticator) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	flags := a.Flags
	if flags == 0 {
		flags = 0x05
	}
	if attested {
		flags |= 0x40
	}
	out := append(h[:], flags, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(out[33:], a.Count)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.ID)))
		out = append(out, a.ID...)
		out = append(out, a.COSEKey()...)
	}
	return out
}

// COSEKey is the public key as a COSE_Key.
func (a *Authenticator) COSEKey() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	a.Key.X.FillBytes(x)
	a.Key.Y.FillBytes(y)
	return Encode(map[any]any{int64(1): int64(2), int64(3): int64(-7), int64(-1): int64(1), int64(-2): x, int64(-3): y})
}

// Create answers navigator.credentials.create().
func (a *Authenticator) Create(challenge []byte, origin string) (clientDataJSON, attestationObject []byte) {
	return a.clientData("webauthn.create", challenge, origin),
		Encode(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": a.authData(true)})
}

// Get answers navigator.credentials.get().
func (a *Authenticator) Get(challenge []byte, origin string) (clientDataJSON, authenticatorData, signature []byte) {
	cd := a.clientData("webauthn.get", challenge, origin)
	ad := a.authData(false)
	sum := sha256.Sum256(cd)
	h := sha256.Sum256(append(append([]byte(nil), ad...), sum[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.Key, h[:])
	return cd, ad, sig
}

// Encode writes the CBOR subset WebAuthn uses: int64, string, []byte and
// maps of them, with keys sorted for a stable encoding.
func Encode(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		case n < 65536:
			return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
		}
		return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
	}
	switch t := v.(type) {
	case int64:
		if t >= 0 {
			return head(0, uint64(t))
		}
		return head(1, uint64(-1-t))
	case []byte:
		return append(head(2, uint64(len(t))), t...)
	case string:
		return append(head(3, uint64(len(t))), t...)
	case map[any]any:
		keys := make([][]byte, 0, len(t))
		enc := map[string][]byte{}
		for k, val := range t {
			kb := Encode(k)
			keys = append(keys, kb)
			enc[string(kb)] = Encode(val)
		}
		sort.Slice(keys, func(i, j int) bool { return string(keys[i]) < string(keys[j]) })
		out := head(5, uint64(len(t)))
		for _, kb := range keys {
			out = append(append(out, kb...), enc[string(kb)]...)
		}
		return out
	}
	panic("webauthntest: cannot encode")
}
