package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// encrypted replaces the signed assertion in a response with its
// encryption. The assertion is serialized without its own namespace
// declaration, so decryption has to supply the response's.
func encrypted(t *testing.T, raw []byte, pub *rsa.PublicKey, dataAlg, keyAlg string) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.ReadFromBytes(raw)
	a := child(doc.Root(), "Assertion")
	ad := etree.NewDocument()
	ad.SetRoot(a.Copy())
	plain, _ := ad.WriteToBytes()
	enc, err := EncryptAssertion(plain, pub, dataAlg, keyAlg)
	if err != nil {
		t.Fatal(err)
	}
	ed := etree.NewDocument()
	if err := ed.ReadFromBytes(enc); err != nil {
		t.Fatal(err)
	}
	doc.Root().RemoveChild(a)
	doc.Root().AddChild(ed.Root())
	out, _ := doc.WriteToBytes()
	return out
}

func TestEncryptedAssertions(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, c := range []struct {
		data, key, words string
		legacy           bool
	}{
		{EncAES256GCM, KeyRSAOAEP11, "AES-256-GCM, key wrapped with RSA-OAEP (SHA-256)", false},
		{EncAES128GCM, KeyRSAOAEP, "AES-128-GCM, key wrapped with RSA-OAEP (SHA-1)", false},
		{EncAES256CBC, KeyRSAOAEP, "AES-256-CBC", true},
		{EncAES128CBC, KeyRSA15, "RSA PKCS#1 v1.5", true},
		{Enc3DESCBC, KeyRSAOAEP, "Triple DES", true},
	} {
		raw := encrypted(t, build(t, ks, sp.EntityID, false), &key.PublicKey, c.data, c.key)
		rep := inspectWith(t, raw, Expect{DecryptKey: key, WantEncrypted: true}, cert(t, ks))
		if f := failures(rep.Checks); len(f) > 0 || !rep.Verified {
			t.Errorf("%s/%s: verified=%v failures=%v", c.data, c.key, rep.Verified, f)
			continue
		}
		if rep.Encrypted == nil || !strings.Contains(rep.Encrypted.String(), c.words) || (rep.Encrypted.Legacy() != "") != c.legacy {
			t.Errorf("%s/%s: %+v legacy %q", c.data, c.key, rep.Encrypted, rep.Encrypted.Legacy())
		}
		if rep.Assertion.Subject.NameID.Value != "alice@example.com" {
			t.Errorf("decrypted NameID %q", rep.Assertion.Subject.NameID.Value)
		}
	}

	// Encrypted for another key, or with no key here: a plain failure.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw := encrypted(t, build(t, ks, sp.EntityID, false), &other.PublicKey, EncAES256GCM, KeyRSAOAEP)
	for _, k := range []*rsa.PrivateKey{key, nil} {
		rep := inspectWith(t, raw, Expect{DecryptKey: k}, cert(t, ks))
		if f := failures(rep.Checks); len(f) == 0 || rep.Verified {
			t.Errorf("undecryptable assertion passed (key %v)", k != nil)
		}
	}
	// Unencrypted when encryption is expected.
	rep := inspectWith(t, build(t, ks, sp.EntityID, false), Expect{WantEncrypted: true}, cert(t, ks))
	if f := failures(rep.Checks); len(f) != 1 || !strings.Contains(f[0], "unencrypted") {
		t.Errorf("unencrypted assertion: %v", f)
	}
}

func TestEncryptedAssertionInSignedResponse(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// An unsigned assertion, encrypted, in a response that is signed.
	doc := etree.NewDocument()
	doc.ReadFromString(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" InResponseTo="_req1" Destination="` + sp.ACSURL + `"><saml:Issuer>` + idpID + `</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`)
	enc, _ := EncryptAssertion([]byte(assertionXML(sp.EntityID)), &key.PublicKey, EncAES256GCM, KeyRSAOAEP)
	ed := etree.NewDocument()
	ed.ReadFromBytes(enc)
	doc.Root().AddChild(ed.Root())
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	doc.SetRoot(signed)
	raw, _ := doc.WriteToBytes()
	rep := inspectWith(t, raw, Expect{DecryptKey: key}, cert(t, ks))
	if !rep.Verified || rep.Assertion.Subject.NameID.Value != "alice@example.com" {
		t.Errorf("verified=%v failures=%v", rep.Verified, failures(rep.Checks))
	}
}

func TestAuthnRequestOptions(t *testing.T) {
	req := string(AuthnRequest(sp, "_x", "https://idp.example/sso", AuthnOptions{IsPassive: true, NameIDFormat: NameIDPersistent,
		AuthnContext: []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}, Comparison: "minimum"}, now))
	for _, want := range []string{`IsPassive="true"`, `<samlp:NameIDPolicy Format="` + NameIDPersistent + `" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="minimum"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`} {
		if !strings.Contains(req, want) {
			t.Errorf("missing %s in\n%s", want, req)
		}
	}
	if doc := etree.NewDocument(); doc.ReadFromString(req) != nil {
		t.Error("not XML")
	}
	md := string(Metadata(SP{EntityID: "e", ACSURL: "a", EncryptionCert: "Q0VSVA==", NameIDFormat: NameIDEmail}))
	if !strings.Contains(md, `use="encryption"`) || !strings.Contains(md, "<md:NameIDFormat>"+NameIDEmail) {
		t.Errorf("metadata:\n%s", md)
	}
}
