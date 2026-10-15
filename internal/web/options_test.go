package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

func TestSAMLRequestOptions(t *testing.T) {
	t.Cleanup(func() { testAuthnStatement = "" })
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"nameid_format": {saml.NameIDPersistent},
		"authn_context": {"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"}, "authn_comparison": {"exact"}})
	if _, md := get(t, c, ts.URL+"/saml/"+id+"/metadata"); !strings.Contains(md, "<md:NameIDFormat>"+saml.NameIDPersistent) {
		t.Error("metadata does not ask for the persistent format")
	}
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	req, _ := saml.DecodeMessage(resp.Header.Get("Location"))
	if !strings.Contains(string(req), `Format="`+saml.NameIDPersistent+`"`) || !strings.Contains(string(req), "RequestedAuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509") {
		t.Errorf("AuthnRequest:\n%s", req)
	}

	// The IdP answers with a password context and a NameID with no format.
	testAuthnStatement = authnStatement(time.Now())
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page := get(t, c, ts.URL+loc)
	for _, want := range []string{"asked for Persistent, but the NameID states no format", "asked for exactly Certificate, but got Password, over an encrypted connection"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q:\n%s", want, mainOf(page))
		}
	}
	if checkStatus(page, "Authentication context") != "fail" || checkStatus(page, "NameID format") != "warn" {
		t.Errorf("context %q, NameID format %q", checkStatus(page, "Authentication context"), checkStatus(page, "NameID format"))
	}

	// IsPassive: a fresh authentication is a failure; a reused session passes.
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"nameid_format": {""}, "is_passive": {"1"}})
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "the person authenticated during a passive request") {
		t.Errorf("IsPassive with a fresh authentication:\n%s", mainOf(page))
	}
	testAuthnStatement = authnStatement(time.Now().Add(-time.Hour))
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, "honored: signed in with the existing session") {
		t.Errorf("IsPassive with a session:\n%s", mainOf(page))
	}
}

// encryptResponse replaces the assertion in a base64 response with its
// encryption for pub.
func encryptResponse(t *testing.T, b64 string, pub *rsa.PublicKey, dataAlg, keyAlg string) string {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(b64)
	doc := etree.NewDocument()
	doc.ReadFromBytes(raw)
	a := doc.Root().SelectElement("Assertion")
	ad := etree.NewDocument()
	ad.SetRoot(a.Copy())
	plain, _ := ad.WriteToBytes()
	enc, err := saml.EncryptAssertion(plain, pub, dataAlg, keyAlg)
	if err != nil {
		t.Fatal(err)
	}
	ed := etree.NewDocument()
	ed.ReadFromBytes(enc)
	doc.Root().RemoveChild(a)
	doc.Root().AddChild(ed.Root())
	out, _ := doc.WriteToBytes()
	return base64.StdEncoding.EncodeToString(out)
}

func TestEncryptedAssertionsEndToEnd(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}, "nameid_format": {""}, "encrypt": {"1"}})
	if _, md := get(t, c, ts.URL+"/saml/"+id+"/metadata"); !strings.Contains(md, `use="encryption"`) {
		t.Fatal("metadata has no encryption key")
	}
	if _, setup := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(setup, "Encryption certificate") {
		t.Error("Set up lacks the encryption certificate")
	}
	_, body := get(t, c, ts.URL+"/saml/"+id+"/encryption.pem")
	blk, _ := pem.Decode([]byte(body))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := cert.PublicKey.(*rsa.PublicKey)
	base := ts.URL + "/saml/" + id

	page, _ := postACS(t, c, base+"/acs", encryptResponse(t, signedResponse(t, ks, testIdP, base, ""), pub, saml.EncAES256GCM, saml.KeyRSAOAEP11))
	if failed(page) || !strings.Contains(page, "AES-256-GCM, key wrapped with RSA-OAEP") || !strings.Contains(page, "Decrypted assertion") {
		t.Errorf("encrypted sign-in:\n%s", mainOf(page))
	}
	page, _ = postACS(t, c, base+"/acs", encryptResponse(t, signedResponse(t, ks, testIdP, base, ""), pub, saml.EncAES128CBC, saml.KeyRSA15))
	if !strings.Contains(page, "Bleichenbacher") {
		t.Errorf("legacy algorithms not flagged:\n%s", mainOf(page))
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	page, _ = postACS(t, c, base+"/acs", encryptResponse(t, signedResponse(t, ks, testIdP, base, ""), &other.PublicKey, saml.EncAES256GCM, saml.KeyRSAOAEP))
	if !failed(page) || !strings.Contains(page, "encrypted for another certificate") {
		t.Errorf("wrong certificate:\n%s", mainOf(page))
	}
	page, _ = postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base, ""))
	if !failed(page) || !strings.Contains(page, "arrived unencrypted") {
		t.Errorf("unencrypted assertion accepted:\n%s", mainOf(page))
	}
}

func TestOIDCHintsAndScopes(t *testing.T) {
	t.Cleanup(func() { fakeClaims, fakeTokenScope = nil, "" })
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"}, "client_secret": {"s"}, "scopes": {"openid email profile"}})
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"issuer": {idp.URL}, "client_id": {"client-1"}, "scopes": {"openid email profile"}, "extra": {""},
		"acr_values": {"urn:example:mfa"}, "login_hint": {"bob@example.com"}})
	fakeClaims = map[string]any{"acr": "urn:example:pwd"}
	fakeTokenScope = "openid email profile"
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	resp, _ = c.Get(resp.Header.Get("Location"))
	if fakeAuthorize.Get("acr_values") != "urn:example:mfa" || fakeAuthorize.Get("login_hint") != "bob@example.com" {
		t.Errorf("authorize request: %v", fakeAuthorize)
	}
	resp, _ = c.Get(resp.Header.Get("Location"))
	_, page := get(t, c, ts.URL+resp.Header.Get("Location"))
	for _, want := range []string{"not one of the acr_values asked for", "bob@example.com was suggested, but alice@example.com signed in",
		"Scopes and claims", "no claims arrived for profile", "email, email_verified"} {
		if !strings.Contains(page, want) && !strings.Contains(page, strings.ReplaceAll(want, "email, email_verified", "email")) {
			t.Errorf("missing %q:\n%s", want, mainOf(page))
		}
	}
}
