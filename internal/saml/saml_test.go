package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/check"
)

var (
	now = time.Now().UTC().Truncate(time.Second)
	sp  = SP{EntityID: "http://localhost:8080/saml/metadata", ACSURL: "http://localhost:8080/saml/acs"}
)

const idpID = "https://idp.example/adfs/services/trust"

func assertionXML(audience string) string {
	f := func(t time.Time) string { return t.Format(time.RFC3339) }
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="%s">
<saml:Issuer>%s</saml:Issuer>
<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="%s" Recipient="%s"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>`, f(now), idpID, f(now.Add(5*time.Minute)), sp.ACSURL, f(now.Add(-time.Minute)), f(now.Add(time.Hour)), audience)
}

// build signs the assertion standalone, then nests it in a Response and
// strips its own namespace declaration so it depends on the parent's, as
// many IdPs emit it.
func build(t *testing.T, ks dsig.X509KeyStore, audience string, tamper bool) []byte {
	t.Helper()
	ad := etree.NewDocument()
	if err := ad.ReadFromString(assertionXML(audience)); err != nil {
		t.Fatal(err)
	}
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(ad.Root())
	if err != nil {
		t.Fatal(err)
	}
	signed.RemoveAttr("xmlns:saml")
	if tamper {
		for _, el := range descendants(signed, "NameID", true) {
			el.SetText("mallory@example.com")
		}
	}
	rd := etree.NewDocument()
	rd.ReadFromString(fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="_req1"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`,
		now.Format(time.RFC3339), sp.ACSURL, idpID))
	rd.Root().AddChild(signed)
	b, err := rd.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cert(t *testing.T, ks dsig.X509KeyStore) *x509.Certificate {
	_, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func inspect(t *testing.T, raw []byte, certs ...*x509.Certificate) *Report {
	t.Helper()
	return inspectWith(t, raw, Expect{}, certs...)
}

// inspectWith fills in the usual expectations around e's.
func inspectWith(t *testing.T, raw []byte, e Expect, certs ...*x509.Certificate) *Report {
	t.Helper()
	e.SP, e.IdP = sp, &IdP{EntityID: idpID, Certs: certs}
	e.RequestKnown = func(id string) bool { return id == "_req1" }
	e.AssertionSeen = func(string) bool { return false }
	e.Now, e.Skew = now, time.Minute
	rep, err := Inspect(raw, e)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func failures(rs []check.Result) []string {
	var out []string
	for _, r := range rs {
		if r.Status == check.Fail {
			out = append(out, r.Name+": "+r.Detail)
		}
	}
	return out
}

func TestSignedAssertionPasses(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	rep := inspect(t, build(t, ks, sp.EntityID, false), cert(t, ks))
	if f := failures(rep.Checks); len(f) > 0 {
		t.Fatalf("unexpected failures: %v", f)
	}
	if !rep.Verified || rep.Assertion.Subject.NameID.Value != "alice@example.com" {
		t.Fatalf("verified=%v nameid=%q", rep.Verified, rep.Assertion.Subject.NameID.Value)
	}
}

func TestTamperedAssertionFails(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	rep := inspect(t, build(t, ks, sp.EntityID, true), cert(t, ks))
	if rep.Verified {
		t.Fatal("tampered assertion verified")
	}
	if !strings.Contains(strings.Join(failures(rep.Checks), "\n"), "Assertion signature") {
		t.Fatalf("no signature failure: %v", failures(rep.Checks))
	}
}

func TestRolledCertExplained(t *testing.T) {
	signer, other := dsig.RandomKeyStoreForTest(), dsig.RandomKeyStoreForTest()
	rep := inspect(t, build(t, signer, sp.EntityID, false), cert(t, other))
	f := strings.Join(failures(rep.Checks), "\n")
	if !strings.Contains(f, "not in the metadata") {
		t.Fatalf("cert mismatch not explained: %s", f)
	}
}

func TestAudienceTrailingSlash(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	rep := inspect(t, build(t, ks, sp.EntityID+"/", false), cert(t, ks))
	for _, r := range rep.Checks {
		if r.Name == "Audience" {
			if r.Status != check.Fail || !strings.Contains(r.Fix, "trailing slash") {
				t.Fatalf("audience check: %+v", r)
			}
			return
		}
	}
	t.Fatal("no audience check")
}

func TestRedirectRoundTrip(t *testing.T) {
	req := AuthnRequest(sp, "_x", "https://idp.example/sso", AuthnOptions{ForceAuthn: true}, now)
	u, err := RedirectURL("https://idp.example/sso?tenant=1", req, "")
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	if pu.Query().Get("tenant") != "1" {
		t.Error("existing query parameter lost")
	}
	got, err := DecodeMessage(u)
	if err != nil || string(got) != string(req) {
		t.Fatalf("round trip: %v\n%s", err, got)
	}
}

func TestParseMetadata(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	_, der, _ := ks.GetKeyPair()
	md := fmt.Sprintf(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="%s"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>bm90LWEtY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="%s" Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`,
		idpID, b64std(der), BindingRedirect)
	idp, err := ParseMetadata([]byte(md))
	if err != nil {
		t.Fatal(err)
	}
	if idp.EntityID != idpID || idp.SSORedirect == "" || len(idp.Certs) != 1 {
		t.Fatalf("%+v", idp)
	}
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestLogoutMessagesAndRedirectSignature(t *testing.T) {
	sp := SP{EntityID: "https://sp.example/saml/x/metadata", ACSURL: "https://sp.example/saml/x/acs", SLOURL: "https://sp.example/saml/x/slo"}
	req := LogoutRequest(sp, "_lr1", "https://idp.example/slo", "bob@example.com", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "_s1", now)
	m, err := ParseLogout(req)
	if err != nil || !m.IsRequest() || m.NameID.Value != "bob@example.com" || len(m.SessionIndex) != 1 {
		t.Fatalf("logout request: %v %+v", err, m)
	}
	resp, _ := ParseLogout(LogoutResponse(sp, "_r1", "_lr1", "https://idp.example/slo", now))
	if resp.IsRequest() || !resp.Success() || resp.InResponseTo != "_lr1" {
		t.Fatalf("logout response: %+v", resp)
	}
	if md := string(Metadata(sp)); !strings.Contains(md, `SingleLogoutService Binding="`+BindingRedirect+`" Location="https://sp.example/saml/x/slo"`) {
		t.Error("SP metadata lacks SingleLogoutService")
	}

	// A signed HTTP-Redirect message, signed the way an IdP does it.
	ks := dsig.RandomKeyStoreForTest()
	key, der, _ := ks.GetKeyPair()
	cert, _ := x509.ParseCertificate(der)
	u, _ := EncodeRedirect("https://sp.example/saml/x/slo", "SAMLRequest", req, "rs-1")
	pu, _ := url.Parse(u)
	q := pu.Query()
	signed := "SAMLRequest=" + url.QueryEscape(q.Get("SAMLRequest")) + "&RelayState=" + url.QueryEscape(q.Get("RelayState")) +
		"&SigAlg=" + url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	raw := signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	if present, err := VerifyRedirectSignature(raw, []*x509.Certificate{cert}); !present || err != nil {
		t.Errorf("valid redirect signature: present=%v err=%v", present, err)
	}
	tampered := strings.Replace(raw, "RelayState=rs-1", "RelayState=rs-2", 1)
	if _, err := VerifyRedirectSignature(tampered, []*x509.Certificate{cert}); err == nil {
		t.Error("tampered redirect message verified")
	}
	if present, _ := VerifyRedirectSignature(signed[:strings.Index(signed, "&SigAlg")], nil); present {
		t.Error("unsigned message reported as signed")
	}
	// A forged copy in front of the signed one: the receiver reads the first.
	forged := "SAMLRequest=" + url.QueryEscape("Zm9yZ2Vk") + "&" + raw
	if present, err := VerifyRedirectSignature(forged, []*x509.Certificate{cert}); !present || err == nil {
		t.Errorf("repeated SAMLRequest: present=%v err=%v, want a failed signature", present, err)
	}
	both := raw + "&SAMLResponse=x"
	if _, err := VerifyRedirectSignature(both, []*x509.Certificate{cert}); err == nil {
		t.Error("message with both SAMLRequest and SAMLResponse verified")
	}
}

func TestParseMetadataLogoutEndpoints(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	_, der, _ := ks.GetKeyPair()
	md := fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><IDPSSODescriptor><KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService Binding="%s" Location="https://idp.example/slo"/><SingleSignOnService Binding="%s" Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		b64std(der), BindingRedirect, BindingRedirect)
	idp, err := ParseMetadata([]byte(md))
	if err != nil || idp.SLORedirect != "https://idp.example/slo" {
		t.Fatalf("%v %+v", err, idp)
	}
}

// Requests signed by SSOBench verify with the certificate it publishes, both
// as a signed redirect URL and as an embedded XML signature.
func TestSignerRoundTrip(t *testing.T) {
	sg, keyPEM, certPEM, err := NewSigner("SSOBench test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(keyPEM, certPEM); err != nil {
		t.Fatal(err)
	}
	sp := SP{EntityID: "https://sp.example/m", ACSURL: "https://sp.example/acs", SigningCert: sg.CertBase64(), SignRequests: true}
	if md := string(Metadata(sp)); !strings.Contains(md, `use="signing"`) || !strings.Contains(md, `AuthnRequestsSigned="true"`) {
		t.Error("SP metadata lacks the signing certificate")
	}
	req := LogoutRequest(sp, "_lr", "https://idp.example/slo", "bob", "", "", now)
	u, err := EncodeRedirectSigned("https://idp.example/slo?tenant=1", "SAMLRequest", req, "rs 1", sg)
	if err != nil {
		t.Fatal(err)
	}
	raw := u[strings.Index(u, "?")+1:]
	raw = strings.TrimPrefix(raw, "tenant=1&")
	if present, err := VerifyRedirectSignature(raw, []*x509.Certificate{sg.Cert}); !present || err != nil {
		t.Errorf("signed redirect: present=%v err=%v", present, err)
	}
	if got, err := DecodeMessage(u); err != nil || string(got) != string(req) {
		t.Errorf("signed redirect does not decode back: %v", err)
	}
	signed, err := sg.SignEnveloped(req)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := VerifyEmbeddedSignature(signed, []*x509.Certificate{sg.Cert}); !present || err != nil {
		t.Errorf("embedded signature: present=%v err=%v", present, err)
	}
	if i, j := strings.Index(string(signed), "Issuer>"), strings.Index(string(signed), "Signature"); j < i {
		t.Error("Signature is not placed after Issuer")
	}
}
