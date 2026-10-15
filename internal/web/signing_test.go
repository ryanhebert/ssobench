package web

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

// spCert downloads an app's signing certificate.
func spCert(t *testing.T, c *http.Client, base, id string) *x509.Certificate {
	t.Helper()
	code, body := get(t, c, base+"/saml/"+id+"/cert.pem")
	b, _ := pem.Decode([]byte(body))
	if code != http.StatusOK || b == nil {
		t.Fatalf("cert.pem: %d\n%s", code, body)
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSignedRequests(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	state := filepath.Join(t.TempDir(), "state.json")
	ts, c := newTestServer(t, state)
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataWithSLO(ks)}})
	cert := spCert(t, c, ts.URL, id)

	_, md := get(t, c, ts.URL+"/saml/"+id+"/metadata")
	if !strings.Contains(md, `AuthnRequestsSigned="false"`) || !strings.Contains(md, base64.StdEncoding.EncodeToString(cert.Raw)) {
		t.Errorf("metadata before signing sign-in requests:\n%s", md)
	}
	// Unsigned sign-in requests by default.
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	if strings.Contains(resp.Header.Get("Location"), "Signature=") {
		t.Error("sign-in request signed while the setting is off")
	}

	enable(t, c, ts.URL, id, metadataWithSLO(ks), url.Values{"logout": {"1"}, "sign_authn": {"1"}})
	if _, md := get(t, c, ts.URL+"/saml/"+id+"/metadata"); !strings.Contains(md, `AuthnRequestsSigned="true"`) {
		t.Error("metadata does not say sign-in requests are signed")
	}
	if _, setup := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(setup, "Signing certificate") || !strings.Contains(setup, "/saml/"+id+"/cert.pem") {
		t.Error("Set up lacks the signing certificate")
	}

	verify := func(what, loc string) {
		t.Helper()
		u, _ := url.Parse(loc)
		if present, err := saml.VerifyRedirectSignature(u.RawQuery, []*x509.Certificate{cert}); !present || err != nil {
			t.Errorf("%s: signed %v, %v (%s)", what, present, err, loc)
		}
	}
	resp, _ = c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	verify("AuthnRequest", resp.Header.Get("Location"))

	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	resp, _ = c.PostForm(ts.URL+"/a/"+id+"/logout/"+rid, nil)
	verify("LogoutRequest", resp.Header.Get("Location"))
	lr, _ := saml.DecodeMessage(resp.Header.Get("Location"))
	lrID := regexp.MustCompile(` ID="([^"]+)"`).FindStringSubmatch(string(lr))[1]

	// An answer from another issuer is not trusted.
	other := saml.SP{EntityID: "https://attacker.example"}
	answer, _ := saml.EncodeRedirect(ts.URL+"/saml/"+id+"/slo", "SAMLResponse", saml.LogoutResponse(other, "_lo1", lrID, ts.URL+"/saml/"+id+"/slo", time.Now()), "")
	resp, _ = c.Get(answer)
	if _, page := get(t, c, ts.URL+resp.Header.Get("Location")); !strings.Contains(html.UnescapeString(page), "may still be signed in") {
		t.Errorf("untrusted LogoutResponse shown as confirmed:\n%s", mainOf(page))
	}

	// The IdP's own LogoutRequest is answered with a signed LogoutResponse.
	idp := saml.SP{EntityID: testIdP}
	req, _ := idpRedirect(t, ks, ts.URL+"/saml/"+id+"/slo", "SAMLRequest", saml.LogoutRequest(idp, "_idp1", ts.URL+"/saml/"+id+"/slo", "bob@example.com", "", "", time.Now()), "rs")
	resp, _ = c.Get(req)
	verify("LogoutResponse", resp.Header.Get("Location"))

	// One addressed elsewhere, or from another issuer, is refused.
	for name, msg := range map[string][]byte{
		"wrong destination": saml.LogoutRequest(idp, "_idp2", "https://elsewhere.example/slo", "bob@example.com", "", "", time.Now()),
		"wrong issuer":      saml.LogoutRequest(other, "_idp3", ts.URL+"/saml/"+id+"/slo", "bob@example.com", "", "", time.Now()),
	} {
		req, _ := idpRedirect(t, ks, ts.URL+"/saml/"+id+"/slo", "SAMLRequest", msg, "")
		resp, _ := c.Get(req)
		if body := readBody(resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "still signed in") {
			t.Errorf("%s: %d\n%s", name, resp.StatusCode, mainOf(body))
		}
	}

	// The key survives a restart.
	ts2, c2 := newTestServer(t, state)
	if got := spCert(t, c2, ts2.URL, id); !got.Equal(cert) {
		t.Error("signing certificate changed after a restart")
	}
}

func TestSignedPostBinding(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	md := strings.ReplaceAll(metadataWithSLO(ks), saml.BindingRedirect, saml.BindingPOST)
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {md}})
	enable(t, c, ts.URL, id, md, url.Values{"sign_authn": {"1"}})
	cert := spCert(t, c, ts.URL, id)
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	body := readBody(resp)
	m := regexp.MustCompile(`name="SAMLRequest" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no POST form:\n%s", body)
	}
	raw, err := saml.DecodeMessage(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if present, err := saml.VerifyEmbeddedSignature(raw, []*x509.Certificate{cert}); !present || err != nil {
		t.Errorf("POST AuthnRequest: signed %v, %v\n%s", present, err, raw)
	}
	if strings.Index(string(raw), "Signature") < strings.Index(string(raw), "</saml:Issuer>") {
		t.Error("signature is not after the Issuer")
	}
}

func TestAssetsServeOnlyStaticFiles(t *testing.T) {
	ts, c := newTestServer(t, "")
	for path, want := range map[string]int{"/assets/app.css": 200, "/assets/theme.js": 200, "/assets/": 404, "/assets/layout.html": 404} {
		if code, _ := get(t, c, ts.URL+path); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}
}

// The certificate shown under Set up is the one in the metadata, and it
// stays the same from one page view to the next.
func TestSigningCertIsStable(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	fp := regexp.MustCompile(`SHA-1 fingerprint</dt><dd><span class="v">([0-9A-F]+)`)
	_, p1 := get(t, c, ts.URL+"/apps/"+id+"/setup")
	_, p2 := get(t, c, ts.URL+"/apps/"+id+"/setup")
	m1, m2 := fp.FindStringSubmatch(p1), fp.FindStringSubmatch(p2)
	if m1 == nil || m2 == nil || m1[1] != m2[1] {
		t.Fatalf("fingerprint changed between views: %v %v", m1, m2)
	}
	cert := spCert(t, c, ts.URL, id)
	if !strings.Contains(strings.ReplaceAll(fmt.Sprintf("%X", sha1.Sum(cert.Raw)), " ", ""), m1[1]) {
		t.Error("Set up shows a different certificate from the one served")
	}
}
