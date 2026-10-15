package web

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/ryanhebert/ssobench/internal/check"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

const testIdP = "https://idp.example/saml2/app1"

// newTestServer runs SSOBench on a test listener. Redirects are not followed,
// so tests can see where each step sends the browser.
func newTestServer(t *testing.T, statePath string) (*httptest.Server, *http.Client) {
	t.Helper()
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	srv, err := New(ts.URL, time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Quiet = true
	srv.StatePath = statePath
	// Every failure and warning tells the reader how to fix it.
	srv.onSave = func(res *Result) {
		for _, c := range res.Checks {
			if (c.Status == check.Fail || c.Status == check.Warn) && c.Fix == "" {
				t.Errorf("%s check %q (%s) has no fix", c.Status, c.Name, c.Detail)
			}
		}
	}
	if err := srv.LoadState(); err != nil {
		t.Fatal(err)
	}
	if err := srv.LoadHistory(); err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	return ts, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// createApp posts the new-app form and returns the app ID.
func createApp(t *testing.T, c *http.Client, base string, form url.Values) string {
	t.Helper()
	resp, err := c.PostForm(base+"/apps", form)
	if err != nil {
		t.Fatal(err)
	}
	loc := resp.Header.Get("Location")
	m := regexp.MustCompile(`^/apps/([^/?]+)\?done=created$`).FindStringSubmatch(loc)
	if resp.StatusCode != http.StatusSeeOther || m == nil {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create app: %d %q\n%s", resp.StatusCode, loc, b)
	}
	return m[1]
}

func metadataFor(ks dsig.X509KeyStore, entityID string) string {
	_, der, _ := ks.GetKeyPair()
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s"><IDPSSODescriptor><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></IDPSSODescriptor></EntityDescriptor>`,
		entityID, base64.StdEncoding.EncodeToString(der))
}

// signedResponse builds a response from issuer, signed by ks, for the SP
// whose URLs start with spBase (base+"/saml/"+appID, or base+"/saml" for the
// legacy URLs). An empty inResponseTo makes it unsolicited (IdP-initiated).
func signedResponse(t *testing.T, ks dsig.X509KeyStore, issuer, spBase, inResponseTo string) string {
	t.Helper()
	now := time.Now().UTC()
	f := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	irt := ""
	if inResponseTo != "" {
		irt = fmt.Sprintf(` InResponseTo="%s"`, inResponseTo)
	}
	ad := etree.NewDocument()
	ad.ReadFromString(fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a%d" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer><saml:Subject><saml:NameID>bob@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData%s NotOnOrAfter="%s" Recipient="%s/acs"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>%s<saml:AttributeStatement><saml:Attribute Name="department"><saml:AttributeValue>Engineering &amp; Ops</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`,
		now.UnixNano(), f(0), issuer, irt, f(5*time.Minute), spBase, f(-time.Minute), f(time.Hour), spBase, testAuthnStatement))
	sc := dsig.NewDefaultSigningContext(ks)
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sc.SignEnveloped(ad.Root())
	if err != nil {
		t.Fatal(err)
	}
	ad.SetRoot(signed)
	as, _ := ad.WriteToString()
	resp := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r%d" Version="2.0" IssueInstant="%s" Destination="%s/acs"%s><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>`,
		now.UnixNano(), f(0), spBase, irt, as)
	return base64.StdEncoding.EncodeToString([]byte(resp))
}

// testAuthnStatement, when set, goes into the assertions signedResponse
// builds. Tests do not run in parallel.
var testAuthnStatement string

var welcomePath = regexp.MustCompile(`^/a/[^/]+/welcome/([^/]+)$`)

// postACS posts a response to acsURL and returns the diagnostic result page
// and its URL, following a welcome-screen landing through to the result.
func postACS(t *testing.T, c *http.Client, acsURL, samlResponse string, relayState ...string) (string, string) {
	t.Helper()
	relay := "https://app.example/landing"
	if len(relayState) > 0 {
		relay = relayState[0]
	}
	resp, err := c.PostForm(acsURL, url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relay}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(acsURL)
	loc := resp.Header.Get("Location")
	if m := welcomePath.FindStringSubmatch(loc); m != nil {
		loc = "/result/" + m[1]
	}
	res := u.Scheme + "://" + u.Host + loc
	_, body := get(t, c, res)
	return body, res
}

// mdServer serves metadata whose content can be swapped (a rollover).
type mdServer struct {
	mu sync.Mutex
	md string
}

func (m *mdServer) set(s string) { m.mu.Lock(); m.md = s; m.mu.Unlock() }
func (m *mdServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprint(w, m.md)
}

// failed reports whether a result page has a failing check. Tests find
// checks by their data attributes, which don't change with the design.
func failed(body string) bool { return strings.Contains(body, `data-status="fail"`) }

// checkStatus is the status of the named check on a result page, or "".
func checkStatus(body, name string) string {
	m := regexp.MustCompile(`data-check="` + regexp.QuoteMeta(html.EscapeString(name)) + `" data-status="(\w+)"`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

func mainOf(body string) string {
	if i := strings.Index(body, "<main"); i >= 0 {
		return body[i:]
	}
	return body
}

// idpRedirect encodes msg for the Redirect binding, signed with the test
// IdP's key, as an identity provider sends a logout request.
func idpRedirect(t *testing.T, ks dsig.X509KeyStore, dest, param string, msg []byte, relay string) (string, error) {
	t.Helper()
	key, der, err := ks.GetKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return saml.EncodeRedirectSigned(dest, param, msg, relay, &saml.Signer{Key: key, Cert: cert})
}

// TestMain makes each kind of SAML key once, rather than once per app:
// generating RSA keys was half the time of this package's tests.
func TestMain(m *testing.M) {
	newSigningKey, newEncryptionKey = onceKey(saml.NewSigner), onceKey(saml.NewEncryptionKey)
	os.Exit(m.Run())
}

func onceKey(make func(string) (*saml.Signer, []byte, []byte, error)) func(string) (*saml.Signer, []byte, []byte, error) {
	var once sync.Once
	var sg *saml.Signer
	var k, c []byte
	var err error
	return func(string) (*saml.Signer, []byte, []byte, error) {
		once.Do(func() { sg, k, c, err = make("SSOBench test") })
		return sg, k, c, err
	}
}
