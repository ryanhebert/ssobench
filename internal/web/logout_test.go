package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

const idpSLO = "https://idp.example/slo"

func metadataWithSLO(ks dsig.X509KeyStore) string {
	return strings.Replace(metadataFor(ks, testIdP), "<SingleSignOnService",
		`<SingleLogoutService Binding="`+saml.BindingRedirect+`" Location="`+idpSLO+`"/><SingleSignOnService`, 1)
}

func enable(t *testing.T, c *http.Client, base, id string, md string, extra url.Values) {
	t.Helper()
	form := url.Values{"metadata_xml": {md}, "optional": {"1"}}
	for k, v := range extra {
		form[k] = v
	}
	if resp, err := c.PostForm(base+"/apps/"+id, form); err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save settings: %v %v", err, resp.StatusCode)
	}
}

func TestOptionalFeaturesOffByDefault(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataWithSLO(ks)}})
	if _, md := get(t, c, ts.URL+"/saml/"+id+"/metadata"); strings.Contains(md, "SingleLogoutService") {
		t.Error("SP metadata offers single logout while it is off")
	}
	if code, _ := get(t, c, ts.URL+"/a/"+id+"/login"); code != http.StatusNotFound {
		t.Errorf("login URL answered %d while off", code)
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id); strings.Contains(page, "/saml/"+id+"/slo") || strings.Contains(page, "/a/"+id+"/login") {
		t.Error("Set up lists optional URLs that are off")
	}
	// Sign out with single logout off: local only, and it says so.
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	resp, _ := c.PostForm(ts.URL+"/a/"+id+"/logout/"+rid, nil)
	if to := resp.Header.Get("Location"); to != "/a/"+id+"/signed-out" {
		t.Fatalf("sign-out went to %q", to)
	}
	_, body := get(t, c, ts.URL+"/a/"+id+"/signed-out")
	if !strings.Contains(body, "signed out of Payroll") || !strings.Contains(body, "may still be signed in") || strings.Contains(body, "end_session_endpoint") {
		t.Errorf("local sign-out page wrong:\n%s", mainOf(body))
	}
}

func TestSAMLSingleLogout(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataWithSLO(ks)}})
	enable(t, c, ts.URL, id, metadataWithSLO(ks), url.Values{"logout": {"1"}})
	if _, md := get(t, c, ts.URL+"/saml/"+id+"/metadata"); !strings.Contains(md, `Location="`+ts.URL+`/saml/`+id+`/slo"`) {
		t.Error("SP metadata lacks the single logout URL")
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(page, ts.URL+"/saml/"+id+"/slo") {
		t.Error("Set up does not list the single logout URL")
	}

	// SP-initiated: welcome screen, Sign out, LogoutRequest to the IdP.
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	// Sign-out continues at the IdP in a new tab; this tab returns to the
	// sign-in page.
	if _, page := get(t, c, ts.URL+loc); !strings.Contains(page, `target="_blank"`) || !strings.Contains(page, `data-then="/a/`+id+`"`) {
		t.Errorf("welcome sign-out form does not return this tab to the sign-in page:\n%s", mainOf(page))
	}
	resp, _ := c.PostForm(ts.URL+"/a/"+id+"/logout/"+rid, nil)
	to := resp.Header.Get("Location")
	if !strings.HasPrefix(to, idpSLO+"?") {
		t.Fatalf("sign-out went to %q, want the IdP's single logout URL", to)
	}
	lr, err := saml.DecodeMessage(to)
	if err != nil || !strings.Contains(string(lr), "LogoutRequest") || !strings.Contains(string(lr), "bob@example.com") {
		t.Fatalf("LogoutRequest: %v\n%s", err, lr)
	}
	lrID := regexp.MustCompile(` ID="([^"]+)"`).FindStringSubmatch(string(lr))[1]

	// The IdP answers Success over the Redirect binding.
	sp := saml.SP{EntityID: testIdP}
	answer, _ := saml.EncodeRedirect(ts.URL+"/saml/"+id+"/slo", "SAMLResponse", saml.LogoutResponse(sp, "_lo1", lrID, ts.URL+"/saml/"+id+"/slo", time.Now()), "")
	resp, _ = c.Get(answer)
	_, page := get(t, c, ts.URL+resp.Header.Get("Location"))
	if !strings.Contains(page, "of your single sign-on session") {
		t.Errorf("confirmed sign-out page wrong:\n%s", mainOf(page))
	}

	// IdP-initiated: the IdP asks; SSOBench answers with a LogoutResponse.
	req, _ := idpRedirect(t, ks, ts.URL+"/saml/"+id+"/slo", "SAMLRequest", saml.LogoutRequest(sp, "_idp1", ts.URL+"/saml/"+id+"/slo", "bob@example.com", "", "", time.Now()), "rs")
	resp, _ = c.Get(req)
	back := resp.Header.Get("Location")
	if !strings.HasPrefix(back, idpSLO+"?") {
		t.Fatalf("IdP-initiated logout answered to %q", back)
	}
	if lo, _ := saml.DecodeMessage(back); !strings.Contains(string(lo), `InResponseTo="_idp1"`) || !strings.Contains(string(lo), "status:Success") {
		t.Errorf("LogoutResponse wrong:\n%s", lo)
	}
	if !strings.Contains(back, "RelayState=rs") {
		t.Error("RelayState not returned with the LogoutResponse")
	}
}

func TestLoginURLAndDefaultRelayState(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"login_url": {"1"}, "relay_state_on": {"1"}, "idp_landing": {"diagnostics"}})
	deepLink := ts.URL + "/a/" + id + "/deep-link"
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(page, deepLink) {
		t.Error("Set up does not give the default relay state")
	}
	if resp, _ := c.Get(deepLink); resp.Header.Get("Location") != "/a/"+id {
		t.Errorf("deep link opened directly went to %q", resp.Header.Get("Location"))
	}

	resp, _ := c.Get(ts.URL + "/a/" + id + "/login")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "https://idp.example/sso?") {
		t.Errorf("login URL: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	base := ts.URL + "/saml/" + id
	ok, _ := postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base, ""), deepLink)
	if failed(ok) || !strings.Contains(ok, "arrived through the app") {
		t.Errorf("expected relay state not accepted:\n%s", mainOf(ok))
	}
	bad, _ := postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base, ""), deepLink+"/")
	if !failed(bad) || !strings.Contains(bad, "trailing slash") {
		t.Errorf("wrong relay state not caught:\n%s", mainOf(bad))
	}
}

// The admin view breaks the whole assertion down, and shows attributes by
// their full name.
func TestCompleteAssertionView(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"idp_landing": {"diagnostics"}})
	base := ts.URL + "/saml/" + id
	body, _ := postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base, ""))
	for _, want := range []string{"Response and assertion", "Subject", "Conditions", "Confirmation method", "urn:oasis:names:tc:SAML:2.0:cm:bearer", "Signatures", "department"} {
		if !strings.Contains(body, want) {
			t.Errorf("assertion view missing %q", want)
		}
	}
}

func readBody(resp *http.Response) string {
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

// Turning on optional features shows their URLs right away, under Set up,
// which opens with a note of what was added. Settings has only the switches.
func TestEnabledFeatureURLsShown(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	resp, _ := c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "optional": {"1"}, "logout": {"1"}, "login_url": {"1"}})
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/setup?done=saved&added=") {
		t.Fatalf("save redirected to %q", loc)
	}
	_, page := get(t, c, ts.URL+loc)
	for _, want := range []string{"single logout URL, service provider login URL", ts.URL + "/saml/" + id + "/slo", ts.URL + "/a/" + id + "/login"} {
		if !strings.Contains(page, want) {
			t.Errorf("after enabling, page missing %q", want)
		}
	}
	if _, settings := get(t, c, ts.URL+"/apps/"+id+"/settings"); strings.Contains(settings, ts.URL+"/saml/"+id+"/slo") {
		t.Error("Settings repeats the single logout URL; it belongs under Set up only")
	}
}

// A single logout URL entered for the app is used when the metadata has none.
func TestEnteredIdPLogoutURL(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"logout": {"1"}, "idp_slo_url": {"https://idp.example/saml2/sp/APP1/slo"}})
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	resp, _ := c.PostForm(ts.URL+"/a/"+id+"/logout/"+rid, nil)
	if to := resp.Header.Get("Location"); !strings.HasPrefix(to, "https://idp.example/saml2/sp/APP1/slo?") {
		t.Fatalf("sign-out went to %q, want the entered IdP logout URL", to)
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id); !strings.Contains(page, "Entered in this app") {
		t.Error("Identity provider section does not say where the logout URL came from")
	}
}

// A logout request ends sessions, so one that isn't signed is refused.
func TestUnsignedIdPLogoutRequestRefused(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataWithSLO(ks)}})
	enable(t, c, ts.URL, id, metadataWithSLO(ks), url.Values{"logout": {"1"}})
	alice := browser()
	welcome := signInVia(t, alice, ts.URL, id, "/a/"+id+"/login", ks, "")
	get(t, alice, ts.URL+welcome)
	sp := saml.SP{EntityID: testIdP}
	req, _ := saml.EncodeRedirect(ts.URL+"/saml/"+id+"/slo", "SAMLRequest", saml.LogoutRequest(sp, "_u1", ts.URL+"/saml/"+id+"/slo", "bob@example.com", "", "", time.Now()), "")
	resp, _ := c.Get(req)
	if body := readBody(resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not signed") {
		t.Errorf("unsigned logout request: %d\n%s", resp.StatusCode, mainOf(body))
	}
	if code, _ := get(t, alice, ts.URL+welcome); code != http.StatusOK {
		t.Error("an unsigned logout request ended the session")
	}
}
