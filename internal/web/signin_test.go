package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

// signInVia starts a SAML sign-in at path (the app's sign-in page or the
// console button), answers it as the IdP, and returns where SSOBench sends
// the browser afterwards.
func signInVia(t *testing.T, c *http.Client, base, app, path string, ks dsig.X509KeyStore, audienceSuffix string) string {
	t.Helper()
	resp, err := c.PostForm(base+path, nil)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("start at %s: %v %d", path, err, resp.StatusCode)
	}
	reqXML, err := saml.DecodeMessage(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	reqID := regexp.MustCompile(` ID="([^"]+)"`).FindStringSubmatch(string(reqXML))[1]
	loc, _ := url.Parse(resp.Header.Get("Location"))
	spBase := base + "/saml/" + app
	sr := signedResponse(t, ks, testIdP, spBase+audienceSuffix, reqID)
	resp, err = c.PostForm(spBase+"/acs", url.Values{"SAMLResponse": {sr}, "RelayState": {loc.Query().Get("RelayState")}})
	if err != nil {
		t.Fatal(err)
	}
	return resp.Header.Get("Location")
}

func TestSignInPageShowsWelcome(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})

	_, page := get(t, c, ts.URL+"/a/"+id)
	if !strings.Contains(page, "Sign in with single sign-on") || !strings.Contains(page, "Payroll") || strings.Contains(page, `class="topbar"`) {
		t.Error("sign-in page wrong, or shows the console")
	}

	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	if !strings.HasPrefix(loc, "/a/"+id+"/welcome/") {
		t.Fatalf("sign-in page landed at %q, want the welcome screen", loc)
	}
	_, welcome := get(t, c, ts.URL+loc)
	for _, want := range []string{"Welcome, bob", "Payroll", "Engineering &amp; Ops", "Sign out", "Details for administrators"} {
		if !strings.Contains(welcome, want) {
			t.Errorf("welcome screen missing %q", want)
		}
	}
	if strings.Contains(welcome, `class="topbar"`) || strings.Contains(welcome, "Signature") {
		t.Error("welcome screen shows console or diagnostics")
	}

	// The console button still goes to diagnostics.
	if loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, ""); !strings.HasPrefix(loc, "/result/") {
		t.Errorf("Test sign-in landed at %q, want diagnostics", loc)
	}
}

func TestSignInPageFailure(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	// Wrong audience: the sign-in fails its checks.
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "-wrong")
	_, page := get(t, c, ts.URL+loc)
	rid := loc[strings.LastIndex(loc, "/")+1:]
	for _, want := range []string{"We couldn't sign you in", rid, "Try again", "/result/" + rid} {
		if !strings.Contains(page, want) {
			t.Errorf("failure screen missing %q", want)
		}
	}
	if strings.Contains(page, "Welcome") {
		t.Error("failed sign-in shows a welcome")
	}
}

func TestIdPInitiatedLanding(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	base := ts.URL + "/saml/" + id
	post := func() string {
		resp, _ := c.PostForm(base+"/acs", url.Values{"SAMLResponse": {signedResponse(t, ks, testIdP, base, "")}})
		return resp.Header.Get("Location")
	}
	if loc := post(); !strings.HasPrefix(loc, "/a/"+id+"/welcome/") {
		t.Errorf("default IdP-initiated landing %q, want the welcome screen", loc)
	}
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	if loc := post(); !strings.HasPrefix(loc, "/result/") {
		t.Errorf("IdP-initiated landing %q after choosing diagnostics", loc)
	}
}

func TestProfileLabels(t *testing.T) {
	res := &Result{Subject: "jdoe@example.com", All: []Section{{Group: GroupIdentity, Rows: []Row{
		{K: "given_name", V: "Jane"}, {K: "family_name", V: "Doe"}, {K: "groups", V: "Admins\nVPN"},
		{K: "Email", V: "jane@example.com"}, {K: "nonce", V: "abc"}, {K: "costCenter", V: "42"},
	}}}}
	p := res.Profile()
	if p.DisplayName != "Jane Doe" || p.FirstName() != "Jane" || p.Initials != "JD" || p.Email != "jane@example.com" {
		t.Errorf("profile %+v", p)
	}
	var labels []string
	for _, f := range p.Fields {
		labels = append(labels, f.Label)
	}
	if got := strings.Join(labels, ","); got != "Email,First name,Last name,Groups,costCenter" {
		t.Errorf("fields %s", got)
	}
}

// Light and dark can be chosen on both the console and the end-user pages,
// and the saved choice is applied before the page draws.
func TestThemeSwitch(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	for _, u := range []string{"/", "/a/" + id} {
		_, page := get(t, c, ts.URL+u)
		head := page[:strings.Index(page, "</head>")]
		if !strings.Contains(page, "data-theme-toggle") || !strings.Contains(head, `<script src="/assets/theme.js"></script>`) {
			t.Errorf("%s: theme switch or early theme script missing", u)
		}
	}
	if code, js := get(t, c, ts.URL+"/assets/theme.js"); code != 200 || !strings.Contains(js, "ssobench.theme") {
		t.Error("theme.js not served")
	}
}
