package web

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
)

// Paths that are easy to miss: errors starting a sign-in, the console's
// smaller actions, and the original single-app URLs.
func TestSmallerPaths(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")

	// A metadata URL that stops answering: the sign-in can't start, and
	// the app page says why.
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(metadataFor(ks, testIdP))) }))
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_url": {md.URL}})
	md.Close()
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	if body := readBody(resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "could not load the IdP metadata") && !strings.Contains(body, "Could not load the IdP metadata") {
		t.Errorf("sign-in with unreachable metadata: %d\n%s", resp.StatusCode, mainOf(body))
	}

	// The directory: turn it on, add an account, delete it.
	if resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/directory", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("directory on: %d", resp.StatusCode)
	}
	c.PostForm(ts.URL+"/apps/"+id+"/users", url.Values{"userName": {"carol@example.com"}})
	_, page := get(t, c, ts.URL+"/apps/"+id+"/users")
	m := regexp.MustCompile(`/users/([^/"]+)/delete`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no account to delete:\n%s", mainOf(page))
	}
	uid := m[1]
	c.PostForm(ts.URL+"/apps/"+id+"/users/"+uid+"/delete", nil)
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/users"); strings.Contains(page, "carol@example.com") {
		t.Error("account not deleted")
	}

	// The old /saml URL goes to the apps list.
	if resp, _ := c.Get(ts.URL + "/saml"); resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("/saml: %d", resp.StatusCode)
	}
}

// A response posted to the original /saml/acs URL, with no legacy app,
// is matched to an app by the IdP's entity ID.
func TestLegacyACSFindsAppByIssuer(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	page, _ := postACS(t, c, ts.URL+"/saml/acs", signedResponse(t, ks, testIdP, ts.URL+"/saml/"+id, ""))
	if !strings.Contains(page, "Payroll") {
		t.Errorf("legacy ACS did not find the app:\n%s", mainOf(page))
	}
}

func TestOIDCCallbackErrors(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"}, "client_secret": {"s"}})
	start := func() string {
		resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
		u, _ := url.Parse(resp.Header.Get("Location"))
		return u.Query().Get("state")
	}
	result := func(q url.Values) string {
		resp, _ := c.Get(ts.URL + "/oidc/" + id + "/callback?" + q.Encode())
		_, page := get(t, c, ts.URL+resp.Header.Get("Location"))
		return page
	}
	if page := result(url.Values{"state": {start()}, "error": {"access_denied"}, "error_description": {"no"}}); !strings.Contains(page, "access_denied") || checkStatus(page, "Authorization") == "" && !failed(page) {
		t.Errorf("error callback:\n%s", mainOf(page))
	}
	if page := result(url.Values{"state": {start()}, "code": {"not-the-code"}}); checkStatus(page, "Token exchange") != "fail" {
		t.Errorf("bad code:\n%s", mainOf(page))
	}
	if page := result(url.Values{"state": {"made-up"}, "code": {"x"}}); checkStatus(page, "State") != "fail" {
		t.Errorf("unknown state:\n%s", mainOf(page))
	}

	// A secret entered on the app page; and an issuer that can't be reached.
	if resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/secret", url.Values{"client_secret": {"new"}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("secret: %d", resp.StatusCode)
	}
	resp, _ := c.PostForm(ts.URL+"/apps/"+id, url.Values{"issuer": {"http://127.0.0.1:1"}, "client_id": {"client-1"}})
	if body := readBody(resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "The issuer URL is the part before") {
		t.Errorf("unreachable issuer: %d\n%s", resp.StatusCode, mainOf(body))
	}
}
