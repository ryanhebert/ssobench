package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

// do sends a request with a given Host header through h.
func do(h http.Handler, method, target, host string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestURLsFollowTheBrowserAddress(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	srv, err := New("", time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Quiet = true
	h := srv.Handler()
	id := createVia(t, h, "a.example.test", ks)
	for _, host := range []string{"dc1.example.test:9444", "10.0.0.5:9444"} {
		body := do(h, http.MethodGet, "/saml/"+id+"/metadata", host, nil).Body.String()
		if want := `entityID="http://` + host + `/saml/` + id + `/metadata"`; !strings.Contains(body, want) {
			t.Errorf("%s: metadata lacks %s", host, want)
		}
	}
	// Opening the app page by IP address shows the hint; by name it does not.
	for host, want := range map[string]bool{"10.0.0.5:9444": true, "dc1.example.test:9444": false} {
		got := strings.Contains(do(h, http.MethodGet, "/apps/"+id+"/setup", host, nil).Body.String(), "opened SSOBench by IP address")
		if got != want {
			t.Errorf("%s: IP hint shown=%v, want %v", host, got, want)
		}
	}
	// A pinned base URL wins over the Host header.
	pinned, _ := New("https://sso.example.com", time.Minute, "test")
	pinned.Quiet = true
	pid := createVia(t, pinned.Handler(), "x", ks)
	if !strings.Contains(do(pinned.Handler(), http.MethodGet, "/saml/"+pid+"/metadata", "10.0.0.5", nil).Body.String(), `entityID="https://sso.example.com/saml/`+pid+`/metadata"`) {
		t.Error("pinned base URL ignored")
	}
}

// A sign-in started at one address while the IdP (registered with another)
// posts back there: reported, and SSOBench's identity at either address passes.
func TestSignInAddressMismatch(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	srv, err := New("", time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Quiet = true
	h := srv.Handler()
	app := createVia(t, h, "a.example.test", ks)

	rec := do(h, http.MethodPost, "/apps/"+app+"/signin", "a.example.test", url.Values{})
	reqXML, err := saml.DecodeMessage(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.SplitN(strings.SplitN(string(reqXML), ` ID="`, 2)[1], `"`, 2)[0]

	resp := signedResponse(t, ks, testIdP, "http://b.example.test/saml/"+app, id)
	rec = do(h, http.MethodPost, "/saml/"+app+"/acs", "b.example.test", url.Values{"SAMLResponse": {resp}})
	body := do(h, http.MethodGet, rec.Header().Get("Location"), "b.example.test", nil).Body.String()
	if !strings.Contains(body, "Sign-in address") || !strings.Contains(body, "http://b.example.test/saml/"+app+"/acs") {
		t.Error("address mismatch not reported")
	}
	if failed(body) {
		t.Errorf("address mismatch caused a failure:\n%s", mainOf(body))
	}
}

// createVia creates a SAML app through h and returns its ID.
func createVia(t *testing.T, h http.Handler, host string, ks dsig.X509KeyStore) string {
	t.Helper()
	rec := do(h, http.MethodPost, "/apps", host, url.Values{"protocol": {"saml"}, "name": {"Web"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/apps/") {
		t.Fatalf("create: %d %q", rec.Code, loc)
	}
	return strings.TrimSuffix(strings.TrimPrefix(loc, "/apps/"), "?done=created")
}
