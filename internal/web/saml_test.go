package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

// TestSAMLEndToEnd: create an app, sign in (SP-initiated), post the signed
// response to the app's ACS URL, and read the result.
func TestSAMLEndToEnd(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Staging portal"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	if !regexp.MustCompile(`^[a-z2-7]{16}$`).MatchString(id) {
		t.Errorf("app ID %q is not a random 16-character ID", id)
	}

	resp, err := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	if err != nil || resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "https://idp.example/sso?") {
		t.Fatalf("sign in: %v %d %s", err, resp.StatusCode, resp.Header.Get("Location"))
	}
	reqXML, err := saml.DecodeMessage(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	reqID := regexp.MustCompile(` ID="([^"]+)"`).FindStringSubmatch(string(reqXML))[1]
	loc, _ := url.Parse(resp.Header.Get("Location"))
	relay := loc.Query().Get("RelayState")
	if relay == "" {
		t.Error("AuthnRequest sent without a RelayState")
	}
	if !strings.Contains(string(reqXML), ts.URL+"/saml/"+id+"/acs") {
		t.Error("AuthnRequest does not carry the app's ACS URL")
	}

	spBase := ts.URL + "/saml/" + id
	body, resultURL := postACS(t, c, spBase+"/acs", signedResponse(t, ks, testIdP, spBase, reqID), relay)
	if failed(body) || !strings.Contains(body, "returned unchanged") {
		t.Fatalf("unexpected failure:\n%s", mainOf(body))
	}
	for _, want := range []string{"Signed in", "bob@example.com", "Engineering &amp; Ops", "department", "Staging portal", "verified with metadata certificate"} {
		if !strings.Contains(body, want) {
			t.Errorf("result page missing %q", want)
		}
	}

	// Every page renders.
	for _, u := range []string{"/", "/apps/new", "/apps/new?protocol=oidc", "/apps/" + id, "/apps/" + id + "?done=created", "/history", "/log", "/decode", "/saml/" + id + "/metadata"} {
		if code, body := get(t, c, ts.URL+u); code != 200 || (!strings.Contains(body, "</html>") && !strings.Contains(u, "metadata")) {
			t.Errorf("GET %s: %d", u, code)
		}
	}
	if _, txt := get(t, c, resultURL+"/log.txt"); !strings.Contains(txt, reqID) {
		t.Error("log.txt lacks the request ID")
	}

	// Posting the same response again is a replay.
	if body, _ := postACS(t, c, spBase+"/acs", signedResponse(t, ks, testIdP, spBase, reqID)); !strings.Contains(body, "InResponseTo") {
		t.Error("second response with the same request ID not flagged")
	}
}

// Each app verifies responses against its own metadata, also for
// IdP-initiated sign-ins.
func TestTwoAppsKeepTheirOwnMetadata(t *testing.T) {
	ksA, ksB := dsig.RandomKeyStoreForTest(), dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	a := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"App A"}, "metadata_xml": {metadataFor(ksA, "https://idp.example/a")}})
	b := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"App B"}, "metadata_xml": {metadataFor(ksB, "https://idp.example/b")}})

	for _, tc := range []struct {
		app, issuer string
		ks          dsig.X509KeyStore
	}{{a, "https://idp.example/a", ksA}, {b, "https://idp.example/b", ksB}} {
		base := ts.URL + "/saml/" + tc.app
		body, _ := postACS(t, c, base+"/acs", signedResponse(t, tc.ks, tc.issuer, base, ""))
		if failed(body) || !strings.Contains(body, "IdP-initiated") {
			t.Errorf("%s: IdP-initiated sign-in not verified:\n%s", tc.app, mainOf(body))
		}
	}
	// B's response posted to A's URL is checked against A's metadata, and fails.
	baseA := ts.URL + "/saml/" + a
	if body, _ := postACS(t, c, baseA+"/acs", signedResponse(t, ksB, "https://idp.example/b", baseA, "")); !failed(body) {
		t.Error("response from another IdP accepted")
	}
}

// IdP-initiated sign-ins verify straight after a restart, from the saved
// metadata, even when the metadata URL is gone.
func TestIdPInitiatedAfterRestart(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	mdSrv := httptest.NewServer(&mdServer{md: metadataFor(ks, testIdP)})
	statePath := filepath.Join(t.TempDir(), "state.json")

	ts1, c1 := newTestServer(t, statePath)
	id := createApp(t, c1, ts1.URL, url.Values{"protocol": {"saml"}, "metadata_url": {mdSrv.URL}})
	if fi, _ := os.Stat(statePath); fi == nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state file missing or not owner-only: %v", fi)
	}
	mdSrv.Close()

	ts2, c2 := newTestServer(t, statePath)
	base := ts2.URL + "/saml/" + id
	body, _ := postACS(t, c2, base+"/acs", signedResponse(t, ks, testIdP, base, ""))
	if failed(body) {
		t.Fatalf("IdP-initiated sign-in failed after restart:\n%s", mainOf(body))
	}
	for _, want := range []string{"Signed in with 1 warning", "IdP-initiated", "bob@example.com", "https://app.example/landing"} {
		if !strings.Contains(body, want) {
			t.Errorf("result missing %q", want)
		}
	}
}

func TestSigningCertRolloverRefreshesMetadata(t *testing.T) {
	oldKey, newKey := dsig.RandomKeyStoreForTest(), dsig.RandomKeyStoreForTest()
	md := &mdServer{md: metadataFor(oldKey, testIdP)}
	mdSrv := httptest.NewServer(md)
	defer mdSrv.Close()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "metadata_url": {mdSrv.URL}})

	md.set(metadataFor(newKey, testIdP)) // the IdP rolls over
	base := ts.URL + "/saml/" + id
	body, _ := postACS(t, c, base+"/acs", signedResponse(t, newKey, testIdP, base, ""))
	if failed(body) || !strings.Contains(body, "Metadata refresh") {
		t.Fatalf("rollover not handled:\n%s", mainOf(body))
	}
	if _, logTxt := get(t, c, ts.URL+"/log.txt"); !strings.Contains(logTxt, "reloading") {
		t.Error("refresh not logged")
	}
}

// A version 1 state file (one SAML configuration) becomes a legacy app that
// answers on the original URLs, so an existing IdP registration keeps working.
func TestV1StateMigratesToLegacyApp(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	statePath := filepath.Join(t.TempDir(), "state.json")
	v1 := `{"version":1,"saml":{"metadata_url":"https://idp.example/md","metadata_xml":` + jsonString(metadataFor(ks, testIdP)) + `,"loaded_at":"2026-10-14T12:00:00Z"},"oidc":{}}`
	os.WriteFile(statePath, []byte(v1), 0o600)

	ts, c := newTestServer(t, statePath)
	if _, md := get(t, c, ts.URL+"/saml/metadata"); !strings.Contains(md, `entityID="`+ts.URL+`/saml/metadata"`) {
		t.Errorf("legacy metadata URL: %s", md)
	}
	base := ts.URL + "/saml"
	body, _ := postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base, ""))
	if failed(body) || !strings.Contains(body, "SAML app") {
		t.Fatalf("legacy ACS URL did not verify:\n%s", mainOf(body))
	}
	if saved, _ := os.ReadFile(statePath); !strings.Contains(string(saved), `"version": 2`) {
		t.Error("state not upgraded to version 2")
	}
}

func TestDeleteApp(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	statePath := filepath.Join(t.TempDir(), "state.json")
	ts, c := newTestServer(t, statePath)
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Old app"}, "metadata_xml": {metadataFor(ks, testIdP)}})

	// Without confirming, delete only asks.
	resp, _ := c.PostForm(ts.URL+"/apps/"+id+"/delete", nil)
	if loc := resp.Header.Get("Location"); loc != "/apps/"+id+"/delete" {
		t.Fatalf("unconfirmed delete went to %q", loc)
	}
	if _, confirm := get(t, c, ts.URL+"/apps/"+id+"/delete"); !strings.Contains(confirm, "Delete Old app?") {
		t.Error("no confirmation page")
	}
	if code, _ := get(t, c, ts.URL+"/apps/"+id); code != http.StatusOK {
		t.Fatal("app gone before confirming")
	}
	resp, err := c.PostForm(ts.URL+"/apps/"+id+"/delete", url.Values{"confirm": {"1"}})
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %v %d", err, resp.StatusCode)
	}
	if _, page := get(t, c, ts.URL+resp.Header.Get("Location")); !strings.Contains(page, "Deleted Old app") || strings.Contains(page, `href="/apps/`+id+`"`) {
		t.Error("app still listed, or no confirmation")
	}
	ts2, c2 := newTestServer(t, statePath)
	if code, _ := get(t, c2, ts2.URL+"/apps/"+id); code != http.StatusNotFound {
		t.Error("deleted app came back after restart")
	}
	base := ts2.URL + "/saml/" + id
	if body, _ := postACS(t, c2, base+"/acs", signedResponse(t, ks, testIdP, base, "")); !strings.Contains(body, "no app in SSOBench matches") {
		t.Error("response for a deleted app was not refused")
	}
}

func TestCreateAppErrors(t *testing.T) {
	ts, c := newTestServer(t, "")
	resp, _ := c.PostForm(ts.URL+"/apps", url.Values{"protocol": {"saml"}, "name": {"Keep me"}, "metadata_xml": {"<not-metadata/>"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad metadata accepted: %d", resp.StatusCode)
	}
	if _, page := get(t, c, ts.URL+"/"); strings.Contains(page, "Keep me") {
		t.Error("app created despite the error")
	}
}

func TestCrossOriginPostBlocked(t *testing.T) {
	srv, _ := New("http://localhost:8080", 0, "test")
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/apps", strings.NewReader("protocol=saml"))
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestNullOriginAndRebindingBlocked(t *testing.T) {
	srv, _ := New("", 0, "test")
	srv.AllowedHosts = []string{"sso-test.example.com", "localhost"}
	h := srv.Handler()
	try := func(host, origin, site string) int {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/apps", strings.NewReader("protocol=saml"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := try("localhost:8080", "null", "cross-site"); c != http.StatusForbidden {
		t.Errorf("Origin null from another site: %d, want 403", c)
	}
	// SSOBench's own forms: no-referrer makes browsers send Origin null.
	if c := try("localhost:8080", "null", "same-origin"); c == http.StatusForbidden {
		t.Errorf("own form with Origin null blocked: %d", c)
	}
	if c := try("localhost:8080", "", "cross-site"); c != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site cross-site: %d, want 403", c)
	}
	if c := try("rebind.attacker.example:8080", "http://rebind.attacker.example:8080", ""); c != http.StatusMisdirectedRequest {
		t.Errorf("rebinding host: %d, want 421", c)
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "sso-test.example.com", "[::1]:8080"} {
		if c := try(host, "http://"+host, "same-origin"); c == http.StatusForbidden || c == http.StatusMisdirectedRequest {
			t.Errorf("same-origin POST at %s blocked: %d", host, c)
		}
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// Neither protocol is preselected: New app asks first.
// Each app gets its own random ID, unrelated to its name, and renaming the
// app does not change its URLs.
func TestAppIDsAreRandomAndStable(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	form := url.Values{"protocol": {"saml"}, "name": {"Same name"}, "metadata_xml": {metadataFor(ks, testIdP)}}
	a, b := createApp(t, c, ts.URL, form), createApp(t, c, ts.URL, form)
	if a == b {
		t.Fatal("two apps share an ID")
	}
	for _, id := range []string{a, b} {
		if strings.Contains(id, "same") {
			t.Errorf("ID %q is derived from the name", id)
		}
	}
	c.PostForm(ts.URL+"/apps/"+a, url.Values{"name": {"Renamed"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	if _, md := get(t, c, ts.URL+"/saml/"+a+"/metadata"); !strings.Contains(md, `/saml/`+a+`/metadata"`) {
		t.Error("renaming changed the app's URLs")
	}
	if _, p := get(t, c, ts.URL+"/apps/"+a); !strings.Contains(p, "Renamed") {
		t.Error("rename not applied")
	}
}

func TestNewAppAsksForProtocol(t *testing.T) {
	ts, c := newTestServer(t, "")
	_, page := get(t, c, ts.URL+"/apps/new")
	if !strings.Contains(page, `href="/apps/new?protocol=saml"`) || !strings.Contains(page, `href="/apps/new?protocol=oidc"`) {
		t.Error("choice step missing")
	}
	if strings.Contains(page, `name="metadata_url"`) || strings.Contains(page, `name="issuer"`) {
		t.Error("a protocol form is shown before a choice is made")
	}
	for proto, field := range map[string]string{"saml": `name="metadata_url"`, "oidc": `name="issuer"`} {
		if _, p := get(t, c, ts.URL+"/apps/new?protocol="+proto); !strings.Contains(p, field) {
			t.Errorf("%s form missing %s", proto, field)
		}
	}
	if _, home := get(t, c, ts.URL+"/"); !strings.Contains(home, `href="/apps/new"`) || strings.Contains(home, "New SAML app") {
		t.Error("empty state still favours one protocol")
	}
}
