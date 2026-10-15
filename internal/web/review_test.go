package web

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// An app can exist before its IdP is connected: the values to register come
// first, sign-in waits until the IdP is connected.
func TestAppBeforeIdPConnected(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}})
	_, page := get(t, c, ts.URL+"/apps/"+id+"?done=created")
	for _, want := range []string{"Register SSOBench at your identity provider", ts.URL + "/saml/" + id + "/acs", "Connect your identity provider", "Available once the identity provider is connected"} {
		if !strings.Contains(page, want) {
			t.Errorf("unconnected app page missing %q", want)
		}
	}
	if strings.Contains(page, `action="/apps/`+id+`/signin"`) {
		t.Error("Test sign-in offered before the IdP is connected")
	}
	if _, signin := get(t, c, ts.URL+"/a/"+id); strings.Contains(signin, "Sign in with single sign-on") {
		t.Error("sign-in page offers a sign-in before the IdP is connected")
	}
	// Connect it.
	resp, _ := c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("connect: %d", resp.StatusCode)
	}
	if _, page := get(t, c, ts.URL+"/apps/"+id); !strings.Contains(page, `action="/apps/`+id+`/signin"`) {
		t.Error("Test sign-in missing after connecting")
	}
}

func TestInlineFieldErrors(t *testing.T) {
	ts, c := newTestServer(t, "")
	resp, _ := c.PostForm(ts.URL+"/apps", url.Values{"protocol": {"saml"}, "name": {"X"}, "metadata_xml": {"<nope/>"}})
	body := readBody(resp)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, `class="field-error"`) || !strings.Contains(body, "identity provider metadata. No EntityDescriptor") {
		t.Errorf("no inline error for bad metadata:\n%s", mainOf(body))
	}
	if strings.Contains(body, `class="banner banner-fail"`) {
		t.Error("field error also shown as a page banner")
	}
}

func TestReferencesAndEndedSessions(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	loc := signInVia(t, c, ts.URL, id, "/a/"+id+"/login", ks, "")
	rid := loc[strings.LastIndex(loc, "/")+1:]
	if len(rid) != 12 || strings.ContainsAny(rid, "ILOU01") {
		t.Errorf("reference %q is not 12 unambiguous characters", rid)
	}
	// Found by reference in any case, with dashes, from History.
	typed := strings.ToLower(FormatRef(rid))
	resp, _ := c.Get(ts.URL + "/history?ref=" + url.QueryEscape(typed))
	if resp.Header.Get("Location") != "/result/"+rid {
		t.Errorf("find by %q went to %q", typed, resp.Header.Get("Location"))
	}
	// After sign-out the welcome URL no longer shows the profile.
	c.PostForm(ts.URL+"/a/"+id+"/logout/"+rid, nil)
	resp, _ = c.Get(ts.URL + loc)
	if to := resp.Header.Get("Location"); !strings.HasPrefix(to, "/a/"+id+"/signed-out") {
		t.Errorf("welcome URL after sign-out went to %q, want the signed-out page", to)
	}
}

// The POST-binding hand-off uses the plain layout for people signing in.
func TestPlainHandOffForEndUsers(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	md := strings.Replace(metadataFor(ks, testIdP), "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1)
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {md}})
	resp, _ := c.PostForm(ts.URL+"/a/"+id+"/login", nil)
	body := readBody(resp)
	if !strings.Contains(body, "Taking you to sign in") || strings.Contains(body, `class="topbar"`) {
		t.Errorf("end-user hand-off shows the console:\n%s", mainOf(body))
	}
	resp, _ = c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	if body := readBody(resp); !strings.Contains(body, `class="topbar"`) {
		t.Error("console hand-off lost the console layout")
	}
}

// A failing check marks the value it is about in the data.
func TestFailingValueMarked(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	base := ts.URL + "/saml/" + id
	body, _ := postACS(t, c, base+"/acs", signedResponse(t, ks, testIdP, base+"-other", ""))
	if !strings.Contains(body, `class="row-fail"><dt>Audience</dt>`) {
		t.Error("failing Audience row not marked")
	}
	if !strings.Contains(body, "<dt>Received</dt>") || !strings.Contains(body, "<dt>Expected</dt>") {
		t.Error("no received/expected comparison")
	}
}

// History, the log and replay protection survive a restart.
func TestHistorySurvivesRestart(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	statePath := filepath.Join(t.TempDir(), "state.json")
	ts1, c1 := newTestServer(t, statePath)
	id := createApp(t, c1, ts1.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	c1.PostForm(ts1.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	base := ts1.URL + "/saml/" + id
	resp := signedResponse(t, ks, testIdP, base, "")
	_, resultURL := postACS(t, c1, base+"/acs", resp)
	rid := resultURL[strings.LastIndex(resultURL, "/")+1:]

	ts2, c2 := newTestServer(t, statePath)
	if code, _ := get(t, c2, ts2.URL+"/result/"+rid); code != http.StatusOK {
		t.Error("result lost on restart")
	}
	if _, logPage := get(t, c2, ts2.URL+"/log"); !strings.Contains(logPage, "Payroll") {
		t.Error("log lost on restart")
	}
	if fi, _ := os.Stat(strings.TrimSuffix(statePath, ".json") + "-history.json"); !ownerOnly(fi) {
		t.Error("history file missing or not owner-only")
	}
	// Replaying the same assertion after a restart is still caught.
	c2.PostForm(ts2.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	if body, _ := postACS(t, c2, base+"/acs", resp); !strings.Contains(body, "already used") {
		t.Error("replay not caught after restart")
	}
}

// A forged copy of an assertion, posted first, must not make the real one
// look like a replay.
func TestForgedAssertionDoesNotPoisonReplayCheck(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_xml": {metadataFor(ks, testIdP)}, "idp_landing": {"diagnostics"}})
	base := ts.URL + "/saml/" + id
	real := signedResponse(t, ks, testIdP, base, "")
	xml, _ := base64.StdEncoding.DecodeString(real)
	forged := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(xml), "Engineering", "Executives", 1)))
	if body, _ := postACS(t, c, base+"/acs", forged); !failed(body) {
		t.Fatal("forged response passed")
	}
	if body, _ := postACS(t, c, base+"/acs", real); strings.Contains(body, "already used") {
		t.Error("the forged copy made the real assertion look like a replay")
	}
	if body, _ := postACS(t, c, base+"/acs", real); !strings.Contains(body, "already used") {
		t.Error("real replay not caught")
	}
}

func TestSettingsSaveKeepsAndClearsTheRightThings(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	// Emptying both metadata fields in Settings disconnects the app.
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"metadata_url": {""}, "metadata_xml": {""}})
	if _, page := get(t, c, ts.URL+"/apps/"+id); !strings.Contains(page, "not connected to an identity provider yet") {
		t.Errorf("metadata not cleared:\n%s", mainOf(page))
	}
}

func TestNewerStateFileIsLeftAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	os.WriteFile(path, []byte(`{"version": 99, "apps": []}`), 0o600)
	s, _ := New("", time.Minute, "test")
	s.Quiet, s.StatePath = true, path
	if err := s.LoadState(); err == nil || s.StatePath != "" {
		t.Fatalf("newer state file: %v, still saving to %q", err, s.StatePath)
	}
	s.saveState()
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "99") {
		t.Error("newer state file overwritten")
	}
}

func TestNormalizeRef(t *testing.T) {
	if got := normalizeRef(" abcd-efgh jkmn "); got != "ABCDEFGHJKMN" {
		t.Errorf("%q", got)
	}
}
