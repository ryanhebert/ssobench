package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/saml"
)

// browser is a client with cookies that doesn't follow redirects.
func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestSessionBelongsToTheBrowser(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, admin := newTestServer(t, "")
	id := createApp(t, admin, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})
	alice := browser()
	welcome := signInVia(t, alice, ts.URL, id, "/a/"+id+"/login", ks, "")
	if _, page := get(t, alice, ts.URL+welcome); !strings.Contains(page, "Welcome, bob") {
		t.Fatal("no welcome screen")
	}
	// Back on the sign-in page, the browser is still signed in.
	if _, page := get(t, alice, ts.URL+"/a/"+id); !strings.Contains(page, "signed in as<br><strong class=\"who-strong\">bob@example.com") || !strings.Contains(page, "Continue") {
		t.Errorf("sign-in page does not show the session:\n%s", mainOf(page))
	}
	// Another browser with the welcome link does not get in.
	if resp, _ := browser().Get(ts.URL + welcome); resp.Header.Get("Location") != "/a/"+id {
		t.Errorf("another browser opened the welcome screen: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The admin sees it, and ends it.
	_, list := get(t, admin, ts.URL+"/apps/"+id+"/sessions")
	if !strings.Contains(list, "bob@example.com") || !strings.Contains(list, "Sign-in page") {
		t.Fatalf("Sessions tab:\n%s", mainOf(list))
	}
	end := list[strings.Index(list, `action="/apps/`+id+`/sessions/`):]
	end = end[len(`action="`) : strings.Index(end[len(`action="`):], `"`)+len(`action="`)]
	admin.PostForm(ts.URL+end, nil)
	resp, _ := alice.Get(ts.URL + welcome)
	if to := resp.Header.Get("Location"); !strings.HasPrefix(to, "/a/"+id+"/signed-out?session=") {
		t.Fatalf("ended session still opens: %q", to)
	}
	if _, page := get(t, alice, ts.URL+resp.Header.Get("Location")); !strings.Contains(page, "an administrator ended it") {
		t.Errorf("signed-out page does not say why:\n%s", mainOf(page))
	}
	if _, list := get(t, admin, ts.URL+"/apps/"+id+"/sessions"); !strings.Contains(list, "Ended recently") || !strings.Contains(list, "Ended by an administrator") {
		t.Error("ended session not listed with its reason")
	}
	// Console tests start no session.
	signInVia(t, admin, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, list := get(t, admin, ts.URL+"/apps/"+id+"/sessions"); !strings.Contains(list, "No one is signed in") {
		t.Error("a console test started a session")
	}
}

func TestIdPLogoutEndsSessions(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, admin := newTestServer(t, "")
	id := createApp(t, admin, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataWithSLO(ks)}})
	enable(t, admin, ts.URL, id, metadataWithSLO(ks), url.Values{"logout": {"1"}})
	alice := browser()
	welcome := signInVia(t, alice, ts.URL, id, "/a/"+id+"/login", ks, "")
	get(t, alice, ts.URL+welcome)

	sp := saml.SP{EntityID: testIdP}
	req, _ := idpRedirect(t, ks, ts.URL+"/saml/"+id+"/slo", "SAMLRequest", saml.LogoutRequest(sp, "_idp1", ts.URL+"/saml/"+id+"/slo", "bob@example.com", "", "", time.Now()), "")
	admin.Get(req)

	resp, _ := alice.Get(ts.URL + welcome)
	if to := resp.Header.Get("Location"); !strings.Contains(to, "/signed-out?session=") {
		t.Fatalf("session survived the IdP's logout request: %q", to)
	}
	if _, page := get(t, alice, ts.URL+resp.Header.Get("Location")); !strings.Contains(page, "your sign-in service ended it") {
		t.Errorf("signed-out page:\n%s", mainOf(page))
	}
}

func TestSessionExpiry(t *testing.T) {
	app := &App{AppConfig: AppConfig{SessionMinutes: 60, IdleMinutes: 15}}
	now := time.Now()
	idle := &Session{Started: now.Add(-30 * time.Minute), LastSeen: now.Add(-20 * time.Minute), Expires: now.Add(30 * time.Minute)}
	checkSessionLocked(app, idle, now)
	if idle.Active() || !strings.Contains(idle.EndedHow, "inactive for 15 minutes") {
		t.Errorf("idle session: active=%v %q", idle.Active(), idle.EndedHow)
	}
	old := &Session{Started: now.Add(-2 * time.Hour), LastSeen: now, Expires: now.Add(-time.Hour), ExpiresWhy: "app"}
	checkSessionLocked(app, old, now)
	if !strings.Contains(old.EndedHow, "1 hour limit") {
		t.Errorf("expired session: %q", old.EndedHow)
	}
	idp := &Session{Started: now.Add(-time.Hour), LastSeen: now, Expires: now.Add(-time.Minute), ExpiresWhy: "idp"}
	checkSessionLocked(app, idp, now)
	if !strings.Contains(idp.EndedHow, "sign-in service's session limit") {
		t.Errorf("IdP-limited session: %q", idp.EndedHow)
	}
}

func TestDeactivationEndsSessions(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ts, admin := newTestServer(t, "")
	id, token := newDirectoryApp(t, admin, ts.URL, ks, url.Values{"jit": {"1"}})
	alice := browser()
	welcome := signInVia(t, alice, ts.URL, id, "/a/"+id+"/login", ks, "")
	get(t, alice, ts.URL+welcome)
	_, m := scimCall(t, "GET", ts.URL+"/scim/"+id+"/v2/Users?filter="+url.QueryEscape(`userName eq "bob@example.com"`), token, "")
	uid := m["Resources"].([]any)[0].(map[string]any)["id"].(string)
	scimCall(t, "PATCH", ts.URL+"/scim/"+id+"/v2/Users/"+uid, token, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	resp, _ := alice.Get(ts.URL + welcome)
	if _, page := get(t, alice, ts.URL+resp.Header.Get("Location")); !strings.Contains(page, "your account was deactivated") {
		t.Errorf("deactivation did not end the session:\n%s", mainOf(page))
	}
	if _, prov := get(t, admin, ts.URL+"/apps/"+id+"/users?view=provisioning"); !strings.Contains(prov, "ended 1 session") {
		t.Error("provisioning activity does not say a session ended")
	}
}

func rs256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	in := enc(map[string]any{"alg": "RS256", "kid": "k1", "typ": "logout+jwt"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestBackchannelLogout(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	ts, admin := newTestServer(t, "")
	id := createApp(t, admin, ts.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"}, "client_secret": {"s3cret"}})
	admin.PostForm(ts.URL+"/apps/"+id, url.Values{"issuer": {idp.URL}, "client_id": {"client-1"}, "optional": {"1"}, "logout": {"1"}})
	if _, setup := get(t, admin, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(setup, ts.URL+"/oidc/"+id+"/backchannel-logout") {
		t.Error("Set up lacks the back-channel logout URI")
	}

	alice := browser()
	resp, _ := alice.PostForm(ts.URL+"/a/"+id+"/login", nil)
	resp, _ = alice.Get(resp.Header.Get("Location"))
	resp, _ = alice.Get(resp.Header.Get("Location"))
	welcome := resp.Header.Get("Location")
	if _, page := get(t, alice, ts.URL+welcome); !strings.Contains(page, "Welcome") {
		t.Fatalf("OIDC welcome:\n%s", mainOf(page))
	}

	post := func(token string) int {
		resp, _ := http.PostForm(ts.URL+"/oidc/"+id+"/backchannel-logout", url.Values{"logout_token": {token}})
		return resp.StatusCode
	}
	claims := func() map[string]any {
		return map[string]any{"iss": idp.URL, "aud": "client-1", "sub": "u1", "iat": time.Now().Unix(), "jti": "j1",
			"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if st := post(rs256(t, other, claims())); st != 400 {
		t.Errorf("token signed with another key: %d", st)
	}
	bad := claims()
	bad["nonce"] = "n"
	if st := post(rs256(t, key, bad)); st != 400 {
		t.Errorf("token with a nonce: %d", st)
	}
	if st := post(rs256(t, key, claims())); st != 200 {
		t.Fatalf("valid logout token: %d", st)
	}
	resp, _ = alice.Get(ts.URL + welcome)
	if !strings.Contains(resp.Header.Get("Location"), "/signed-out?session=") {
		t.Errorf("session survived back-channel logout: %q", resp.Header.Get("Location"))
	}
}

// Ending sessions for removed accounts must not trip over the pruning of
// old ended sessions, which shortens the list being walked.
func TestEndForAccountsWithManyEndedSessions(t *testing.T) {
	s, _ := New("", time.Minute, "test")
	now := time.Now()
	app := &App{}
	for i := range maxEndedKept + 1 {
		app.Sessions = append(app.Sessions, &Session{ID: fmt.Sprint("old", i), Account: "gone", Ended: now.Add(-time.Duration(i+1) * time.Minute), EndedHow: EndSignedOut, Expires: now.Add(time.Hour)})
	}
	for _, id := range []string{"a", "b"} {
		app.Sessions = append(app.Sessions, &Session{ID: id, Account: "gone", Started: now, LastSeen: now, Expires: now.Add(time.Hour)})
	}
	s.mu.Lock()
	n := s.endForAccountsLocked(app)
	s.mu.Unlock()
	if n != 2 {
		t.Errorf("ended %d sessions, want 2", n)
	}
	for _, x := range app.Sessions {
		if x == nil || x.Active() {
			t.Fatalf("sessions after: %+v", x)
		}
	}
}
