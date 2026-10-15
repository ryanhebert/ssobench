package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ryanhebert/ssobench/internal/webauthn/webauthntest"
)

func TestConsolePassword(t *testing.T) {
	failedDelay = 0
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	srv, err := New(ts.URL, time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Quiet, srv.AdminPassword = true, "correct horse"
	ts.Config.Handler = srv.Handler()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// The console asks for the password; open paths do not.
	resp, err := c.Get(ts.URL + "/history?q=x")
	if err != nil {
		t.Fatal(err)
	}
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/console/login?next="+url.QueryEscape("/history?q=x") {
		t.Fatalf("console without a session: %d %q", resp.StatusCode, loc)
	}
	for _, p := range []string{"/assets/app.css", "/console/login", "/saml/nope/metadata", "/a/nope"} {
		if code, _ := get(t, c, ts.URL+p); code == http.StatusSeeOther || code == http.StatusUnauthorized {
			t.Errorf("%s should stay open, got %d", p, code)
		}
	}
	resp, _ = c.PostForm(ts.URL+"/apps", url.Values{"name": {"x"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST without a session: %d", resp.StatusCode)
	}

	// A wrong password is refused; the right one signs in and returns to next.
	resp, _ = c.PostForm(ts.URL+"/console/login", url.Values{"password": {"wrong"}, "next": {"/history"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(ts.URL+"/console/login", url.Values{"password": {"correct horse"}, "next": {"/history"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/history" {
		t.Fatalf("right password: %d %q", resp.StatusCode, loc)
	}
	if code, body := get(t, c, ts.URL+"/"); code != http.StatusOK || !strings.Contains(body, `action="/console/logout"`) {
		t.Errorf("signed in: %d, sign-out button %v", code, strings.Contains(body, "/console/logout"))
	}

	// Signing out ends the session.
	c.PostForm(ts.URL+"/console/logout", nil)
	if code, _ := get(t, c, ts.URL+"/"); code != http.StatusSeeOther {
		t.Errorf("after sign-out: %d", code)
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/apps/x":               "/apps/x",
		"https://evil.example/": "/",
		"//evil.example/":       "/",
		`/\evil.example/`:       "/",
		"/console/logout":       "/",
		"":                      "/",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// consoleServer runs SSOBench at http://localhost:<port>, where passkeys work.
func consoleServer(t *testing.T, statePath string) (*httptest.Server, *Server, string) {
	t.Helper()
	failedDelay, pbkdf2Iterations = 0, 1000
	ts := httptest.NewServer(nil)
	t.Cleanup(ts.Close)
	base := "http://localhost:" + ts.URL[strings.LastIndex(ts.URL, ":")+1:]
	srv, err := New(base, time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Quiet, srv.StatePath = true, statePath
	if err := srv.LoadState(); err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	return ts, srv, base
}

func jarClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func postJSON(t *testing.T, c *http.Client, u string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := c.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestConsoleSignInSettings(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	ts, srv, _ := consoleServer(t, state)
	admin, other := jarClient(), jarClient()

	// Open by default.
	if code, body := get(t, other, ts.URL+"/settings"); code != http.StatusOK || !strings.Contains(body, "Anyone who can open SSOBench") {
		t.Fatalf("settings by default: %d", code)
	}

	// Password rules.
	for _, f := range []url.Values{{"password": {"short"}, "confirm": {"short"}}, {"password": {"long enough"}, "confirm": {"different!"}}} {
		if resp, _ := admin.PostForm(ts.URL+"/settings/password", f); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("bad password %v accepted: %d", f, resp.StatusCode)
		}
	}
	// Setting one keeps this browser signed in and closes the console to others.
	resp, _ := admin.PostForm(ts.URL+"/settings/password", url.Values{"password": {"s3cret pass"}, "confirm": {"s3cret pass"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set password: %d", resp.StatusCode)
	}
	if code, _ := get(t, admin, ts.URL+"/"); code != http.StatusOK {
		t.Errorf("the admin's browser was signed out: %d", code)
	}
	if code, _ := get(t, other, ts.URL+"/"); code != http.StatusSeeOther {
		t.Errorf("another browser got in: %d", code)
	}
	if b, _ := os.ReadFile(state); strings.Contains(string(b), "s3cret") || !strings.Contains(string(b), "pbkdf2-sha256$") {
		t.Errorf("state file should hold a hash, not the password:\n%s", b)
	}

	// Add a passkey (signed in), then sign in with it from another browser.
	pk := webauthntest.New("localhost")
	code, opts := postJSON(t, admin, ts.URL+"/settings/passkeys/options", nil)
	if code != http.StatusOK || opts["rp"].(map[string]any)["id"] != "localhost" {
		t.Fatalf("passkey options: %d %v", code, opts)
	}
	ch, _ := base64.RawURLEncoding.DecodeString(opts["challenge"].(string))
	origin := srv.BaseURL
	cd, att := pk.Create(ch, origin)
	if code, out := postJSON(t, admin, ts.URL+"/settings/passkeys", map[string]string{"name": "Test key", "clientDataJSON": enc(cd), "attestationObject": enc(att)}); code != http.StatusOK {
		t.Fatalf("add passkey: %d %v", code, out)
	}
	// The same challenge can't be used twice.
	if code, _ := postJSON(t, admin, ts.URL+"/settings/passkeys", map[string]string{"clientDataJSON": enc(cd), "attestationObject": enc(att)}); code != http.StatusBadRequest {
		t.Errorf("replayed registration: %d", code)
	}
	if code, body := get(t, other, ts.URL+"/console/login"); code != http.StatusOK || !strings.Contains(body, "data-passkey-login") {
		t.Errorf("sign-in page should offer the passkey: %d", code)
	}
	code, opts = postJSON(t, other, ts.URL+"/console/passkey/options", nil)
	if code != http.StatusOK {
		t.Fatalf("login options: %d %v", code, opts)
	}
	ch, _ = base64.RawURLEncoding.DecodeString(opts["challenge"].(string))
	cd, ad, sig := pk.Get(ch, origin)
	// A wrong signature fails and does not sign in.
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 1
	if code, _ := postJSON(t, other, ts.URL+"/console/passkey", map[string]string{"id": enc(pk.ID), "clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(bad)}); code != http.StatusUnauthorized {
		t.Errorf("bad signature: %d", code)
	}
	code, opts = postJSON(t, other, ts.URL+"/console/passkey/options", nil)
	ch, _ = base64.RawURLEncoding.DecodeString(opts["challenge"].(string))
	cd, ad, sig = pk.Get(ch, origin)
	if code, out := postJSON(t, other, ts.URL+"/console/passkey?next=/history", map[string]string{"id": enc(pk.ID), "clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(sig)}); code != http.StatusOK || out["next"] != "/history" {
		t.Fatalf("passkey sign-in: %d %v", code, out)
	}
	if code, _ := get(t, other, ts.URL+"/history"); code != http.StatusOK {
		t.Errorf("signed in with a passkey, but: %d", code)
	}

	// Kept across a restart.
	ts2, _, _ := consoleServer(t, state)
	if code, _ := get(t, jarClient(), ts2.URL+"/"); code != http.StatusSeeOther {
		t.Errorf("after a restart the console is open: %d", code)
	}

	// Remove both: open again.
	admin.PostForm(ts.URL+"/settings/password/remove", nil)
	if code, _ := get(t, jarClient(), ts.URL+"/"); code != http.StatusSeeOther {
		t.Errorf("a passkey is still there; the console should still ask: %d", code)
	}
	resp, _ = admin.PostForm(ts.URL+"/settings/passkeys/"+enc(pk.ID)+"/delete", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("remove passkey: %d", resp.StatusCode)
	}
	if code, _ := get(t, jarClient(), ts.URL+"/"); code != http.StatusOK {
		t.Errorf("nothing left, but the console still asks: %d", code)
	}
}

func TestResetConsoleAccess(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	ts, srv, _ := consoleServer(t, state)
	jarClient().PostForm(ts.URL+"/settings/password", url.Values{"password": {"s3cret pass"}, "confirm": {"s3cret pass"}})
	if !srv.Protected() || !srv.ResetConsoleAccess() || srv.Protected() {
		t.Fatal("reset did not remove the password")
	}
	_, srv2, _ := consoleServer(t, state)
	if srv2.Protected() {
		t.Error("the reset was not saved")
	}
}

func TestPasskeysNeedAHostName(t *testing.T) {
	srv, _ := New("http://192.0.2.1:8080", time.Minute, "test")
	if _, why := srv.rpID(httptest.NewRequest("GET", "/", nil)); !strings.Contains(why, "host name") {
		t.Errorf("IP address: %q", why)
	}
	srv.BaseURL = "http://bench.example:8080"
	if _, why := srv.rpID(httptest.NewRequest("GET", "/", nil)); !strings.Contains(why, "HTTPS") {
		t.Errorf("plain HTTP: %q", why)
	}
}

func TestPasswordHash(t *testing.T) {
	pbkdf2Iterations = 1000
	h := hashPassword("pässword")
	if !checkPassword(h, "pässword") || checkPassword(h, "password") || checkPassword("garbage", "x") || h == hashPassword("pässword") {
		t.Error("password hashing")
	}
}
