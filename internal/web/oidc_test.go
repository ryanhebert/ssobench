package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeIdP is a tiny OpenID provider: discovery, authorize (auto-approves),
// token, JWKS and userinfo.
// Knobs for the fake provider. Tests do not run in parallel.
var (
	fakeClaims     map[string]any // extra ID token claims
	fakeTokenScope string         // the scope in the token response
	fakeAuthorize  url.Values     // the last authorize request
)

func fakeIdP(t *testing.T, key *rsa.PrivateKey, clientID string) *httptest.Server {
	var srv *httptest.Server
	var nonce, challenge string
	b64 := base64.RawURLEncoding.EncodeToString
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"userinfo_endpoint": srv.URL + "/userinfo", "jwks_uri": srv.URL + "/jwks", "end_session_endpoint": srv.URL + "/logout",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		fakeAuthorize = q
		nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=thecode&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "thecode" || b64(sum[:]) != challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1"})
		claims := map[string]any{"iss": srv.URL, "aud": clientID, "sub": "u1", "email": "alice@example.com",
			"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
		for k, v := range fakeClaims {
			claims[k] = v
		}
		cl, _ := json.Marshal(claims)
		in := b64(hdr) + "." + b64(cl)
		d := sha256.Sum256([]byte(in))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
		tr := map[string]any{"id_token": in + "." + b64(sig), "access_token": "opaque-at", "token_type": "Bearer"}
		if fakeTokenScope != "" {
			tr["scope"] = fakeTokenScope
		}
		json.NewEncoder(w).Encode(tr)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer opaque-at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"sub": "u1", "email": "alice@example.com"})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("id_token_hint") == "" {
			http.Error(w, "missing id_token_hint", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, q.Get("post_logout_redirect_uri")+"?state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	srv = httptest.NewServer(mux)
	return srv
}

func TestOIDCEndToEnd(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")
	ts, c := newTestServer(t, statePath)

	id := createApp(t, c, ts.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"},
		"client_secret": {"s3cret-value"}, "scopes": {"openid email"}})
	if _, page := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(page, ts.URL+"/oidc/"+id+"/callback") {
		t.Error("app page does not show the app's redirect URI")
	}

	resp, err := c.PostForm(ts.URL+"/apps/"+id+"/signin", nil)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("sign in: %v %v", err, resp.StatusCode)
	}
	// Follow the browser: authorize -> callback -> result.
	resp, _ = c.Get(resp.Header.Get("Location"))
	resp, _ = c.Get(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	res := ts.URL + resp.Header.Get("Location")
	_, body := get(t, c, res)
	for _, want := range []string{"Signed in", "alice@example.com", "UserInfo"} {
		if !strings.Contains(body, want) {
			t.Errorf("result missing %q", want)
		}
	}
	_, txt := get(t, c, res+"/log.txt")
	for _, want := range []string{"Discovery", "Token exchange", "client_secret_basic", "JWKS", "Signed in"} {
		if !strings.Contains(txt, want) {
			t.Errorf("log missing %q", want)
		}
	}
	// The client secret appears nowhere: pages, log, state file.
	_, appPage := get(t, c, ts.URL+"/apps/"+id)
	_, home := get(t, c, ts.URL+"/")
	saved, _ := os.ReadFile(statePath)
	for name, s := range map[string]string{"result": body, "log": txt, "app page": appPage, "home": home, "state file": string(saved)} {
		if strings.Contains(s, "s3cret-value") {
			t.Errorf("client secret leaked into the %s", name)
		}
	}

	// Sign-out at the provider, from Test sign-out on the result page.
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"issuer": {idp.URL}, "client_id": {"client-1"}, "optional": {"1"}, "logout": {"1"}})
	rid := res[strings.LastIndex(res, "/")+1:]
	resp, _ = c.PostForm(ts.URL+"/apps/"+id+"/logout/"+rid, nil)
	resp, _ = c.Get(resp.Header.Get("Location")) // provider end_session_endpoint
	resp, _ = c.Get(resp.Header.Get("Location")) // back to the post-logout redirect URI
	if resp.Header.Get("Location") != "/log" {
		t.Errorf("Test sign-out landed at %q", resp.Header.Get("Location"))
	}
	if _, logTxt := get(t, c, ts.URL+"/log.txt"); !strings.Contains(logTxt, "signed out at the provider") {
		t.Error("provider sign-out not logged")
	}

	// Forgetting the secret from settings.
	c.PostForm(ts.URL+"/apps/"+id, url.Values{"issuer": {idp.URL}, "client_id": {"client-1"}, "clear_secret": {"1"}})
	if _, p := get(t, c, ts.URL+"/apps/"+id); strings.Contains(p, "Set for this session") {
		t.Error("secret not cleared")
	}
}

// After a restart the in-memory secret is gone; the failure says so.
func TestMissingSecretExplained(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")
	ts1, c1 := newTestServer(t, statePath)
	id := createApp(t, c1, ts1.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"}, "client_secret": {"s3cret-value"}})
	ts2, c2 := newTestServer(t, statePath) // a restart: the secret is gone
	if _, page := get(t, c2, ts2.URL+"/apps/"+id); !strings.Contains(page, "Enter the client secret to test") {
		t.Error("app page does not say the secret is missing")
	}
	if !strings.Contains(noSecretFix, "cleared whenever SSOBench restarts") || !clientCredentialError(`HTTP 401: {"error": "invalid_request", "error_description": "Invalid client credential in request"}`) {
		t.Error("client credential errors not recognized")
	}
}

// Keeping the secret is opt-in: saved across restarts, never displayed.
func TestKeepSecretOptIn(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := fakeIdP(t, key, "client-1")
	defer idp.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")
	ts1, c1 := newTestServer(t, statePath)
	id := createApp(t, c1, ts1.URL, url.Values{"protocol": {"oidc"}, "issuer": {idp.URL}, "client_id": {"client-1"},
		"client_secret": {"kept-s3cret"}, "keep_secret": {"1"}})
	if saved, _ := os.ReadFile(statePath); !strings.Contains(string(saved), "kept-s3cret") {
		t.Fatal("secret not saved although Keep was ticked")
	}
	ts2, c2 := newTestServer(t, statePath)
	_, page := get(t, c2, ts2.URL+"/apps/"+id)
	_, settings := get(t, c2, ts2.URL+"/apps/"+id+"/settings")
	if strings.Contains(page, "Enter the client secret to test") || !strings.Contains(settings, "Leave empty to keep the current secret") {
		t.Error("kept secret not restored after restart")
	}
	if strings.Contains(page, "kept-s3cret") {
		t.Error("secret shown on the page")
	}
	// Turning it off removes it from the file.
	c2.PostForm(ts2.URL+"/apps/"+id, url.Values{"issuer": {idp.URL}, "client_id": {"client-1"}})
	if saved, _ := os.ReadFile(statePath); strings.Contains(string(saved), "kept-s3cret") {
		t.Error("secret still saved after unticking Keep")
	}
}
