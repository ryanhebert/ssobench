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
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAS is an OAuth 2.1 authorization server. Each lax* switch breaks one
// rule, so tests can check that SSOBench notices.
type fakeAS struct {
	*httptest.Server
	key            *rsa.PrivateKey
	clientID       string
	secret         string
	redirect       string
	mu             sync.Mutex
	codes          map[string]*asCode
	refresh        map[string]bool // live refresh tokens
	access         map[string]bool
	laxRedirect    bool // accept any redirect URI with the registered prefix
	laxCodeReuse   bool // codes can be redeemed twice
	laxPKCE        bool // no PKCE required, verifier unchecked
	noRotation     bool // refresh tokens are not rotated
	tokenEndpoint5 bool // the token endpoint answers 503 to everything
	advertisePlain bool // the metadata lists the plain PKCE method
	oidcHybrid     bool // OpenID Connect code id_token is offered and accepted, as OAuth 2.1 allows
	laxCodeToken   bool // response_type=code token is accepted, which OAuth 2.1 removes
}

type asCode struct {
	challenge, resource, scope string
	used                       bool
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newFakeAS(t *testing.T, clientID, secret string) *fakeAS {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	as := &fakeAS{key: key, clientID: clientID, secret: secret, codes: map[string]*asCode{}, refresh: map[string]bool{}, access: map[string]bool{}}
	mux := http.NewServeMux()
	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)
	iss := as.URL
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		methods := []string{"S256"}
		if as.advertisePlain {
			methods = append(methods, "plain")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "introspection_endpoint": iss + "/introspect",
			"response_types_supported": responseTypes(as), "code_challenge_methods_supported": methods,
			"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64u(key.N.Bytes()), "e": b64u(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/authorize", as.authorize)
	mux.HandleFunc("/token", as.token)
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		active := as.access[r.FormValue("token")]
		as.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"active": active})
	})
	return as
}

func responseTypes(as *fakeAS) []string {
	rts := []string{"code"}
	if as.oidcHybrid {
		rts = append(rts, "code id_token")
	}
	if as.laxCodeToken {
		rts = append(rts, "code token")
	}
	return rts
}

func (as *fakeAS) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ru := q.Get("redirect_uri")
	if q.Get("client_id") != as.clientID || !(ru == as.redirect || as.laxRedirect && strings.HasPrefix(ru, as.redirect)) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	back := func(v url.Values) {
		v.Set("state", q.Get("state"))
		v.Set("iss", as.URL)
		http.Redirect(w, r, ru+"?"+v.Encode(), http.StatusFound)
	}
	if rt := q.Get("response_type"); rt != "code" && !(rt == "code id_token" && as.oidcHybrid) && !(rt == "code token" && as.laxCodeToken) {
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	}
	if !as.laxPKCE && (q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256") {
		back(url.Values{"error": {"invalid_request"}, "error_description": {"PKCE S256 is required"}})
		return
	}
	code := b64u([]byte(time.Now().String()))[:20]
	as.mu.Lock()
	as.codes[code] = &asCode{challenge: q.Get("code_challenge"), resource: q.Get("resource"), scope: q.Get("scope")}
	as.mu.Unlock()
	back(url.Values{"code": {code}})
}

func (as *fakeAS) jwt(sub, aud, scope string) string {
	h := b64u([]byte(`{"alg":"RS256","kid":"k1","typ":"at+jwt"}`))
	now := time.Now()
	c, _ := json.Marshal(map[string]any{"iss": as.URL, "sub": sub, "aud": aud, "scope": scope, "client_id": as.clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": b64u([]byte(now.String()))})
	in := h + "." + b64u(c)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, as.key, crypto.SHA256, sum[:])
	return in + "." + b64u(sig)
}

func (as *fakeAS) token(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": code})
	}
	if as.tokenEndpoint5 {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	id, sec, ok := r.BasicAuth()
	if !ok {
		id, sec = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	if id != as.clientID || sec != as.secret {
		fail(401, "invalid_client")
		return
	}
	issue := func(sub, aud, scope string, withRefresh bool) {
		if aud == "" {
			aud = as.clientID
		}
		at := as.jwt(sub, aud, scope)
		resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "scope": scope}
		as.mu.Lock()
		as.access[at] = true
		if withRefresh {
			rt := b64u([]byte("rt" + time.Now().String()))
			as.refresh[rt] = true
			resp["refresh_token"] = rt
		}
		as.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		as.mu.Lock()
		c := as.codes[r.FormValue("code")]
		bad := c == nil || (c.used && !as.laxCodeReuse)
		if !bad && !as.laxPKCE {
			sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
			bad = b64u(sum[:]) != c.challenge
		}
		if c != nil && !bad {
			c.used = true
		}
		as.mu.Unlock()
		if bad {
			fail(400, "invalid_grant")
			return
		}
		issue("alice", c.resource, c.scope, strings.Contains(c.scope, "offline_access"))
	case "refresh_token":
		rt := r.FormValue("refresh_token")
		as.mu.Lock()
		live := as.refresh[rt]
		if live && !as.noRotation {
			delete(as.refresh, rt)
		}
		as.mu.Unlock()
		if !live {
			fail(400, "invalid_grant")
			return
		}
		if as.noRotation {
			at := as.jwt("alice", as.clientID, "offline_access")
			as.mu.Lock()
			as.access[at] = true
			as.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": rt})
			return
		}
		issue("alice", as.clientID, "offline_access", true)
	case "client_credentials":
		issue(as.clientID, r.FormValue("resource"), r.FormValue("scope"), false)
	default:
		fail(400, "unsupported_grant_type")
	}
}

// oauthStep follows one redirect hop with c and returns the next Location.
func oauthStep(t *testing.T, c *http.Client, method, u string) string {
	t.Helper()
	var resp *http.Response
	var err error
	if method == "POST" {
		resp, err = c.PostForm(u, nil)
	} else {
		resp, err = c.Get(u)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Header.Get("Location")
}

// runOAuth starts at path, lets the fake server answer, and returns the
// page SSOBench lands on.
func runOAuth(t *testing.T, c *http.Client, base, path string) (string, string) {
	t.Helper()
	authz := oauthStep(t, c, "POST", base+path)
	if !strings.Contains(authz, "/authorize?") {
		t.Fatalf("%s did not go to the authorization endpoint: %q", path, authz)
	}
	cb := oauthStep(t, c, "GET", authz)
	land := oauthStep(t, c, "GET", cb)
	_, page := get(t, c, base+land)
	return land, page
}

func newOAuthApp(t *testing.T, c *http.Client, base string, as *fakeAS) string {
	t.Helper()
	id := createApp(t, c, base, url.Values{"protocol": {"oauth"}, "name": {"Orders API"}, "issuer": {as.URL}, "client_id": {as.clientID},
		"client_secret": {as.secret}, "scopes": {"offline_access orders.read"}, "resource": {"https://api.example.com"}, "machine_scopes": {"orders.read"}})
	as.redirect = base + "/oauth/" + id + "/callback"
	return id
}

func checkLine(page, name string) string {
	i := strings.Index(page, "<strong>"+name+"</strong>")
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(page[:i], `class="check c-`)
	return page[start+len(`class="check c-`) : start+len(`class="check c-`)+4]
}

func TestOAuthAppEndToEnd(t *testing.T) {
	ts, c := newTestServer(t, "")
	as := newFakeAS(t, "orders-client", "s3cret")
	id := newOAuthApp(t, c, ts.URL, as)

	_, app := get(t, c, ts.URL+"/apps/"+id)
	for _, want := range []string{"OAuth 2.1 app", "Other tests", "Machine token", "OAuth 2.1 conformance", "Wrong PKCE verifier", "Introspection endpoint"} {
		if !strings.Contains(app, want) {
			t.Errorf("app page missing %q", want)
		}
	}
	if _, setup := get(t, c, ts.URL+"/apps/"+id+"/setup"); !strings.Contains(setup, ts.URL+"/oauth/"+id+"/callback") {
		t.Error("Set up lacks the redirect URI")
	}

	land, page := runOAuth(t, c, ts.URL, "/apps/"+id+"/signin")
	if !strings.HasPrefix(land, "/result/") || failed(page) {
		t.Fatalf("sign-in landed at %s, failed=%v\n%s", land, failed(page), mainOf(page))
	}
	for name, want := range map[string]string{"Access token signature": "pass", "Access token audience": "pass", "Code single use": "pass",
		"Refresh token rotation": "pass", "Introspection": "pass", "Issuer in the response (RFC 9207)": "pass"} {
		if got := checkLine(page, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}

	// End-user view.
	_, page = runOAuth(t, c, ts.URL, "/a/"+id+"/login")
	if !strings.Contains(page, "Access granted") || !strings.Contains(page, `<span class="tag">orders.read</span>`) {
		t.Errorf("welcome screen for OAuth:\n%s", mainOf(page))
	}

	// Machine token.
	loc := oauthStep(t, c, "POST", ts.URL+"/apps/"+id+"/machine")
	if _, page = get(t, c, ts.URL+loc); failed(page) || checkLine(page, "Client credentials") != "pass" {
		t.Errorf("machine token:\n%s", mainOf(page))
	}
	if !strings.Contains(page, `action="/apps/`+id+`/machine"`) || !strings.Contains(page, "Run again") || strings.Contains(page, "Signed in") {
		t.Error("machine token result: rerun should get another token, and nothing should say Signed in")
	}

	// Conformance, against a server that follows the rules. OpenID Connect's
	// code id_token is allowed: it returns no access token.
	as.oidcHybrid = true
	loc = oauthStep(t, c, "POST", ts.URL+"/apps/"+id+"/conformance")
	_, page = get(t, c, ts.URL+loc)
	if failed(page) {
		t.Errorf("conformance failed against a conforming server:\n%s", mainOf(page))
	}
	if !strings.Contains(page, "All tested OAuth 2.1 rules met") || strings.Contains(page, "No user was signed in") {
		t.Error("conformance headline wrong")
	}
	for _, name := range []string{"PKCE required", "Implicit flow removed", "Hybrid flow with an access token removed", "Exact redirect URI match (trailing slash)", "Exact redirect URI match (another host)", "Password grant removed"} {
		if got := checkLine(page, name); got != "pass" {
			t.Errorf("conformance %s: %q, want pass", name, got)
		}
	}
	if got := checkLine(page, "Advertised response types"); got != "" {
		t.Errorf("code id_token advertised: %q, want no finding", got)
	}
	as.oidcHybrid = false

	// Guided checks.
	if _, page = runOAuth(t, c, ts.URL, "/apps/"+id+"/check/wrongverifier"); !strings.Contains(page, "Refused, as it should be") || !strings.Contains(page, "Run again") {
		t.Error("guided check headline or rerun label wrong")
	}
	if _, page = runOAuth(t, c, ts.URL, "/apps/"+id+"/check/wrongverifier"); checkLine(page, "PKCE verifier binding") != "pass" {
		t.Errorf("wrong verifier check:\n%s", mainOf(page))
	}
	cb := oauthStep(t, c, "GET", oauthStep(t, c, "POST", ts.URL+"/apps/"+id+"/check/nopkce"))
	_, page = get(t, c, ts.URL+oauthStep(t, c, "GET", cb))
	if checkLine(page, "PKCE required") != "pass" {
		t.Errorf("no-PKCE check:\n%s", mainOf(page))
	}
}

func TestOAuthCatchesLaxServers(t *testing.T) {
	ts, c := newTestServer(t, "")
	as := newFakeAS(t, "orders-client", "s3cret")
	id := newOAuthApp(t, c, ts.URL, as)
	as.laxRedirect, as.laxCodeReuse, as.noRotation = true, true, true

	_, page := runOAuth(t, c, ts.URL, "/apps/"+id+"/signin")
	if checkLine(page, "Code single use") != "fail" {
		t.Error("code reuse not caught")
	}
	if got := checkLine(page, "Refresh token rotation"); got != "info" {
		t.Errorf("no rotation for a confidential client: %q, want info", got)
	}
	as.advertisePlain, as.laxCodeToken = true, true
	loc := oauthStep(t, c, "POST", ts.URL+"/apps/"+id+"/conformance")
	_, page = get(t, c, ts.URL+loc)
	if checkLine(page, "Exact redirect URI match (trailing slash)") != "fail" {
		t.Errorf("loose redirect matching not caught:\n%s", mainOf(page))
	}
	if got := checkLine(page, "Advertised PKCE methods"); got != "fail" {
		t.Errorf("advertising plain PKCE: %q, want fail (OAuth 2.1 forbids it)", got)
	}
	if got := checkLine(page, "Hybrid flow with an access token removed"); got != "fail" {
		t.Errorf("code token accepted: %q, want fail", got)
	}
	if got := checkLine(page, "Advertised response types"); got != "warn" {
		t.Errorf("code token advertised: %q, want warn", got)
	}
	as.advertisePlain, as.laxCodeToken = false, false

	// A broken token endpoint is not mistaken for a refusal.
	as.laxRedirect, as.laxCodeReuse = false, false
	authz := oauthStep(t, c, "POST", ts.URL+"/apps/"+id+"/check/wrongverifier")
	cb := oauthStep(t, c, "GET", authz)
	as.tokenEndpoint5 = true
	_, page = get(t, c, ts.URL+oauthStep(t, c, "GET", cb))
	if got := checkLine(page, "PKCE verifier binding"); got != "warn" {
		t.Errorf("503 from the token endpoint counted as %q, want warn", got)
	}
}
