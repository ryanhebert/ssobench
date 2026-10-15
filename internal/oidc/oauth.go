package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

// ASMetadataURLs are the places an OAuth 2.0 authorization server
// publishes RFC 8414 metadata for issuer: the standard well-known URI
// (inserted before any issuer path) and the common appended form.
func ASMetadataURLs(issuer string) []string {
	u, err := url.Parse(strings.TrimRight(issuer, "/"))
	if err != nil {
		return nil
	}
	std := u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server" + u.Path
	appended := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	if std == appended {
		return []string{std}
	}
	return []string{std, appended}
}

// DiscoverAS loads RFC 8414 authorization server metadata, returning the
// URL it came from. The fields it shares with OIDC discovery fill a Provider.
func DiscoverAS(ctx context.Context, issuer string) (*Provider, string, error) {
	var lastErr error
	for _, u := range ASMetadataURLs(issuer) {
		body, err := get(ctx, u, "")
		if err != nil {
			lastErr = err
			continue
		}
		p := &Provider{Raw: body}
		if err := json.Unmarshal(body, p); err != nil {
			lastErr = fmt.Errorf("%s is not valid JSON: %w", u, err)
			continue
		}
		return p, u, nil
	}
	return nil, "", lastErr
}

// AuthOptions vary the authorize request for conformance probes.
type AuthOptions struct {
	NoPKCE       bool   // send no code_challenge
	Method       string // code_challenge_method; "" means S256
	ResponseType string // "" means code
	RedirectURI  string // overrides cfg.RedirectURI (redirect matching probes)
	Resource     string // RFC 8707 resource indicator
}

// AuthURLWith builds an authorize request with the given variations.
func AuthURLWith(cfg Config, p *Provider, state, nonce, verifier string, o AuthOptions) (string, error) {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if cfg.ExtraParams != "" {
		extra, err := url.ParseQuery(strings.TrimPrefix(cfg.ExtraParams, "?"))
		if err != nil {
			return "", fmt.Errorf("extra parameters: %w", err)
		}
		for k, v := range extra {
			q[k] = v
		}
	}
	rt := o.ResponseType
	if rt == "" {
		rt = "code"
	}
	redirect := cfg.RedirectURI
	if o.RedirectURI != "" {
		redirect = o.RedirectURI
	}
	q.Set("response_type", rt)
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", cfg.Scopes)
	q.Set("state", state)
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	if o.Resource != "" {
		q.Set("resource", o.Resource)
	}
	if !o.NoPKCE {
		method := o.Method
		if method == "" {
			method = "S256"
		}
		challenge := verifier
		if method == "S256" {
			sum := sha256.Sum256([]byte(verifier))
			challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		}
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", method)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// tokenRequest posts form to the token endpoint with client authentication
// as the provider advertises, returning the parsed tokens, the raw body and
// the HTTP status.
func tokenRequest(ctx context.Context, cfg Config, p *Provider, form url.Values) (*Tokens, int, error) {
	if cfg.ClientID != "" {
		form.Set("client_id", cfg.ClientID)
	}
	post := AuthMethod(cfg, p) == "client_secret_post"
	if post {
		form.Set("client_secret", cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cfg.ClientSecret != "" && !post {
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	t := &Tokens{Raw: body}
	if resp.StatusCode != http.StatusOK {
		return t, resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, t); err != nil {
		return t, resp.StatusCode, fmt.Errorf("token response is not valid JSON: %w", err)
	}
	return t, resp.StatusCode, nil
}

// RedeemCode exchanges an authorization code. An empty verifier sends no
// code_verifier (the no-PKCE probe).
func RedeemCode(ctx context.Context, cfg Config, p *Provider, code, verifier, resource string) (*Tokens, int, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cfg.RedirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	return tokenRequest(ctx, cfg, p, form)
}

// ClientCredentials requests a token with the client credentials grant.
func ClientCredentials(ctx context.Context, cfg Config, p *Provider, scope, resource string) (*Tokens, int, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	return tokenRequest(ctx, cfg, p, form)
}

// Refresh uses a refresh token; scope narrows the request when set.
func Refresh(ctx context.Context, cfg Config, p *Provider, refreshToken, scope string) (*Tokens, int, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return tokenRequest(ctx, cfg, p, form)
}

// PasswordGrant tries the removed resource owner password grant with
// throwaway credentials. A conforming server refuses the grant type itself.
func PasswordGrant(ctx context.Context, cfg Config, p *Provider) (*Tokens, int, error) {
	form := url.Values{"grant_type": {"password"}, "username": {"ssobench-probe"}, "password": {"ssobench-probe-" + RandomString(6)}, "scope": {cfg.Scopes}}
	return tokenRequest(ctx, cfg, p, form)
}

// OAuthError is the error code in an OAuth error response, if any.
func OAuthError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(body, &e)
	return e.Error
}

// Introspect asks the introspection endpoint (RFC 7662) about token.
func Introspect(ctx context.Context, cfg Config, endpoint, token string) (map[string]any, []byte, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	body, err := do(req)
	if err != nil {
		return nil, body, err
	}
	var m map[string]any
	if err := unmarshal(body, &m); err != nil {
		return nil, body, fmt.Errorf("introspection response is not valid JSON: %w", err)
	}
	return m, body, nil
}

// ProbeAuthorize sends an authorize request without following redirects
// and reports where the server would send the browser.
type ProbeResult struct {
	Status   int
	Location string
	Body     string
}

func ProbeAuthorize(ctx context.Context, authURL string) (ProbeResult, error) {
	c := *HTTPClient
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return ProbeResult{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return ProbeResult{Status: resp.StatusCode, Location: resp.Header.Get("Location"), Body: string(b)}, nil
}

// ExpectAT is what an API (resource server) checks in an access token.
type ExpectAT struct {
	Issuer   string
	ClientID string
	Resource string // the expected audience, when one was requested
	Scopes   []string
	JWKS     *JWKS
	Now      time.Time
	Skew     time.Duration
}

// CheckAccessToken validates a JWT access token the way an API would, and
// against the JWT access token profile (RFC 9068).
func CheckAccessToken(j *JWT, e ExpectAT) []check.Result {
	var rs []check.Result
	alg := j.Alg()
	switch {
	case alg == "" || alg == "none":
		rs = append(rs, check.Bad("Access token signature", "the token is unsigned (alg=none)", "An API must reject unsigned access tokens."))
	case strings.HasPrefix(alg, "HS"):
		rs = append(rs, check.Bad("Access token signature", alg+": signed with a shared secret",
			"APIs verify access tokens with the authorization server's published public keys. An HMAC-signed token can be forged by anyone who holds the secret, so APIs must reject it. Configure the server to sign access tokens with RS256 or ES256."))
	case e.JWKS == nil:
		rs = append(rs, check.Bad("Access token signature", "no JWKS to verify it with", "Check jwks_uri in the server metadata."))
	default:
		k, ok := e.JWKS.Find(j.Kid())
		if !ok {
			rs = append(rs, check.Bad("Access token signature", fmt.Sprintf("kid %q is not in the JWKS", j.Kid()),
				"The token was signed with a key the server does not publish, so APIs cannot verify it."))
			break
		}
		err := j.VerifyJWK(k)
		if err != nil {
			rs = append(rs, check.Bad("Access token signature", fmt.Sprintf("%s with key %q: %v", alg, k.Kid, err), "The token was altered, or signed with another key."))
		} else {
			rs = append(rs, check.OK("Access token signature", fmt.Sprintf("%s with key %q", alg, k.Kid)))
		}
	}

	typ, _ := j.Header["typ"].(string)
	switch strings.ToLower(typ) {
	case "at+jwt", "application/at+jwt":
		rs = append(rs, check.OK("Token type (typ)", typ))
	default:
		// The RFC 9068 profile is optional, and many servers use typ JWT,
		// so this is information, not a problem.
		rs = append(rs, check.Note("Token type (typ)", fmt.Sprintf("%q; the optional JWT access token profile (RFC 9068) uses at+jwt, and only APIs that require that profile would reject it", typ)))
	}

	if iss := j.Str("iss"); IssuerMatches(e.Issuer, iss, j.Str("tid")) {
		rs = append(rs, check.OK("Access token issuer", iss))
	} else {
		rs = append(rs, check.Bad("Access token issuer", "the token comes from a different issuer", "APIs check iss against the authorization server they trust.").Mismatch(iss, e.Issuer))
	}

	auds := j.Audiences()
	switch {
	case e.Resource != "" && slices.Contains(auds, e.Resource):
		rs = append(rs, check.OK("Access token audience", e.Resource))
	case e.Resource != "":
		rs = append(rs, check.Bad("Access token audience", "the token is not for the requested resource",
			"An API accepts only tokens whose aud names it. Check the resource (API) configured for this client at the identity provider.").Mismatch(strings.Join(auds, "\n"), e.Resource))
	case len(auds) == 0:
		rs = append(rs, check.Meh("Access token audience", "the token has no aud claim", "Without an audience, any API that trusts this server would accept the token."))
	case slices.Contains(auds, e.ClientID):
		rs = append(rs, check.Note("Access token audience", fmt.Sprintf("aud is the client ID %q; RFC 9068 expects the API (resource) instead", e.ClientID)))
	default:
		rs = append(rs, check.OK("Access token audience", strings.Join(auds, ", ")))
	}

	exp, hasExp := j.Time("exp")
	nbf, _ := j.Time("nbf")
	if !hasExp {
		rs = append(rs, check.Bad("Access token lifetime", "no exp claim", "Access tokens must expire."))
	} else {
		rs = append(rs, check.Window("Access token lifetime", nbf, exp, e.Now, e.Skew))
		if iat, ok := j.Time("iat"); ok && exp.Sub(iat) > 24*time.Hour {
			rs = append(rs, check.Meh("Access token lifetime", fmt.Sprintf("issued for %s", check.Human(exp.Sub(iat))), "Long-lived access tokens are hard to revoke. Shorten the access token lifetime."))
		}
	}

	granted := strings.Fields(j.Str("scope"))
	if len(granted) == 0 {
		switch scp := j.Claims["scp"].(type) {
		case []any:
			for _, x := range scp {
				if v, ok := x.(string); ok {
					granted = append(granted, v)
				}
			}
		case string: // some servers send scp as one space-separated string
			granted = strings.Fields(scp)
		}
	}
	switch {
	case len(granted) == 0:
		rs = append(rs, check.Note("Scopes in the token", "the token carries no scope claim"))
	default:
		var missing []string
		for _, want := range e.Scopes {
			if want != "openid" && want != "offline_access" && !slices.Contains(granted, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			rs = append(rs, check.Meh("Scopes in the token", fmt.Sprintf("granted %s; not granted: %s", strings.Join(granted, " "), strings.Join(missing, " ")),
				"The identity provider granted fewer scopes than requested, often because of a group-based scope policy. Check the scopes allowed for this client and user."))
		} else {
			rs = append(rs, check.OK("Scopes in the token", strings.Join(granted, " ")))
		}
	}
	if cid := j.Str("client_id"); cid != "" && cid != e.ClientID {
		rs = append(rs, check.Bad("Client (client_id)", "the token was issued to another client", "An API must only accept tokens issued to clients it trusts. Check that this app's client ID matches the one the authorization server issued the token to.").Mismatch(cid, e.ClientID))
	}
	return rs
}
