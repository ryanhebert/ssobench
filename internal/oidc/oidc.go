// Package oidc is a minimal OpenID Connect relying party built on the
// standard library: discovery, authorization code + PKCE, and ID token checks
// that explain what is wrong instead of just failing.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

var HTTPClient = &http.Client{Timeout: 15 * time.Second}

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       string
	ExtraParams  string // raw query string appended to the authorize request
	RedirectURI  string
}

type Provider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	GrantTypes            []string `json:"grant_types_supported"`
	ResponseTypes         []string `json:"response_types_supported"`
	IssParameter          bool     `json:"authorization_response_iss_parameter_supported"`

	Raw []byte `json:"-"`
	// Invalid holds the JSON error when the document only parsed leniently.
	Invalid string `json:"-"`
}

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

func DiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

func Discover(ctx context.Context, issuer string) (*Provider, error) {
	body, err := get(ctx, DiscoveryURL(issuer), "")
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	p := &Provider{Raw: body}
	if err := json.Unmarshal(body, p); err != nil {
		// Trailing commas are a common hand-edit mistake; read past them but
		// report it, because strict client libraries will not.
		fixed := trailingComma.ReplaceAll(body, []byte("$1"))
		if err2 := json.Unmarshal(fixed, p); err2 != nil {
			return nil, fmt.Errorf("discovery document is not valid JSON: %w", err)
		}
		p.Invalid = err.Error()
	}
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document has no authorization_endpoint or token_endpoint")
	}
	return p, nil
}

func FetchJWKS(ctx context.Context, uri string) (*JWKS, []byte, error) {
	body, err := get(ctx, uri, "")
	if err != nil {
		return nil, nil, fmt.Errorf("jwks: %w", err)
	}
	var s JWKS
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, body, fmt.Errorf("jwks is not valid JSON: %w", err)
	}
	return &s, body, nil
}

func get(ctx context.Context, u, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(req)
}

func do(req *http.Request) ([]byte, error) {
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return body, fmt.Errorf("%s %s: HTTP %d: %s", req.Method, req.URL.Redacted(), resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// RandomString returns n random bytes, base64url-encoded.
func RandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func AuthURL(cfg Config, p *Provider, state, nonce, verifier string) (string, error) {
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
	sum := sha256.Sum256([]byte(verifier))
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type Tokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`

	Raw []byte `json:"-"`
}

// AuthMethod is how Exchange authenticates the client at the token endpoint.
func AuthMethod(cfg Config, p *Provider) string {
	switch {
	case cfg.ClientSecret == "":
		return "none (public client, PKCE only)"
	case len(p.TokenAuthMethods) > 0 &&
		!slices.Contains(p.TokenAuthMethods, "client_secret_basic") &&
		slices.Contains(p.TokenAuthMethods, "client_secret_post"):
		return "client_secret_post"
	}
	return "client_secret_basic"
}

// Exchange redeems the authorization code. Client authentication follows the
// provider's advertised methods: client_secret_basic unless only _post is
// offered.
func Exchange(ctx context.Context, cfg Config, p *Provider, code, verifier string) (*Tokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"code_verifier": {verifier},
		"client_id":     {cfg.ClientID},
	}
	post := AuthMethod(cfg, p) == "client_secret_post"
	if post {
		form.Set("client_secret", cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cfg.ClientSecret != "" && !post {
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}
	body, err := do(req)
	t := &Tokens{Raw: body}
	if err != nil {
		return t, fmt.Errorf("token exchange: %w", err)
	}
	if err := json.Unmarshal(body, t); err != nil {
		return t, fmt.Errorf("token response is not valid JSON: %w", err)
	}
	return t, nil
}

func Userinfo(ctx context.Context, p *Provider, accessToken string) ([]byte, error) {
	return get(ctx, p.UserinfoEndpoint, accessToken)
}

// Expect is what the relying party knows when the ID token arrives.
type Expect struct {
	Config   Config
	Provider *Provider
	JWKS     *JWKS
	Nonce    string
	Now      time.Time
	Skew     time.Duration
}

// IssuerMatches compares iss to the discovered issuer, expanding the Entra
// multi-tenant "{tenantid}" template from the tid claim.
func IssuerMatches(discovered, iss, tid string) bool {
	if strings.Contains(discovered, "{tenantid}") && tid != "" {
		discovered = strings.ReplaceAll(discovered, "{tenantid}", tid)
	}
	return iss == discovered
}

func CheckDiscovery(cfg Config, p *Provider) []check.Result {
	var rs []check.Result
	if p.Invalid != "" {
		rs = append(rs, check.Meh("Discovery JSON", "the discovery document is not valid JSON ("+p.Invalid+"); read it leniently",
			"Strict OIDC libraries will refuse this provider. Look for a trailing comma in the discovery document."))
	}
	switch {
	case p.Issuer == cfg.Issuer:
		rs = append(rs, check.OK("Discovery issuer", p.Issuer))
	case strings.TrimRight(p.Issuer, "/") == strings.TrimRight(cfg.Issuer, "/"):
		rs = append(rs, check.Meh("Discovery issuer",
			fmt.Sprintf("you entered %q but the provider calls itself %q", cfg.Issuer, p.Issuer),
			"Trailing slash difference. Libraries that compare issuers exactly will reject tokens; configure the issuer exactly as discovery reports it."))
	default:
		rs = append(rs, check.Meh("Discovery issuer",
			fmt.Sprintf("you entered %q but the provider calls itself %q", cfg.Issuer, p.Issuer),
			"Use the discovery issuer value in your app's configuration."))
	}
	if len(p.CodeChallengeMethods) > 0 && !slices.Contains(p.CodeChallengeMethods, "S256") {
		rs = append(rs, check.Meh("PKCE", "provider does not advertise S256 code challenges",
			"PKCE with S256 is recommended for every client. Check whether the provider supports it."))
	}
	return rs
}

// CheckIDToken runs every ID token validation rule from OIDC Core 3.1.3.7
// and reports each one separately.
func CheckIDToken(j *JWT, e Expect, accessToken string) []check.Result {
	var rs []check.Result
	now := e.Now

	alg := j.Alg()
	switch {
	case alg == "" || alg == "none":
		rs = append(rs, check.Bad("Signature", "token is unsigned (alg=none)",
			"Never accept unsigned ID tokens. Configure the identity provider to sign with RS256 or ES256."))
	case strings.HasPrefix(alg, "HS") && e.Config.ClientSecret == "":
		rs = append(rs, check.Bad("Signature", alg+": signed with a shared secret, and this client has none",
			"Without a client secret the token cannot be verified, so it must not be trusted. Enter the client secret, or have the identity provider sign ID tokens with RS256 or ES256."))
	case strings.HasPrefix(alg, "HS"):
		if err := j.Verify(nil, []byte(e.Config.ClientSecret)); err != nil {
			rs = append(rs, check.Bad("Signature", alg+": "+err.Error(),
				"HS* tokens are signed with the client secret. Check that the secret is current."))
		} else {
			rs = append(rs, check.OK("Signature", alg+" with the client secret"))
		}
	case e.JWKS == nil:
		rs = append(rs, check.Bad("Signature", "no JWKS available to verify the signature", "Check jwks_uri in the discovery document."))
	default:
		k, ok := e.JWKS.Find(j.Kid())
		if !ok {
			rs = append(rs, check.Bad("Signature",
				fmt.Sprintf("kid %q is not in the JWKS (available: %s)", j.Kid(), strings.Join(e.JWKS.Kids(), ", ")),
				"The signing key rotated, or the token was issued by a different issuer or tenant than the one you configured."))
			break
		}
		err := j.VerifyJWK(k)
		if err != nil {
			rs = append(rs, check.Bad("Signature", fmt.Sprintf("%s with key %q: %v", alg, k.Kid, err),
				"The token was altered, or signed by a different key with the same kid."))
		} else {
			rs = append(rs, check.OK("Signature", fmt.Sprintf("%s with key %q", alg, k.Kid)))
		}
	}

	iss := j.Str("iss")
	if IssuerMatches(e.Provider.Issuer, iss, j.Str("tid")) {
		rs = append(rs, check.OK("Issuer (iss)", iss))
	} else {
		rs = append(rs, check.Bad("Issuer (iss)", "the token comes from a different issuer than discovery describes",
			"The token came from a different issuer, often another tenant or API version. Use the issuer URL the provider's discovery document gives.").Mismatch(iss, e.Provider.Issuer))
	}

	auds := j.Audiences()
	if slices.Contains(auds, e.Config.ClientID) {
		rs = append(rs, check.OK("Audience (aud)", strings.Join(auds, ", ")))
	} else {
		rs = append(rs, check.Bad("Audience (aud)", "the ID token was issued to another application",
			"Make sure the client ID in SSOBench matches the one at your identity provider.").Mismatch(strings.Join(auds, "\n"), e.Config.ClientID))
	}
	if len(auds) > 1 {
		if azp := j.Str("azp"); azp == e.Config.ClientID {
			rs = append(rs, check.OK("Authorized party (azp)", azp))
		} else {
			rs = append(rs, check.Meh("Authorized party (azp)", fmt.Sprintf("multiple audiences, azp is %q", azp),
				"With multiple audiences, azp should equal your client ID."))
		}
	}

	exp, hasExp := j.Time("exp")
	nbf, _ := j.Time("nbf")
	if !hasExp {
		rs = append(rs, check.Bad("Expiry (exp)", "missing", "exp is required in an ID token."))
	} else {
		rs = append(rs, check.Window("Lifetime (nbf/exp)", nbf, exp, now, e.Skew))
	}
	if iat, ok := j.Time("iat"); ok {
		skew := iat.Sub(now).Round(time.Second)
		if skew > e.Skew {
			rs = append(rs, check.Bad("Issued at (iat)", fmt.Sprintf("%s, %s ahead of this machine", check.When(iat, now), skew),
				"Clock skew between this machine and the identity provider. Sync both with NTP."))
		} else {
			rs = append(rs, check.OK("Issued at (iat)", check.When(iat, now)))
		}
	} else {
		rs = append(rs, check.Bad("Issued at (iat)", "missing", "iat is required in an ID token."))
	}

	switch nonce := j.Str("nonce"); {
	case e.Nonce == "":
		rs = append(rs, check.Note("Nonce", "none was sent, so there is nothing to compare"))
	case nonce == e.Nonce:
		rs = append(rs, check.OK("Nonce", "matches the request"))
	case nonce == "":
		rs = append(rs, check.Bad("Nonce", "missing from the token", "The identity provider dropped the nonce. This allows token replay."))
	default:
		rs = append(rs, check.Bad("Nonce", "does not match the request", "Possible replay, or the login was started in another tab."))
	}

	if atHash := j.Str("at_hash"); atHash != "" && accessToken != "" {
		if want, ok := HalfHash(alg, accessToken); ok && want == atHash {
			rs = append(rs, check.OK("Access token hash (at_hash)", "matches the access token"))
		} else {
			rs = append(rs, check.Bad("Access token hash (at_hash)", "does not match the access token",
				"The access token was swapped or the identity provider computed at_hash with the wrong hash."))
		}
	}

	if j.Str("sub") == "" {
		rs = append(rs, check.Bad("Subject (sub)", "missing", "sub is required in an ID token."))
	}
	return rs
}
