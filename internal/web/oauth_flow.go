package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/oidc"
)

// OAuth 2.1 (API access) apps test an authorization server: what access
// tokens it issues and which OAuth 2.1 rules it enforces. Sign-in modes:
const (
	ModeNormal        = ""
	ModeNoPKCE        = "nopkce"        // guided check: authorize without PKCE
	ModeWrongVerifier = "wrongverifier" // guided check: redeem with the wrong verifier
)

// oauthProvider loads the server's metadata: RFC 8414 first, then OIDC
// discovery. It logs both and keeps the result on the app.
func (s *Server) oauthProvider(ctx context.Context, f *Flow, app *App, issuer string) (*oidc.Provider, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t0 := time.Now()
	p, src, err := oidc.DiscoverAS(ctx, issuer)
	if err != nil {
		s.event(f, LInfo, "Discovery", time.Since(t0), "", "No OAuth authorization server metadata (RFC 8414): %v", err)
		t1 := time.Now()
		if p, err = oidc.Discover(ctx, issuer); err != nil {
			s.event(f, LError, "Discovery", time.Since(t1), "", "GET %s failed: %v", oidc.DiscoveryURL(issuer), err)
			return nil, "", err
		}
		src = oidc.DiscoveryURL(issuer)
	}
	s.event(f, LInfo, "Discovery", time.Since(t0), discoveryDetail(p), "Loaded %s", src)
	s.mu.Lock()
	app.provider, app.providerAt = p, time.Now()
	s.mu.Unlock()
	return p, src, nil
}

func (s *Server) oauthConfig(r *http.Request, app *App) (oidc.Config, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := withHints(app.OIDCConfig(), app.AcrValues, app.LoginHint)
	cfg.RedirectURI = s.oauthRedirectFor(r, app)
	if cfg.Scopes == "" {
		cfg.Scopes = "openid"
	}
	return cfg, app.Resource, app.MachineScopes
}

// oauthSignIn starts the authorization code flow, or a guided check.
func (s *Server) oauthSignIn(w http.ResponseWriter, r *http.Request, app *App, via, mode string) {
	cfg, resource, _ := s.oauthConfig(r, app)
	label := s.appName(app)
	switch mode {
	case ModeNoPKCE:
		label += " (check: sign-in without PKCE)"
	case ModeWrongVerifier:
		label += " (check: wrong PKCE verifier)"
	}
	f := s.newFlow("OAUTH", label)
	p, _, err := s.oauthProvider(r.Context(), f, app, cfg.Issuer)
	if err != nil {
		s.finish(f, "", "stopped: no server metadata")
		s.appError(w, r, app, fmt.Sprintf("Could not load the authorization server metadata for %s: %v", cfg.Issuer, err))
		return
	}
	state, verifier := oidc.RandomString(24), oidc.RandomString(48)
	nonce := ""
	if slices.Contains(strings.Fields(cfg.Scopes), "openid") {
		nonce = oidc.RandomString(24)
	}
	u, err := oidc.AuthURLWith(cfg, p, state, nonce, verifier, oidc.AuthOptions{NoPKCE: mode == ModeNoPKCE, Resource: resource})
	if err != nil {
		s.finish(f, "", "stopped: "+err.Error())
		s.appError(w, r, app, err.Error())
		return
	}
	what := "authorization code flow, PKCE S256"
	if mode == ModeNoPKCE {
		what = "authorization code flow, deliberately without PKCE"
	}
	s.event(f, LInfo, "Authorize request", 0, prettyURL(u), "Sending the browser to the authorization endpoint (%s)", what)
	s.pendingOAuth.Put(state, &codePending{app: app, cfg: cfg, provider: p, verifier: verifier, nonce: nonce, resource: resource,
		mode: mode, via: via, started: time.Now(), flow: f})
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pend, _ := s.pendingOAuth.Take(q.Get("state"))

	res := &Result{Kind: "OAUTH", Via: ViaConsole}
	var f *Flow
	var app *App
	defer func() {
		s.save(res, f)
		http.Redirect(w, r, s.landing(res, app), http.StatusSeeOther)
	}()
	params := Section{Group: GroupRaw, Title: "Callback parameters", Rows: queryRows(q)}
	if pend == nil {
		f = s.unknownState(res, "OAUTH", params)
		return
	}
	f, app = pend.flow, pend.app
	cfg, p := pend.cfg, pend.provider
	res.AppID, res.AppName, res.Via = app.ID, s.appName(app), pend.via
	res.Mode = pend.mode
	res.Title, res.Issuer = cfg.Issuer, cfg.Issuer
	res.Checks = append(res.Checks, check.OK("State", "matches the request"))
	res.Checks = append(res.Checks, issParamCheck(q, p))

	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		s.event(f, LInfo, "Callback", 0, rowsText(params.Rows), "Server returned an error, %s after the request: %s", humanDur(time.Since(pend.started)), msg)
		if pend.mode == ModeNoPKCE {
			// Refusing an authorize request without PKCE is the right answer.
			res.Title = "Check: sign-in without PKCE"
			res.Checks = append(res.Checks, check.OK("PKCE required", "the server refused an authorize request without PKCE ("+e+")"))
			res.All = []Section{params}
			return
		}
		res.Refused = msg
		res.Checks = append(res.Checks, check.Bad("Authorization", msg, oauthFix(e)))
		res.All = []Section{params, discoverySection(p)}
		return
	}
	s.event(f, LInfo, "Callback", 0, rowsText(params.Rows), "Browser returned with a code, %s after the request", humanDur(time.Since(pend.started)))
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	code := q.Get("code")

	switch pend.mode {
	case ModeNoPKCE:
		res.Title = "Check: sign-in without PKCE"
		tok, status, err := oidc.RedeemCode(ctx, cfg, p, code, "", pend.resource)
		switch {
		case err == nil && tok.AccessToken != "":
			s.event(f, LError, "Token exchange", 0, shortenTokens(tok.Raw), "Tokens issued without PKCE")
			res.Checks = append(res.Checks, check.Bad("PKCE required", "the server issued a code and redeemed it without any PKCE",
				"OAuth 2.1 requires PKCE for every authorization code. Turn on PKCE enforcement for this client at the IdP."))
		case !refused(tok, status, err):
			s.event(f, LError, "Token exchange", 0, string(tokRaw(tok)), "No usable answer (HTTP %d): %v", status, err)
			res.Checks = append(res.Checks, couldNotTell("PKCE required", status, err))
		default:
			s.event(f, LInfo, "Token exchange", 0, string(tokRaw(tok)), "Refused without a verifier (HTTP %d)", status)
			res.Checks = append(res.Checks, check.Meh("PKCE required",
				"the server issued a code without PKCE, but refused to redeem it ("+oidc.OAuthError(tokRaw(tok))+")",
				"Codes are protected, but the server should refuse the authorize request itself when it has no code_challenge."))
		}
		res.All = []Section{params, discoverySection(p)}
		return
	case ModeWrongVerifier:
		res.Title = "Check: wrong PKCE verifier"
		tok, status, err := oidc.RedeemCode(ctx, cfg, p, code, oidc.RandomString(48), pend.resource)
		switch {
		case err == nil && tok.AccessToken != "":
			s.event(f, LError, "Token exchange", 0, shortenTokens(tok.Raw), "Tokens issued for the wrong verifier")
			res.Checks = append(res.Checks, check.Bad("PKCE verifier binding", "the server issued tokens for a code_verifier that does not match the challenge",
				"The server does not check PKCE at all. Anyone who intercepts a code can redeem it."))
		case !refused(tok, status, err):
			s.event(f, LError, "Token exchange", 0, string(tokRaw(tok)), "No usable answer (HTTP %d): %v", status, err)
			res.Checks = append(res.Checks, couldNotTell("PKCE verifier binding", status, err))
		default:
			s.event(f, LInfo, "Token exchange", 0, string(tokRaw(tok)), "Wrong verifier refused (HTTP %d)", status)
			res.Checks = append(res.Checks, check.OK("PKCE verifier binding", "the server refused the wrong code_verifier ("+oidc.OAuthError(tokRaw(tok))+")"))
		}
		res.All = []Section{params, discoverySection(p)}
		return
	}

	t0 := time.Now()
	tok, _, err := oidc.RedeemCode(ctx, cfg, p, code, pend.verifier, pend.resource)
	detail := fmt.Sprintf("POST %s\nclient authentication  %s\ngrant_type             authorization_code\ncode                   %s\nredirect_uri           %s\ncode_verifier          (sent, not logged)",
		p.TokenEndpoint, oidc.AuthMethod(cfg, p), shortToken(code), cfg.RedirectURI)
	if err != nil {
		s.event(f, LError, "Token exchange", time.Since(t0), detail+"\n\nResponse:\n"+string(tokRaw(tok)), "%v", err)
		fix := tokenFix(err.Error())
		if cfg.ClientSecret == "" && clientCredentialError(err.Error()) {
			fix = noSecretFix
		}
		res.Checks = append(res.Checks, check.Bad("Token exchange", oauthRefusal("the server refused to redeem the code", tokRaw(tok), err), fix))
		res.All = []Section{params, discoverySection(p)}
		return
	}
	s.event(f, LInfo, "Token exchange", time.Since(t0), detail+"\n\nResponse:\n"+shortenTokens(tok.Raw), "Redeemed the code: received %s", tokenKinds(tok))
	res.Checks = append(res.Checks, check.OK("Token exchange", "code redeemed at "+p.TokenEndpoint))

	s.analyzeTokens(ctx, f, res, app, cfg, p, tok, pend.resource, pend.nonce, false)

	// Codes are single use: redeeming it again must fail. This runs last,
	// because a server may (and should) revoke the tokens issued for a
	// code that is replayed.
	again, status, err := oidc.RedeemCode(ctx, cfg, p, code, pend.verifier, pend.resource)
	switch {
	case err == nil && again.AccessToken != "":
		s.event(f, LError, "Code reuse", 0, "", "The same code was redeemed a second time")
		res.Checks = append(res.Checks, check.Bad("Code single use", "the same code was redeemed twice",
			"OAuth 2.1 requires codes to be single use. A stolen code could be replayed."))
	case !refused(again, status, err):
		s.event(f, LWarn, "Code reuse", 0, string(tokRaw(again)), "No usable answer (HTTP %d): %v", status, err)
		res.Checks = append(res.Checks, couldNotTell("Code single use", status, err))
	default:
		s.event(f, LInfo, "Code reuse", 0, string(tokRaw(again)), "Second redemption refused")
		res.Checks = append(res.Checks, check.OK("Code single use", "a second redemption was refused ("+oidc.OAuthError(tokRaw(again))+")"))
	}
	res.All = append(res.All, Section{Group: GroupRaw, Title: "Token response", Pre: redactRefresh(tok.Raw)}, params, discoverySection(p))
}

// refused reports whether the token endpoint refused a request the way
// OAuth defines: a 4xx answer carrying an OAuth error code. Timeouts,
// network errors and server errors say nothing about the rule being tested.
func refused(tok *oidc.Tokens, status int, err error) bool {
	return err != nil && status >= 400 && status < 500 && oidc.OAuthError(tokRaw(tok)) != ""
}

func couldNotTell(name string, status int, err error) check.Result {
	what := fmt.Sprintf("HTTP %d", status)
	if status == 0 && err != nil {
		what = err.Error()
	}
	return check.Meh(name, "could not tell: the token endpoint gave no OAuth answer ("+what+")",
		"The server did not answer with an OAuth error, so this rule was not tested. Check that the token endpoint is reachable, then run it again.")
}

// tokRaw is the raw body of a token response, empty when there was none.
func tokRaw(t *oidc.Tokens) []byte {
	if t == nil {
		return nil
	}
	return t.Raw
}

// issParamCheck: RFC 9207 puts the issuer in the authorization response so
// a client can't be mixed up between servers.
func issParamCheck(q url.Values, p *oidc.Provider) check.Result {
	iss := q.Get("iss")
	switch {
	case iss != "" && iss == p.Issuer:
		return check.OK("Issuer in the response (RFC 9207)", iss)
	case iss != "":
		return check.Bad("Issuer in the response (RFC 9207)", "the authorization response names another issuer", "A mismatch here is how mix-up attacks show.").Mismatch(iss, p.Issuer)
	case p.IssParameter:
		return check.Bad("Issuer in the response (RFC 9207)", "advertised in the metadata, but missing from the response", "The server says it sends iss but did not.")
	}
	return check.Note("Issuer in the response (RFC 9207)", "not sent; it protects clients that use several servers from mix-up attacks")
}

// analyzeTokens checks the access token (and an ID token, if any), asks the
// introspection endpoint about it, and tests refresh token rotation.
func (s *Server) analyzeTokens(ctx context.Context, f *Flow, res *Result, app *App, cfg oidc.Config, p *oidc.Provider, tok *oidc.Tokens, resource, nonce string, machine bool) {
	var jwks *oidc.JWKS
	if p.JWKSURI != "" {
		t1 := time.Now()
		var err error
		if jwks, _, err = oidc.FetchJWKS(ctx, p.JWKSURI); err != nil {
			s.event(f, LError, "JWKS", time.Since(t1), "", "GET %s failed: %v", p.JWKSURI, err)
		} else {
			s.event(f, LInfo, "JWKS", time.Since(t1), "", "Loaded %d keys (kids: %s)", len(jwks.Keys), strings.Join(jwks.Kids(), ", "))
		}
	}
	requested := strings.Fields(cfg.Scopes)
	if machine {
		s.mu.Lock()
		requested = strings.Fields(app.MachineScopes)
		s.mu.Unlock()
	}

	if tok.AccessToken == "" {
		res.Checks = append(res.Checks, check.Bad("Access token", "the token response has no access_token", "An OAuth token response must include an access token."))
	} else if at, err := oidc.ParseJWT(tok.AccessToken); err == nil {
		s.event(f, LInfo, "Access token", 0, string(at.HeaderRaw), "JWT, alg %s, typ %v, aud %v", at.Alg(), at.Header["typ"], at.Audiences())
		res.Checks = append(res.Checks, oidc.CheckAccessToken(at, oidc.ExpectAT{Issuer: p.Issuer, ClientID: cfg.ClientID, Resource: resource,
			Scopes: requested, JWKS: jwks, Now: time.Now(), Skew: s.Skew})...)
		sec := claimsSection(GroupIdentity, "Access token", at, true)
		res.All = append(res.All, sec, Section{Group: GroupRaw, Title: "Access token header", Pre: indent(at.HeaderRaw)},
			Section{Group: GroupRaw, Title: "Access token (encoded)", Pre: at.Raw})
		res.GrantedScopes = strings.Fields(at.Str("scope"))
		if exp, ok := at.Time("exp"); ok {
			res.TokenExpiry = exp
		}
		if sub := at.Str("sub"); sub != "" && res.Subject == "" {
			res.Subject = sub
		}
	} else {
		res.Checks = append(res.Checks, check.Note("Access token", "opaque (not a JWT); only the server's introspection endpoint can describe it"))
	}
	if res.GrantedScopes == nil && tok.Scope != "" {
		res.GrantedScopes = strings.Fields(tok.Scope)
	}

	// Introspection (RFC 7662) needs the client's credentials.
	switch {
	case tok.AccessToken == "":
	case p.IntrospectionEndpoint == "":
		res.Checks = append(res.Checks, check.Note("Introspection", "the server advertises no introspection endpoint"))
	case cfg.ClientSecret == "":
		res.Checks = append(res.Checks, check.Note("Introspection", "skipped: introspection needs the client secret"))
	default:
		t2 := time.Now()
		m, body, err := oidc.Introspect(ctx, cfg, p.IntrospectionEndpoint, tok.AccessToken)
		switch {
		case err != nil:
			s.event(f, LWarn, "Introspection", time.Since(t2), string(body), "%v", err)
			res.Checks = append(res.Checks, check.Meh("Introspection", err.Error(), "The client may not be allowed to introspect tokens."))
		case m["active"] == true:
			s.event(f, LInfo, "Introspection", time.Since(t2), indent(body), "Token is active")
			res.Checks = append(res.Checks, check.OK("Introspection", "the server says the token is active"))
			res.All = append(res.All, Section{Group: GroupDetail, Title: "Introspection response", Pre: indent(body)})
		default:
			s.event(f, LError, "Introspection", time.Since(t2), indent(body), "Token reported inactive")
			res.Checks = append(res.Checks, check.Bad("Introspection", "the server reports its own fresh token as inactive",
				"APIs that introspect would reject this token. Check the token and introspection settings at the IdP."))
			res.All = append(res.All, Section{Group: GroupDetail, Title: "Introspection response", Pre: indent(body)})
		}
	}

	// An ID token comes back when openid was requested.
	if tok.IDToken != "" {
		if idt, err := oidc.ParseJWT(tok.IDToken); err == nil {
			res.IDToken = tok.IDToken
			res.Checks = append(res.Checks, oidc.CheckIDToken(idt, oidc.Expect{Config: cfg, Provider: p, JWKS: jwks, Nonce: nonce, Now: time.Now(), Skew: s.Skew}, tok.AccessToken)...)
			res.Checks = append(res.Checks, hintChecks(idt, cfg.ExtraParams)...)
			user, token := splitClaims(claimsSection(GroupIdentity, "Claims about the user", idt, true))
			token.Title = "ID token"
			res.All = append(res.All, user, token)
			res.Subject = firstNonEmpty(idt.Str("email"), idt.Str("preferred_username"), idt.Str("sub"), res.Subject)
		}
	}

	if machine {
		if tok.RefreshToken != "" {
			res.Checks = append(res.Checks, check.Meh("Refresh token", "issued with the client credentials grant",
				"A client with credentials can always get a new token; refresh tokens here only widen what can leak."))
		}
		return
	}
	s.refreshChecks(ctx, f, res, cfg, p, tok)
}

// refreshChecks uses the refresh token, then reuses the old one: OAuth 2.1
// requires public clients' refresh tokens to rotate (or be sender-bound).
func (s *Server) refreshChecks(ctx context.Context, f *Flow, res *Result, cfg oidc.Config, p *oidc.Provider, tok *oidc.Tokens) {
	if tok.RefreshToken == "" {
		res.Checks = append(res.Checks, check.Note("Refresh token", "none issued; request offline_access to test refresh"))
		return
	}
	t0 := time.Now()
	next, _, err := oidc.Refresh(ctx, cfg, p, tok.RefreshToken, "")
	if err != nil {
		s.event(f, LError, "Refresh", time.Since(t0), string(tokRaw(next)), "%v", err)
		res.Checks = append(res.Checks, check.Bad("Refresh", oauthRefusal("the server refused the refresh token it had just issued", tokRaw(next), err),
			"The server issued a refresh token and then would not accept it. Check that this client may use the refresh token grant, and that refresh tokens are not single-use for a different client type."))
		return
	}
	s.event(f, LInfo, "Refresh", time.Since(t0), shortenTokens(next.Raw), "Refreshed: received %s", tokenKinds(next))
	res.Checks = append(res.Checks, check.OK("Refresh", "a new access token was issued"))
	public := cfg.ClientSecret == ""
	switch {
	case next.RefreshToken == "" || next.RefreshToken == tok.RefreshToken:
		if public {
			res.Checks = append(res.Checks, check.Bad("Refresh token rotation", "the same refresh token stays valid after use",
				"OAuth 2.1 requires public clients' refresh tokens to rotate, or be bound to the client. Turn on rotation at the IdP."))
		} else {
			res.Checks = append(res.Checks, check.Note("Refresh token rotation", "not rotated; allowed for confidential clients, required for public ones"))
		}
		return
	}
	// Rotated: the old refresh token must now be dead.
	if _, _, err := oidc.Refresh(ctx, cfg, p, tok.RefreshToken, ""); err == nil {
		s.event(f, LWarn, "Refresh reuse", 0, "", "The old refresh token still works after rotation")
		res.Checks = append(res.Checks, check.Meh("Refresh token rotation", "a new refresh token was issued, but the old one still works",
			"Rotation only protects against theft if used refresh tokens are revoked."))
	} else {
		s.event(f, LInfo, "Refresh reuse", 0, "", "Old refresh token refused after rotation")
		res.Checks = append(res.Checks, check.OK("Refresh token rotation", "rotated, and the old refresh token is refused"))
	}
}

// oauthMachine gets a token with the client credentials grant.
func (s *Server) oauthMachine(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil || !app.IsOAuth() {
		http.NotFound(w, r)
		return
	}
	cfg, resource, scopes := s.oauthConfig(r, app)
	res := &Result{Kind: "OAUTH", Via: ViaConsole, AppID: app.ID, AppName: s.appName(app), Machine: true, Title: "Machine token", Issuer: cfg.Issuer}
	f := s.newFlow("OAUTH", s.appName(app)+" (machine token)")
	defer func() {
		s.save(res, f)
		http.Redirect(w, r, "/result/"+res.ID, http.StatusSeeOther)
	}()
	if cfg.ClientSecret == "" {
		s.event(f, LError, "Client credentials", 0, "", "No client secret")
		res.Checks = []check.Result{check.Bad("Client credentials", "the client credentials grant needs the client secret",
			"Enter the client secret in the app's settings. It is kept in memory only.")}
		return
	}
	p, _, err := s.oauthProvider(r.Context(), f, app, cfg.Issuer)
	if err != nil {
		res.Checks = []check.Result{check.Bad("Server metadata", err.Error(), "Check the issuer URL.")}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if len(p.GrantTypes) > 0 && !slices.Contains(p.GrantTypes, "client_credentials") {
		res.Checks = append(res.Checks, check.Meh("Advertised grant types", "client_credentials is not in grant_types_supported",
			"Clients that read the metadata will think the grant is unavailable. If it works below, the metadata is out of date."))
	}
	t0 := time.Now()
	tok, _, err := oidc.ClientCredentials(ctx, cfg, p, scopes, resource)
	if err != nil {
		s.event(f, LError, "Client credentials", time.Since(t0), string(tokRaw(tok)), "%v", err)
		fix := "Turn on the client credentials grant for this client at the IdP, and allow the requested scopes."
		if e := oidc.OAuthError(tokRaw(tok)); e == "invalid_client" {
			fix = "The client ID or secret is wrong."
		}
		res.Checks = append(res.Checks, check.Bad("Client credentials", oauthRefusal("the server refused the client credentials grant", tokRaw(tok), err), fix))
		res.All = []Section{discoverySection(p)}
		return
	}
	s.event(f, LInfo, "Client credentials", time.Since(t0), shortenTokens(tok.Raw), "Received %s", tokenKinds(tok))
	res.Checks = append(res.Checks, check.OK("Client credentials", "token issued by "+p.TokenEndpoint))
	s.analyzeTokens(ctx, f, res, app, cfg, p, tok, resource, "", true)
	res.Subject = firstNonEmpty(res.Subject, cfg.ClientID)
	res.All = append(res.All, Section{Group: GroupRaw, Title: "Token response", Pre: redactRefresh(tok.Raw)}, discoverySection(p))
}

// oauthConformance probes OAuth 2.1 rules that can be tested without a
// sign-in: metadata, removed grants, PKCE and redirect URI handling.
func (s *Server) oauthConformance(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil || !app.IsOAuth() {
		http.NotFound(w, r)
		return
	}
	cfg, resource, _ := s.oauthConfig(r, app)
	res := &Result{Kind: "OAUTH", Via: ViaConsole, AppID: app.ID, AppName: s.appName(app), Title: "Conformance checks", Issuer: cfg.Issuer, Conformance: true}
	f := s.newFlow("OAUTH", s.appName(app)+" (conformance checks)")
	defer func() {
		s.save(res, f)
		http.Redirect(w, r, "/result/"+res.ID, http.StatusSeeOther)
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	add := func(c check.Result) { res.Checks = append(res.Checks, c) }

	// Metadata: RFC 8414 and OIDC discovery should agree.
	as, asURL, asErr := oidc.DiscoverAS(ctx, cfg.Issuer)
	od, odErr := oidc.Discover(ctx, cfg.Issuer)
	p := as
	switch {
	case asErr == nil:
		s.event(f, LInfo, "Metadata", 0, discoveryDetail(as), "Loaded %s", asURL)
		add(check.OK("Authorization server metadata (RFC 8414)", asURL))
		if as.Issuer != cfg.Issuer {
			add(check.Bad("Metadata issuer", "the metadata names a different issuer", "Configure the issuer exactly as the metadata reports it.").Mismatch(as.Issuer, cfg.Issuer))
		}
	case odErr == nil:
		p = od
		add(check.Note("Authorization server metadata (RFC 8414)", "not found; using OpenID Connect discovery instead"))
	default:
		s.event(f, LError, "Metadata", 0, "", "%v; %v", asErr, odErr)
		add(check.Bad("Server metadata", "neither RFC 8414 metadata nor OpenID Connect discovery could be loaded", "Check the issuer URL."))
		res.All = nil
		return
	}
	if as != nil && od != nil {
		var diff []string
		for _, pair := range [][3]string{{"issuer", as.Issuer, od.Issuer}, {"authorization_endpoint", as.AuthorizationEndpoint, od.AuthorizationEndpoint},
			{"token_endpoint", as.TokenEndpoint, od.TokenEndpoint}, {"jwks_uri", as.JWKSURI, od.JWKSURI}} {
			if pair[1] != "" && pair[2] != "" && pair[1] != pair[2] {
				diff = append(diff, fmt.Sprintf("%s: %s vs %s", pair[0], pair[1], pair[2]))
			}
		}
		if len(diff) > 0 {
			add(check.Bad("Metadata agreement", "OAuth metadata and OpenID discovery disagree: "+strings.Join(diff, "; "), "Clients that read different documents will behave differently."))
		} else {
			add(check.OK("Metadata agreement", "OAuth metadata and OpenID discovery agree"))
		}
	}
	switch {
	case slices.Contains(p.CodeChallengeMethods, "plain"):
		add(check.Bad("Advertised PKCE methods", "plain is advertised", "OAuth 2.1 forbids plain: it does not protect the code if it is intercepted. Advertise and accept S256 only."))
	case slices.Contains(p.CodeChallengeMethods, "S256"):
		add(check.OK("Advertised PKCE methods", "S256"))
	default:
		add(check.Meh("Advertised PKCE methods", "code_challenge_methods_supported is missing", "Clients use this to know PKCE is supported."))
	}
	for _, rt := range p.ResponseTypes {
		if strings.Contains(rt, "token") {
			add(check.Meh("Advertised response types", "includes "+rt, "OAuth 2.1 removes the implicit and hybrid flows. Advertise code only."))
			break
		}
	}
	for _, gt := range p.GrantTypes {
		if gt == "password" || gt == "implicit" {
			add(check.Bad("Advertised grant types", gt+" is advertised", "OAuth 2.1 removes this grant."))
		}
	}

	// Authorize-endpoint probes, without following redirects. A server that
	// shows its sign-in page first can't be judged here: those are listed
	// together as not tested, not as warnings.
	var untested []string
	probe := func(name string, o oidc.AuthOptions, okWhat, failWhat, fix string) {
		variant := o.RedirectURI != ""
		u, err := oidc.AuthURLWith(cfg, p, oidc.RandomString(12), "", oidc.RandomString(48), o)
		if err != nil {
			return
		}
		pr, err := oidc.ProbeAuthorize(ctx, u)
		redirect := cfg.RedirectURI
		if o.RedirectURI != "" {
			redirect = o.RedirectURI
		}
		verdict, detail := classifyProbe(pr, err, redirect, variant)
		if verdict == "fail" && !variant && failWhat != "" {
			detail = failWhat
		}
		s.event(f, map[string]Level{"pass": LInfo, "fail": LError, "unknown": LWarn}[verdict], "Probe", 0, prettyURL(u)+"\n\nAnswer: "+detail, "%s: %s", name, detail)
		switch verdict {
		case "pass":
			add(check.OK(name, okWhat+" ("+detail+")"))
		case "fail":
			add(check.Bad(name, detail, fix))
		default:
			untested = append(untested, name)
		}
	}
	probe("PKCE required", oidc.AuthOptions{NoPKCE: true, Resource: resource}, "refused an authorize request without PKCE", "the server issued a code without a code challenge",
		"OAuth 2.1 requires PKCE. Turn on PKCE enforcement for this client at the IdP.")
	probe("Plain PKCE refused", oidc.AuthOptions{Method: "plain", Resource: resource}, "refused code_challenge_method=plain", "the server accepted code_challenge_method=plain",
		"OAuth 2.1 forbids plain. Accept only S256.")
	probe("Implicit flow removed", oidc.AuthOptions{ResponseType: "token", Resource: resource}, "refused response_type=token", "the server returned a token for response_type=token",
		"OAuth 2.1 removes the implicit flow. Turn it off for this client.")
	probe("Hybrid flow removed", oidc.AuthOptions{ResponseType: "code id_token", Resource: resource}, "refused response_type=code id_token", "the server returned a token for response_type=code id_token",
		"Return tokens only from the token endpoint.")
	for _, v := range redirectVariants(cfg.RedirectURI) {
		probe("Exact redirect URI match ("+v.name+")", oidc.AuthOptions{RedirectURI: v.uri, Resource: resource}, "refused "+v.uri, "",
			"OAuth 2.1 requires an exact redirect URI match. Remove wildcards and loose matching for this client.")
	}

	if len(untested) > 0 {
		add(check.Note("Not tested before sign-in", fmt.Sprintf("the server shows its sign-in page before checking these, which is allowed: %s. "+
			"The guided checks on the app page test PKCE with a real sign-in.", strings.Join(untested, "; "))))
	}

	// The password grant must be gone.
	tok, status, err := oidc.PasswordGrant(ctx, cfg, p)
	e := oidc.OAuthError(tokRaw(tok))
	s.event(f, LInfo, "Probe", 0, string(tokRaw(tok)), "Password grant: HTTP %d %s", status, e)
	switch {
	case err == nil:
		add(check.Bad("Password grant removed", "the server issued tokens for the password grant", "OAuth 2.1 removes the password grant. Turn it off."))
	case e == "unsupported_grant_type" || e == "unauthorized_client":
		add(check.OK("Password grant removed", "refused ("+e+")"))
	case status >= 400 && status < 500 && e != "" && e != "invalid_grant" && strings.Contains(strings.ReplaceAll(e, "_", ""), "granttype"):
		add(check.OK("Password grant removed", "refused, with the nonstandard error "+e+" (the standard code is unsupported_grant_type)"))
	default:
		add(check.Meh("Password grant removed", fmt.Sprintf("answered %s, not unsupported_grant_type", nameOr(e, fmt.Sprintf("HTTP %d", status))),
			"The server may be trying to sign the probe user in. It should refuse the grant type outright."))
	}
	add(check.Note("Checks that need a sign-in", "code single use and refresh token rotation run on every Test sign-in; PKCE enforcement and verifier binding have guided checks on the app page"))
	res.All = []Section{discoverySection(p)}
}

type variant struct{ name, uri string }

// redirectVariants are near-misses of the registered redirect URI that an
// exact-matching server must refuse.
func redirectVariants(registered string) []variant {
	u, err := url.Parse(registered)
	if err != nil {
		return nil
	}
	vs := []variant{{"trailing slash", registered + "/"}}
	q := *u
	q.RawQuery = "x=1"
	vs = append(vs, variant{"extra query parameter", q.String()})
	up := *u
	up.Path = strings.ToUpper(u.Path)
	if up.Path != u.Path {
		vs = append(vs, variant{"different case", up.String()})
	}
	sub := *u
	sub.Host = "evil." + u.Host
	vs = append(vs, variant{"another host", sub.String()})
	return vs
}

// classifyProbe reads an authorize answer. For a probe with a deliberately
// wrong redirect URI (variant), any redirect to that URI fails: sending the
// browser to an unregistered URI, even with an error, is an open redirector.
// Otherwise an error redirect to the registered URI, or an HTTP error page,
// means refused; a code or token means accepted; a sign-in page means the
// server can't tell yet.
func classifyProbe(pr oidc.ProbeResult, err error, redirect string, variant bool) (verdict, detail string) {
	if err != nil {
		return "unknown", err.Error()
	}
	if loc := pr.Location; loc != "" {
		lu, perr := url.Parse(loc)
		ru, rerr := url.Parse(redirect)
		if perr == nil && rerr == nil && strings.EqualFold(lu.Scheme, ru.Scheme) && strings.EqualFold(lu.Host, ru.Host) && lu.Path == ru.Path {
			if variant {
				return "fail", "the server redirected the browser to the unregistered URI"
			}
			vals := lu.Query()
			if frag, err := url.ParseQuery(lu.Fragment); err == nil {
				for k, v := range frag {
					vals[k] = v
				}
			}
			if e := vals.Get("error"); e != "" {
				return "pass", "error " + e
			}
			if vals.Get("code") != "" || vals.Get("access_token") != "" {
				return "fail", "the server redirected to it with a code or token"
			}
			return "fail", "the server redirected the browser to it"
		}
		return "unknown", "redirected to " + hostOf(loc)
	}
	if pr.Status >= 400 {
		return "pass", fmt.Sprintf("HTTP %d error page", pr.Status)
	}
	return "unknown", fmt.Sprintf("HTTP %d page, probably sign-in", pr.Status)
}

// oauthProbeSignIn starts a guided check that needs a real sign-in.
func (s *Server) oauthProbeSignIn(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil || !app.IsOAuth() {
		http.NotFound(w, r)
		return
	}
	mode := r.PathValue("mode")
	if mode != ModeNoPKCE && mode != ModeWrongVerifier {
		http.NotFound(w, r)
		return
	}
	s.oauthSignIn(w, r, app, ViaConsole, mode)
}
