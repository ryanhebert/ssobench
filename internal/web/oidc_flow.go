package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/decode"
	"github.com/ryanhebert/ssobench/internal/oidc"
)

// oidcSignIn starts the authorization code flow for app.
func (s *Server) oidcSignIn(w http.ResponseWriter, r *http.Request, app *App, via string) {
	s.mu.Lock()
	cfg := withHints(app.OIDCConfig(), app.AcrValues, app.LoginHint)
	s.mu.Unlock()
	cfg.RedirectURI = s.redirectFor(r, app)
	if cfg.Scopes == "" {
		cfg.Scopes = "openid"
	}
	if cfg.Issuer == "" || cfg.ClientID == "" {
		s.appError(w, r, app, "Enter the issuer URL and the client ID in this app's settings.")
		return
	}

	f := s.newFlow("OIDC", s.appName(app))
	secret := "not set (public client)"
	if cfg.ClientSecret != "" {
		secret = "set (not logged)"
	}
	s.event(f, LInfo, "Configuration", 0, fmt.Sprintf("app           %s\nissuer        %s\nclient_id     %s\nclient secret %s\nscopes        %s\nredirect_uri  %s\nextra params  %s",
		s.appName(app), cfg.Issuer, cfg.ClientID, secret, cfg.Scopes, cfg.RedirectURI, cfg.ExtraParams), "Starting sign-in with client %s, client secret %s", cfg.ClientID, secret)

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	p, err := oidc.Discover(ctx, cfg.Issuer)
	if err != nil {
		s.event(f, LError, "Discovery", time.Since(t0), "", "GET %s failed: %v", oidc.DiscoveryURL(cfg.Issuer), err)
		s.finish(f, "", "stopped: discovery failed")
		s.appError(w, r, app, fmt.Sprintf("Could not load %s: %v", oidc.DiscoveryURL(cfg.Issuer), err))
		return
	}
	s.event(f, LInfo, "Discovery", time.Since(t0), discoveryDetail(p), "Loaded %s", oidc.DiscoveryURL(cfg.Issuer))
	s.mu.Lock()
	app.provider, app.providerAt = p, time.Now()
	s.mu.Unlock()

	state, nonce, verifier := oidc.RandomString(24), oidc.RandomString(24), oidc.RandomString(48)
	u, err := oidc.AuthURL(cfg, p, state, nonce, verifier)
	if err != nil {
		s.event(f, LError, "Authorize request", 0, "", "%v", err)
		s.finish(f, "", "stopped: could not build the authorize request")
		s.appError(w, r, app, err.Error())
		return
	}
	s.event(f, LInfo, "Authorize request", 0, prettyURL(u),
		"Sending the browser to the authorization endpoint (code flow, PKCE S256)")
	s.pendingOIDC.Put(state, &codePending{app: app, cfg: cfg, provider: p, nonce: nonce, verifier: verifier, started: time.Now(), flow: f, via: via})
	http.Redirect(w, r, u, http.StatusFound)
}

func discoveryDetail(p *oidc.Provider) string {
	return fmt.Sprintf("issuer                 %s\nauthorization_endpoint %s\ntoken_endpoint         %s\nuserinfo_endpoint      %s\njwks_uri               %s\ntoken auth methods     %s\nPKCE methods           %s",
		p.Issuer, p.AuthorizationEndpoint, p.TokenEndpoint, p.UserinfoEndpoint, p.JWKSURI,
		strings.Join(p.TokenAuthMethods, ", "), strings.Join(p.CodeChallengeMethods, ", "))
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pend, _ := s.pendingOIDC.Take(q.Get("state"))

	res := &Result{Kind: "OIDC", Via: ViaConsole}
	var f *Flow
	var app *App
	defer func() {
		s.save(res, f)
		http.Redirect(w, r, s.landing(res, app), http.StatusSeeOther)
	}()
	params := Section{Group: GroupRaw, Title: "Callback parameters", Rows: queryRows(q)}

	if pend == nil {
		f = s.unknownState(res, "OIDC", params)
		return
	}
	f = pend.flow
	cfg, p := pend.cfg, pend.provider
	res.AppID, res.AppName, res.Via, app = pend.app.ID, s.appName(pend.app), pend.via, pend.app
	if q.Get("error") == "" {
		s.event(f, LInfo, "Callback", 0, rowsText(params.Rows), "Browser returned from the identity provider, %s after the request", humanDur(time.Since(pend.started)))
	}
	res.Title, res.Issuer = cfg.Issuer, cfg.Issuer
	res.Checks = append(res.Checks, check.OK("State", "matches the request"))
	res.Checks = append(res.Checks, oidc.CheckDiscovery(cfg, p)...)

	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		s.event(f, LError, "Callback", 0, rowsText(params.Rows), "Browser returned with an error, %s after the request: %s", humanDur(time.Since(pend.started)), msg)
		res.Refused = msg
		res.Checks = append(res.Checks, check.Bad("Authorization", msg, oauthFix(e)))
		res.All = []Section{params, discoverySection(p)}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t0 := time.Now()
	tok, err := oidc.Exchange(ctx, cfg, p, q.Get("code"), pend.verifier)
	reqDetail := fmt.Sprintf("POST %s\nclient authentication  %s\ngrant_type             authorization_code\ncode                   %s\nredirect_uri           %s\ncode_verifier          (sent, not logged)",
		p.TokenEndpoint, oidc.AuthMethod(cfg, p), shortToken(q.Get("code")), cfg.RedirectURI)
	if err != nil {
		if tok != nil && len(tok.Raw) > 0 {
			reqDetail += "\n\nResponse:\n" + string(tok.Raw)
		}
		s.event(f, LError, "Token exchange", time.Since(t0), reqDetail, "%v", err)
		fix := tokenFix(err.Error())
		if cfg.ClientSecret == "" && clientCredentialError(err.Error()) {
			fix = noSecretFix
		}
		res.Checks = append(res.Checks, check.Bad("Token exchange", err.Error(), fix))
		res.All = []Section{params, discoverySection(p)}
		return
	}
	s.event(f, LInfo, "Token exchange", time.Since(t0), reqDetail+"\n\nResponse:\n"+shortenTokens(tok.Raw),
		"Redeemed the code: received %s", tokenKinds(tok))
	res.Checks = append(res.Checks, check.OK("Token exchange", "code redeemed at "+p.TokenEndpoint))

	var idt *oidc.JWT
	if tok.IDToken == "" {
		res.Checks = append(res.Checks, check.Bad("ID token", "token response has no id_token",
			"Include the openid scope; without it this is plain OAuth, not OpenID Connect."))
	} else if idt, err = oidc.ParseJWT(tok.IDToken); err != nil {
		s.event(f, LError, "ID token", 0, "", "Could not parse: %v", err)
		res.Checks = append(res.Checks, check.Bad("ID token", err.Error(), "The id_token is not a well-formed JWT. Check the provider's token settings for this app, or paste the token into Decode to see what arrived."))
	} else {
		res.IDToken = tok.IDToken
		s.event(f, LInfo, "ID token", 0, string(idt.HeaderRaw), "alg %s, kid %q, sub %q", idt.Alg(), idt.Kid(), idt.Str("sub"))
		t1 := time.Now()
		jwks, _, err := oidc.FetchJWKS(ctx, p.JWKSURI)
		if err != nil {
			s.event(f, LError, "JWKS", time.Since(t1), "", "GET %s failed: %v", p.JWKSURI, err)
			res.Checks = append(res.Checks, check.Bad("JWKS", err.Error(), "The signing keys could not be loaded from jwks_uri."))
		} else {
			s.event(f, LInfo, "JWKS", time.Since(t1), "", "Loaded %d keys (kids: %s)", len(jwks.Keys), strings.Join(jwks.Kids(), ", "))
		}
		res.Checks = append(res.Checks, oidc.CheckIDToken(idt, oidc.Expect{
			Config: cfg, Provider: p, JWKS: jwks, Nonce: pend.nonce, Now: time.Now(), Skew: s.Skew,
		}, tok.AccessToken)...)
		res.Subject = firstNonEmpty(idt.Str("email"), idt.Str("preferred_username"), idt.Str("upn"), idt.Str("sub"))
		res.Sub, res.SID = idt.Str("sub"), idt.Str("sid")
		res.Auth = oidcAuthInfo(idt, pend.started, cfg.ExtraParams)
		res.Checks = append(res.Checks, authChecks(res.Auth, time.Now(), s.Skew)...)
		res.Checks = append(res.Checks, hintChecks(idt, cfg.ExtraParams)...)
		res.Title = res.Subject + " at " + cfg.Issuer
		user, token := splitClaims(claimsSection(GroupIdentity, "Claims about the user", idt, true))
		res.All = append(res.All, user, token)
	}

	var uiClaims map[string]any
	defer func() {
		var idClaims map[string]any
		if idt != nil {
			idClaims = idt.Claims
		}
		rows, rs := inspectScopes(cfg.Scopes, tok.Scope, claimNames(idClaims, uiClaims), tok.RefreshToken != "")
		res.Scopes = rows
		res.Checks = append(res.Checks, rs...)
	}()
	if tok.AccessToken != "" {
		if at, err := oidc.ParseJWT(tok.AccessToken); err == nil {
			sec := claimsSection(GroupDetail, "Access token claims", at, true)
			sec.Note = "The access token is a JWT, but it is meant for the API in aud, not for this app. Its signature is not checked here."
			res.All = append(res.All, sec)
		} else {
			res.Checks = append(res.Checks, check.Note("Access token", "opaque (not a JWT); only the API it was issued for can read it"))
		}
		if p.UserinfoEndpoint != "" {
			t2 := time.Now()
			body, err := oidc.Userinfo(ctx, p, tok.AccessToken)
			if err != nil {
				s.event(f, LWarn, "UserInfo", time.Since(t2), "", "GET %s failed: %v", p.UserinfoEndpoint, err)
				res.Checks = append(res.Checks, check.Meh("UserInfo", err.Error(),
					"The access token may be for another API. For example, Microsoft Graph tokens only work at Graph."))
			} else {
				s.event(f, LInfo, "UserInfo", time.Since(t2), indent(body), "Loaded %s", p.UserinfoEndpoint)
				res.Checks = append(res.Checks, userinfoCheck(body, idt))
				uiClaims = userinfoClaims(body)
				sec := Section{Group: GroupDetail, Title: "UserInfo response", Pre: indent(body), Open: true}
				if j, err := oidc.ParseJWT(strings.TrimSpace(string(body))); err == nil {
					sec = claimsSection(GroupDetail, "UserInfo response (signed JWT)", j, true)
					sec.Note = "The provider returned UserInfo as a JWT. Its signature is not checked here."
				}
				res.All = append(res.All, sec)
			}
		}
	}

	res.All = append(res.All,
		Section{Group: GroupRaw, Title: "Token response", Pre: redactRefresh(tok.Raw)},
		params, discoverySection(p))
	if idt != nil {
		res.All = append(res.All, Section{Group: GroupRaw, Title: "ID token header", Pre: indent(idt.HeaderRaw)},
			Section{Group: GroupRaw, Title: "ID token (encoded)", Pre: idt.Raw})
	}
}

func oauthFix(code string) string {
	switch code {
	case "invalid_client", "unauthorized_client":
		return "The client ID is wrong, or the client is not allowed to use the authorization code flow."
	case "invalid_scope":
		return "One of the requested scopes is not allowed for this client."
	case "access_denied":
		return "The user cancelled, or isn't allowed to use this application. If they should be, assign the user (or a group they're in) to the application at your identity provider, then test again."
	case "invalid_request":
		return "Often a redirect URI that is not registered for this client. At your identity provider, register exactly the redirect URI shown under Set up on the app's page."
	}
	return "Read the error description above, and the identity provider's sign-in log."
}

func tokenFix(msg string) string {
	switch {
	case strings.Contains(msg, "invalid_client"), strings.Contains(strings.ToLower(msg), "client credential"):
		return "The client secret is wrong or expired, or the client expects a different authentication method."
	case strings.Contains(msg, "invalid_grant"):
		return "The code was already used or expired, or the redirect URI differs from the one in the authorize request."
	}
	return "Read the response body above."
}

func claimsSection(group, title string, j *oidc.JWT, open bool) Section {
	sec := Section{Group: group, Title: title, Open: open}
	for _, k := range sortedKeys(j.Claims) {
		row := Row{K: k, V: display(j.Claims[k])}
		if slices.Contains(decode.TimeClaims, k) {
			if t, ok := oidc.NumericDate(j.Claims[k]); ok {
				row.Hint = check.When(t, time.Now())
			}
		}
		sec.Rows = append(sec.Rows, row)
	}
	sec.Pre = indent(j.ClaimsRaw)
	return sec
}

func discoverySection(p *oidc.Provider) Section {
	return Section{Group: GroupRaw, Title: "Discovery document", Pre: indent(p.Raw)}
}

// splitClaims separates the claims about the person from the token's own
// plumbing (iss, aud, exp, nonce...), which go to an "ID token" section.
func splitClaims(all Section) (user, token Section) {
	user = Section{Group: GroupIdentity, Title: "Claims about the user", Open: true}
	token = Section{Group: GroupDetail, Title: "ID token", Open: true, Pre: all.Pre}
	for _, row := range all.Rows {
		if k := normKey(row.K); technicalClaims[k] && k != "sub" {
			token.Rows = append(token.Rows, row)
		} else {
			user.Rows = append(user.Rows, row)
		}
	}
	return user, token
}

// noSecretFix explains the most common cause of a rejected client after a
// restart: the secret is held in memory only.
const noSecretFix = "SSOBench has no client secret for this app. Secrets are kept in memory only and are cleared whenever SSOBench restarts. Enter it again in the app's Settings, then test again."

func clientCredentialError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "invalid_client") || strings.Contains(m, "client credential") || strings.Contains(m, "client authentication")
}

// userinfoCheck compares the sub in a UserInfo response, plain JSON or a
// JWT, with the ID token's.
func userinfoCheck(body []byte, idt *oidc.JWT) check.Result {
	var sub string
	if j, err := oidc.ParseJWT(strings.TrimSpace(string(body))); err == nil {
		sub = j.Str("sub")
	} else {
		var ui map[string]any
		if err := json.Unmarshal(body, &ui); err != nil {
			return check.Bad("UserInfo", "the response is neither JSON nor a JWT", "UserInfo must return a JSON object, or a signed JWT.")
		}
		sub, _ = ui["sub"].(string)
	}
	switch {
	case sub == "":
		return check.Bad("UserInfo subject (sub)", "missing", "UserInfo must always return sub, so its claims can be tied to the ID token.")
	case idt == nil:
		return check.Note("UserInfo", fmt.Sprintf("sub %q; there is no ID token to compare it with", sub))
	case sub != idt.Str("sub"):
		return check.Bad("UserInfo subject (sub)", fmt.Sprintf("%q differs from the ID token's %q", sub, idt.Str("sub")),
			"Never merge UserInfo claims when sub differs.")
	}
	return check.OK("UserInfo", "sub matches the ID token")
}

// userinfoClaims reads a UserInfo response, plain JSON or a JWT.
func userinfoClaims(body []byte) map[string]any {
	if j, err := oidc.ParseJWT(strings.TrimSpace(string(body))); err == nil {
		return j.Claims
	}
	var m map[string]any
	json.Unmarshal(body, &m)
	return m
}
