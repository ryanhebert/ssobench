package web

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
)

// settingsPatch is what a submitted settings form changes. The connect
// step and Settings send different sets of fields, so anything a form
// did not include is nil (or has* false) and keeps its value.
type settingsPatch struct {
	appForm
	SignAuthn bool
	Request   *requestPatch // SAML request options
	// OpenID Connect and OAuth 2.1
	NewSecret               string
	ClearSecret, KeepSecret bool
	Extra, Acr, Hint        *string
	Resource, MachineScopes *string
	// Every app
	Expected   *[]ExpectedAttr
	IdPLanding string
	Features   *featurePatch // the Features fieldset
	// Errs are fields the form got wrong; nothing is saved when set.
	Errs map[string]FieldError
}

type requestPatch struct {
	NameIDFormat string
	AuthnContext []string
	Comparison   string
	IsPassive    bool
	Encrypt      bool
}

type featurePatch struct {
	Logout, LoginURL, RelayStateOn bool
	IdPSLOURL                      string
	SessionMinutes, IdleMinutes    *int // nil: not one of the choices, keep
	Directory, JIT                 bool
	MatchKey, MatchAttr            string
	SCIMPublic                     string
}

// parseSettings reads a settings form. It does no I/O and takes no locks.
func parseSettings(r *http.Request) settingsPatch {
	r.ParseForm()
	sent := func(k string) bool { _, ok := r.Form[k]; return ok }
	str := func(k string) *string {
		if !sent(k) {
			return nil
		}
		v := strings.TrimSpace(r.FormValue(k))
		return &v
	}
	on := func(k string) bool { return r.FormValue(k) != "" }
	p := settingsPatch{appForm: readAppForm(r), SignAuthn: on("sign_authn"),
		NewSecret: r.FormValue("client_secret"), ClearSecret: on("clear_secret"), KeepSecret: on("keep_secret"),
		Extra: str("extra"), Resource: str("resource"), MachineScopes: str("machine_scopes")}
	if sent("acr_values") {
		p.Acr, p.Hint = str("acr_values"), str("login_hint")
	}
	if sent("nameid_format") {
		rp := &requestPatch{AuthnContext: strings.Fields(r.FormValue("authn_context")), IsPassive: on("is_passive"), Encrypt: on("encrypt")}
		for _, f := range nameIDFormats {
			if f.URI == r.FormValue("nameid_format") {
				rp.NameIDFormat = f.URI
			}
		}
		if c := r.FormValue("authn_comparison"); slices.Contains(authnComparisons, c) && c != "exact" {
			rp.Comparison = c
		}
		p.Request = rp
	}
	if sent("expected") {
		e := parseExpected(r.FormValue("expected"))
		p.Expected = &e
	}
	if v := r.FormValue("idp_landing"); v == LandProfile || v == LandDiagnostics {
		p.IdPLanding = v
	}
	if on("optional") {
		fp := &featurePatch{Logout: on("logout"), LoginURL: on("login_url"), RelayStateOn: on("relay_state_on"),
			IdPSLOURL: strings.TrimSpace(r.FormValue("idp_slo_url")), Directory: on("directory"), JIT: on("jit"),
			MatchKey: MatchNameID, MatchAttr: strings.TrimSpace(r.FormValue("match_attr"))}
		if m, err := strconv.Atoi(r.FormValue("session_minutes")); err == nil && slices.Contains(lifetimeChoices, m) {
			fp.SessionMinutes = &m
		}
		if m, err := strconv.Atoi(r.FormValue("idle_minutes")); err == nil && slices.Contains(idleChoices, m) {
			fp.IdleMinutes = &m
		}
		if v, ok := publicOrigin(r.FormValue("scim_public")); ok {
			fp.SCIMPublic = v
		} else {
			p.Errs = map[string]FieldError{"scim_public": {Msg: "Enter an address such as https://scim.example.com, with no path."}}
		}
		if k := r.FormValue("match_key"); k == MatchEmail || k == MatchUsername || (k == MatchAttr && fp.MatchAttr != "") {
			fp.MatchKey = k
		}
		p.Features = fp
	}
	return p
}

// apply makes the patch's changes to app, except the identity provider
// connection (metadata or discovery), which needs I/O and is the
// handler's job. Call it with s.mu held. It returns the URLs that turned
// on and now need registering at the identity provider.
func (p settingsPatch) apply(app *App, persisting bool) (added []string) {
	if p.Name != "" {
		app.Name = p.Name
	}
	if app.IsSAML() {
		app.ForceAuthn, app.SignAuthn = p.ForceAuthn, p.SignAuthn
		if rp := p.Request; rp != nil {
			app.NameIDFormat, app.AuthnContext, app.AuthnComparison = rp.NameIDFormat, rp.AuthnContext, rp.Comparison
			app.IsPassive, app.EncryptAssertions = rp.IsPassive, rp.Encrypt
		}
	} else {
		secret := app.ClientSecret
		if p.NewSecret != "" {
			secret = p.NewSecret
		}
		if p.ClearSecret {
			secret = ""
		}
		extra := app.ExtraParams
		if p.Extra != nil {
			extra = *p.Extra
		}
		app.Issuer, app.ClientID, app.ClientSecret = p.Issuer, p.ClientID, secret
		app.Scopes, app.ExtraParams = nameOr(p.Scopes, defaultScopes), extra
		app.KeepSecret = persisting && p.KeepSecret
		if p.Acr != nil {
			app.AcrValues, app.LoginHint = *p.Acr, *p.Hint
		}
		if app.IsOAuth() {
			if p.Resource != nil {
				app.Resource = *p.Resource
			}
			if p.MachineScopes != nil {
				app.MachineScopes = *p.MachineScopes
			}
		}
	}
	if p.Expected != nil && !app.IsOAuth() {
		app.Expected = *p.Expected
	}
	if p.IdPLanding != "" {
		app.IdPLanding = p.IdPLanding
	}
	fp := p.Features
	if fp == nil {
		return nil
	}
	saml := app.IsSAML()
	if fp.Logout && !app.Logout {
		added = append(added, map[bool]string{true: "single logout URL", false: "post-logout redirect URI"}[saml])
	}
	if fp.LoginURL && !app.LoginURL {
		added = append(added, map[bool]string{true: "service provider login URL", false: "initiate login URI"}[saml])
	}
	if saml && fp.RelayStateOn && !app.RelayStateOn {
		added = append(added, "default relay state")
	}
	app.Logout, app.LoginURL, app.RelayStateOn = fp.Logout, fp.LoginURL, saml && fp.RelayStateOn
	if saml {
		app.IdPSLOURL = fp.IdPSLOURL
	}
	if fp.SessionMinutes != nil {
		app.SessionMinutes = *fp.SessionMinutes
	}
	if fp.IdleMinutes != nil {
		app.IdleMinutes = *fp.IdleMinutes
	}
	if fp.Directory {
		if !app.Directory {
			added = append(added, "SCIM base URL and token")
		}
		app.MatchKey, app.MatchAttr, app.JIT, app.SCIMPublic = fp.MatchKey, fp.MatchAttr, fp.JIT, fp.SCIMPublic
		if app.SCIMToken == "" {
			app.SCIMToken = newSCIMToken()
		}
	}
	app.Directory = fp.Directory
	return added
}

// discover loads the identity provider's metadata for an OpenID Connect
// or OAuth 2.1 app, logging to f.
func (s *Server) discover(ctx context.Context, f *Flow, app *App, issuer string) (*oidc.Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t0 := time.Now()
	var p *oidc.Provider
	var err error
	if app.IsOAuth() {
		p, _, err = s.oauthProvider(ctx, f, app, issuer)
	} else {
		p, err = oidc.Discover(ctx, issuer)
	}
	if err != nil {
		s.event(f, LError, "Discovery", time.Since(t0), "", "GET %s failed: %v", oidc.DiscoveryURL(issuer), err)
		return nil, err
	}
	s.event(f, LInfo, "Discovery", time.Since(t0), discoveryDetail(p), "Loaded %s", oidc.DiscoveryURL(issuer))
	return p, nil
}

// issuerFieldError explains a discovery failure next to the issuer field.
func issuerFieldError(issuer string, err error) FieldError {
	fe := friendlyLoadError(oidc.DiscoveryURL(issuer), err)
	fe.Msg += " The issuer URL is the part before /.well-known/openid-configuration."
	return fe
}

// metadataFieldError explains a metadata failure next to the field used.
func metadataFieldError(mdURL string, err error) (string, FieldError) {
	if mdURL == "" {
		return "metadata_xml", friendlyLoadError("", err)
	}
	return "metadata_url", friendlyLoadError(mdURL, err)
}
