package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func patchFrom(v url.Values) settingsPatch {
	r := httptest.NewRequest("POST", "/apps/x", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return parseSettings(r)
}

func TestSettingsRules(t *testing.T) {
	for _, c := range []struct {
		name  string
		app   App
		form  url.Values
		check func(*testing.T, *App, []string)
	}{
		{"match on an attribute with no name falls back to NameID", App{AppConfig: AppConfig{Protocol: ProtoSAML}},
			url.Values{"optional": {"1"}, "directory": {"1"}, "match_key": {"attr"}, "match_attr": {""}},
			func(t *testing.T, a *App, added []string) {
				if a.MatchKey != MatchNameID || a.SCIMToken == "" || len(added) != 1 {
					t.Errorf("match %q token %v added %v", a.MatchKey, a.SCIMToken != "", added)
				}
			}},
		{"durations outside the choices are ignored; Never idle is allowed", App{AppConfig: AppConfig{Protocol: ProtoSAML, SessionMinutes: 60, IdleMinutes: 15}},
			url.Values{"optional": {"1"}, "session_minutes": {"7"}, "idle_minutes": {"0"}},
			func(t *testing.T, a *App, _ []string) {
				if a.SessionMinutes != 60 || a.IdleMinutes != 0 {
					t.Errorf("session %d idle %d", a.SessionMinutes, a.IdleMinutes)
				}
			}},
		{"turning features on lists the URLs to register", App{AppConfig: AppConfig{Protocol: ProtoSAML}},
			url.Values{"optional": {"1"}, "logout": {"1"}, "login_url": {"1"}, "relay_state_on": {"1"}},
			func(t *testing.T, a *App, added []string) {
				if strings.Join(added, ", ") != "single logout URL, service provider login URL, default relay state" {
					t.Errorf("added %v", added)
				}
			}},
		{"OIDC has no relay state", App{AppConfig: AppConfig{Protocol: ProtoOIDC}},
			url.Values{"optional": {"1"}, "relay_state_on": {"1"}, "issuer": {"https://idp"}, "client_id": {"c"}},
			func(t *testing.T, a *App, added []string) {
				if a.RelayStateOn || len(added) != 0 {
					t.Errorf("relay %v added %v", a.RelayStateOn, added)
				}
			}},
		{"fields the form lacks keep their values", withSecret(AppConfig{Protocol: ProtoOAuth, Resource: "api://x", MachineScopes: "read", AcrValues: "mfa",
			Issuer: "https://idp", ClientID: "c", ExtraParams: "x=1"}, "secret"),
			url.Values{"issuer": {"https://idp"}, "client_id": {"c"}},
			func(t *testing.T, a *App, _ []string) {
				if a.Resource != "api://x" || a.MachineScopes != "read" || a.AcrValues != "mfa" || a.ExtraParams != "x=1" || a.ClientSecret != "secret" {
					t.Errorf("lost: %+v", a)
				}
			}},
		{"forget the secret; keep it only when saving state", withSecret(AppConfig{Protocol: ProtoOIDC, Issuer: "https://idp", ClientID: "c"}, "secret"),
			url.Values{"issuer": {"https://idp"}, "client_id": {"c"}, "clear_secret": {"1"}, "keep_secret": {"1"}},
			func(t *testing.T, a *App, _ []string) {
				if a.ClientSecret != "" || a.KeepSecret {
					t.Errorf("secret %q keep %v", a.ClientSecret, a.KeepSecret)
				}
			}},
		{"request options: unknown NameID format and exact comparison store as empty", App{AppConfig: AppConfig{Protocol: ProtoSAML}},
			url.Values{"nameid_format": {"urn:bogus"}, "authn_comparison": {"exact"}, "authn_context": {"a b"}},
			func(t *testing.T, a *App, _ []string) {
				if a.NameIDFormat != "" || a.AuthnComparison != "" || len(a.AuthnContext) != 2 {
					t.Errorf("%q %q %v", a.NameIDFormat, a.AuthnComparison, a.AuthnContext)
				}
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := c.app
			added := patchFrom(c.form).apply(&a, false)
			c.check(t, &a, added)
		})
	}
}

func withSecret(c AppConfig, secret string) App {
	return App{AppConfig: c, ClientSecret: secret}
}
