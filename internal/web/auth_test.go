package web

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/oidc"
)

func authnStatement(at time.Time) string {
	return fmt.Sprintf(`<saml:AuthnStatement AuthnInstant="%s" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
		at.UTC().Format(time.RFC3339))
}

func TestAuthenticationPanelAndForceAuthn(t *testing.T) {
	t.Cleanup(func() { testAuthnStatement = "" })
	ks := dsig.RandomKeyStoreForTest()
	ts, c := newTestServer(t, "")
	id := createApp(t, c, ts.URL, url.Values{"protocol": {"saml"}, "name": {"Payroll"}, "metadata_xml": {metadataFor(ks, testIdP)}})

	// A session from an hour ago, reused: shown, and fine without ForceAuthn.
	testAuthnStatement = authnStatement(time.Now().Add(-time.Hour))
	loc := signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	_, page := get(t, c, ts.URL+loc)
	if !strings.Contains(page, "<h2>Authentication</h2>") || !strings.Contains(page, "Password, over an encrypted connection") || !strings.Contains(page, "an existing session at the identity provider was reused") {
		t.Errorf("authentication panel:\n%s", mainOf(page))
	}
	if failed(page) {
		t.Error("reused session failed without ForceAuthn")
	}

	// With ForceAuthn, the reused session fails the test.
	enable(t, c, ts.URL, id, metadataFor(ks, testIdP), url.Values{"force_authn": {"1"}})
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); !failed(page) || !strings.Contains(page, "not honored") {
		t.Errorf("ForceAuthn ignored but not reported:\n%s", mainOf(page))
	}

	// A fresh authentication passes.
	testAuthnStatement = authnStatement(time.Now())
	loc = signInVia(t, c, ts.URL, id, "/apps/"+id+"/signin", ks, "")
	if _, page := get(t, c, ts.URL+loc); failed(page) || !strings.Contains(page, "honored: the person authenticated again") || !strings.Contains(page, "For this sign-in") {
		t.Errorf("fresh authentication:\n%s", mainOf(page))
	}
}

func TestOIDCAuthInfo(t *testing.T) {
	now := time.Now()
	idt := &oidc.JWT{Claims: map[string]any{"auth_time": json.Number(fmt.Sprint(now.Add(-10 * time.Minute).Unix())), "amr": []any{"pwd", "mfa"}, "acr": "urn:example:loa2"}}
	info := oidcAuthInfo(idt, now, "max_age=60")
	if strings.Join(info.Methods, ", ") != "Password, Multi-factor" || info.Asked != "max_age=60" || !info.Reused() {
		t.Fatalf("%+v", info)
	}
	if got := authChecks(info, now, 2*time.Minute); len(got) != 1 || got[0].Status != "fail" {
		t.Errorf("max_age exceeded: %+v", got)
	}
	info = oidcAuthInfo(&oidc.JWT{Claims: map[string]any{"sub": "x"}}, now, "prompt=login")
	if got := authChecks(info, now, 0); len(got) != 1 || got[0].Status != "warn" {
		t.Errorf("prompt=login without auth_time: %+v", got)
	}
	if oidcAuthInfo(&oidc.JWT{Claims: map[string]any{"sub": "x"}}, now, "") != nil {
		t.Error("panel shown with nothing to show")
	}
}
