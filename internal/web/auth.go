package web

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/oidc"
	"github.com/ryanhebert/ssobench/internal/saml"
)

// AuthInfo says how and when the person authenticated at the identity
// provider, which tells a fresh sign-in from a reused session.
type AuthInfo struct {
	Methods     []string  `json:"methods,omitempty"`     // in plain words
	Raw         []string  `json:"raw,omitempty"`         // as sent: context class refs, amr and acr values
	At          time.Time `json:"at,omitempty"`          // when the person authenticated
	Requested   time.Time `json:"requested,omitempty"`   // when SSOBench asked; zero when the IdP started it
	SessionEnds time.Time `json:"sessionEnds,omitempty"` // SAML SessionNotOnOrAfter
	Authorities []string  `json:"authorities,omitempty"`
	Asked       string    `json:"asked,omitempty"` // a fresh authentication SSOBench asked for, such as ForceAuthn
}

// reuseMargin is how far before the request an authentication may be and
// still count as made for it, allowing for clock differences.
const reuseMargin = 30 * time.Second

// Reused reports whether the identity provider used an existing session
// instead of authenticating the person for this sign-in.
func (a *AuthInfo) Reused() bool {
	return !a.Requested.IsZero() && !a.At.IsZero() && a.At.Before(a.Requested.Add(-reuseMargin))
}

// Freshness describes the authentication time against the request.
func (a *AuthInfo) Freshness() string {
	switch {
	case a.At.IsZero():
		return "Not stated"
	case a.Requested.IsZero():
		return "Before this sign-in, which the identity provider started"
	case a.Reused():
		return "Earlier: an existing session at the identity provider was reused, " + humanDur(a.Requested.Sub(a.At)) + " before this sign-in"
	}
	return "For this sign-in"
}

// classWords are common SAML authentication context classes in plain words.
var classWords = map[string]string{
	"PasswordProtectedTransport":  "Password, over an encrypted connection",
	"Password":                    "Password",
	"X509":                        "Certificate",
	"TLSClient":                   "Client certificate",
	"Smartcard":                   "Smart card",
	"SmartcardPKI":                "Smart card",
	"Kerberos":                    "Kerberos (Windows sign-in)",
	"unspecified":                 "Not stated",
	"TimeSyncToken":               "One-time code",
	"MobileTwoFactorContract":     "Two-factor on a phone",
	"MobileTwoFactorUnregistered": "Two-factor on a phone",
	"multipleauthn":               "Multi-factor",
	"mfa":                         "Multi-factor",
	"InternetProtocol":            "Network address",
	"PreviousSession":             "Previous session",
}

func classWord(ref string) string {
	last := ref
	if i := strings.LastIndexAny(ref, ":/"); i >= 0 && i < len(ref)-1 {
		last = ref[i+1:]
	}
	if w, ok := classWords[last]; ok {
		return w
	}
	return last
}

// samlAuthInfo reads the first AuthnStatement of a.
func samlAuthInfo(a *saml.Assertion, requested time.Time, force bool) *AuthInfo {
	if a == nil || len(a.AuthnStatements) == 0 {
		return nil
	}
	st := a.AuthnStatements[0]
	info := &AuthInfo{Requested: requested, Authorities: st.Authorities}
	if force {
		info.Asked = "ForceAuthn"
	}
	for _, ref := range []string{st.ClassRef, st.DeclRef} {
		if ref != "" {
			info.Raw = append(info.Raw, ref)
			info.Methods = append(info.Methods, classWord(ref))
		}
	}
	info.At, _ = time.Parse(time.RFC3339, st.AuthnInstant)
	info.SessionEnds, _ = time.Parse(time.RFC3339, st.SessionNotOnOrAfter)
	return info
}

// oidcAuthInfo reads auth_time, amr and acr from an ID token.
func oidcAuthInfo(idt *oidc.JWT, requested time.Time, extra string) *AuthInfo {
	info := &AuthInfo{Requested: requested}
	info.At, _ = idt.Time("auth_time")
	if amr, ok := idt.Claims["amr"].([]any); ok {
		for _, v := range amr {
			if s, ok := v.(string); ok {
				info.Raw = append(info.Raw, "amr "+s)
				if w, ok := amrWords[strings.ToLower(s)]; ok {
					info.Methods = append(info.Methods, w)
				} else {
					info.Methods = append(info.Methods, s)
				}
			}
		}
	}
	if acr := idt.Str("acr"); acr != "" {
		info.Raw = append(info.Raw, "acr "+acr)
		if len(info.Methods) == 0 {
			info.Methods = append(info.Methods, classWord(acr))
		}
	}
	q, _ := url.ParseQuery(strings.TrimPrefix(extra, "?"))
	switch {
	case strings.Contains(" "+q.Get("prompt")+" ", " login "):
		info.Asked = "prompt=login"
	case q.Get("max_age") != "":
		info.Asked = "max_age=" + q.Get("max_age")
	}
	if info.At.IsZero() && len(info.Methods) == 0 && info.Asked == "" {
		return nil
	}
	return info
}

// authChecks checks that a fresh authentication SSOBench asked for happened.
func authChecks(info *AuthInfo, now time.Time, skew time.Duration) []check.Result {
	if info == nil || info.Asked == "" || info.Requested.IsZero() {
		return nil
	}
	name := map[string]string{"ForceAuthn": "ForceAuthn", "prompt=login": "Fresh sign-in (prompt=login)"}[info.Asked]
	if maxAge, ok := strings.CutPrefix(info.Asked, "max_age="); ok {
		name = "Authentication age (max_age)"
		secs, err := strconv.Atoi(maxAge)
		switch {
		case err != nil:
			return nil
		case info.At.IsZero():
			return []check.Result{check.Bad(name, "max_age was sent, but the ID token has no auth_time",
				"OpenID Connect requires auth_time in the ID token when max_age is requested.")}
		case now.Sub(info.At) > time.Duration(secs)*time.Second+skew:
			return []check.Result{check.Bad(name, fmt.Sprintf("the person authenticated %s ago, more than max_age (%d seconds) allows", humanDur(now.Sub(info.At)), secs),
				"The provider should have asked the person to authenticate again. Check that it supports max_age.")}
		}
		return []check.Result{check.OK(name, fmt.Sprintf("authenticated %s ago, within %d seconds", humanDur(now.Sub(info.At)), secs))}
	}
	switch {
	case info.At.IsZero():
		return []check.Result{check.Meh(name, "sent, but the identity provider did not say when the person authenticated, so it can't be checked",
			"Send the authentication time (AuthnInstant or auth_time) with every sign-in.")}
	case info.Reused():
		return []check.Result{check.Bad(name, fmt.Sprintf("not honored: the identity provider reused a session from %s before the request", humanDur(info.Requested.Sub(info.At))),
			"The identity provider should ask the person to authenticate again. Some ignore this request, or only honor it for some authentication methods; check its settings.")}
	}
	return []check.Result{check.OK(name, "honored: the person authenticated again")}
}

// withHints adds acr_values and login_hint to the authorize parameters,
// unless the extra parameters already set them.
func withHints(cfg oidc.Config, acr, hint string) oidc.Config {
	q, _ := url.ParseQuery(strings.TrimPrefix(cfg.ExtraParams, "?"))
	if acr != "" && q.Get("acr_values") == "" {
		q.Set("acr_values", acr)
	}
	if hint != "" && q.Get("login_hint") == "" {
		q.Set("login_hint", hint)
	}
	cfg.ExtraParams = q.Encode()
	return cfg
}

// hintChecks checks acr and the signed-in person against the acr_values
// and login_hint sent.
func hintChecks(idt *oidc.JWT, extra string) []check.Result {
	var rs []check.Result
	q, _ := url.ParseQuery(strings.TrimPrefix(extra, "?"))
	if want := strings.Fields(q.Get("acr_values")); len(want) > 0 {
		switch got := idt.Str("acr"); {
		case got == "":
			rs = append(rs, check.Meh("Authentication level (acr)", "acr_values was sent, but the ID token has no acr claim",
				"Without acr the app can't tell how the person authenticated. Configure the provider to return acr, or request it as an essential claim."))
		case slices.Contains(want, got):
			rs = append(rs, check.OK("Authentication level (acr)", fmt.Sprintf("%s, one of the acr_values asked for", got)))
		default:
			rs = append(rs, check.Meh("Authentication level (acr)", fmt.Sprintf("%s, not one of the acr_values asked for (%s)", got, strings.Join(want, " ")),
				"acr_values is a request the provider may decline. An app that needs a stronger authentication must check acr and refuse the sign-in."))
		}
	}
	if hint := q.Get("login_hint"); hint != "" {
		who := []string{idt.Str("email"), idt.Str("preferred_username"), idt.Str("upn"), idt.Str("sub")}
		if slices.ContainsFunc(who, func(v string) bool { return v != "" && strings.EqualFold(v, hint) }) {
			rs = append(rs, check.OK("Login hint (login_hint)", "the person who signed in matches "+hint))
		} else {
			rs = append(rs, check.Note("Login hint (login_hint)", fmt.Sprintf("%s was suggested, but %s signed in; the provider may have let them choose another account", hint, firstNonEmpty(who...))))
		}
	}
	return rs
}
