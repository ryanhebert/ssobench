package web

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/saml"
)

// nameIDFormats are the NameID formats an app can ask for, in the order
// Settings lists them.
var nameIDFormats = []struct{ URI, Label string }{
	{"", "Any (no format requested)"},
	{saml.NameIDEmail, "Email address"},
	{saml.NameIDPersistent, "Persistent"},
	{saml.NameIDTransient, "Transient"},
	{saml.NameIDUnspecified, "Unspecified"},
}

func nameIDLabel(uri string) string {
	for _, f := range nameIDFormats {
		if f.URI == uri {
			return f.Label
		}
	}
	return saml.Short(uri)
}

// authnComparisons are the RequestedAuthnContext comparisons.
var authnComparisons = []string{"exact", "minimum", "better", "maximum"}

// describeOpts says what an AuthnRequest asked for, for the log.
func describeOpts(o saml.AuthnOptions) string {
	parts := []string{fmt.Sprintf("ForceAuthn %t", o.ForceAuthn)}
	if o.IsPassive {
		parts = append(parts, "IsPassive")
	}
	if o.NameIDFormat != "" {
		parts = append(parts, "NameID format "+saml.Short(o.NameIDFormat))
	}
	if len(o.AuthnContext) > 0 {
		parts = append(parts, fmt.Sprintf("authentication context %s %s", nameOr(o.Comparison, "exact"), strings.Join(shortRefs(o.AuthnContext), " or ")))
	}
	return strings.Join(parts, ", ")
}

func shortRefs(refs []string) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = classWord(r)
	}
	return out
}

// requestChecks checks that the identity provider did what the
// AuthnRequest asked: the NameID format, the authentication context and a
// passive sign-in.
func requestChecks(o saml.AuthnOptions, a *saml.Assertion, auth *AuthInfo) []check.Result {
	var rs []check.Result
	if o.NameIDFormat != "" && o.NameIDFormat != saml.NameIDUnspecified {
		got := a.Subject.NameID.Format
		switch {
		case got == o.NameIDFormat:
			rs = append(rs, check.OK("NameID format", "asked for "+nameIDLabel(o.NameIDFormat)+", and got it"))
		case got == "":
			rs = append(rs, check.Meh("NameID format", "asked for "+nameIDLabel(o.NameIDFormat)+", but the NameID states no format",
				"The identity provider should send the format it was asked for, or refuse with InvalidNameIDPolicy. Check the NameID setting at the identity provider."))
		default:
			rs = append(rs, check.Meh("NameID format", fmt.Sprintf("asked for %s, but got %s", nameIDLabel(o.NameIDFormat), nameIDLabel(got)),
				"The identity provider should send the format it was asked for, or refuse with InvalidNameIDPolicy. Check the NameID setting at the identity provider."))
		}
	}
	if len(o.AuthnContext) > 0 {
		var got string
		if len(a.AuthnStatements) > 0 {
			got = a.AuthnStatements[0].ClassRef
		}
		cmp := nameOr(o.Comparison, "exact")
		asked := strings.Join(shortRefs(o.AuthnContext), " or ")
		switch {
		case got == "":
			rs = append(rs, check.Bad("Authentication context", "asked for "+asked+", but the assertion states no context",
				"The identity provider should state how the person authenticated, or refuse with NoAuthnContext."))
		case slices.Contains(o.AuthnContext, got):
			rs = append(rs, check.OK("Authentication context", "asked for "+asked+" ("+cmp+"), and got "+classWord(got)))
		case cmp == "exact":
			rs = append(rs, check.Bad("Authentication context", fmt.Sprintf("asked for exactly %s, but got %s", asked, classWord(got)),
				"The identity provider should authenticate the person the way it was asked to, or refuse with NoAuthnContext. Check which methods its policy allows for this app."))
		default:
			rs = append(rs, check.Note("Authentication context", fmt.Sprintf("asked for %s %s, and got %s; whether that is %s depends on how the identity provider ranks them",
				cmp, asked, classWord(got), map[string]string{"minimum": "at least as strong", "better": "stronger", "maximum": "no stronger"}[cmp])))
		}
	}
	if o.IsPassive && auth != nil && !auth.At.IsZero() {
		if auth.Reused() {
			rs = append(rs, check.OK("IsPassive", "honored: signed in with the existing session, without asking the person"))
		} else {
			rs = append(rs, check.Bad("IsPassive", "the person authenticated during a passive request",
				"With IsPassive the identity provider must not interact with the person: it should use an existing session or answer NoPassive."))
		}
	}
	return rs
}

// passiveStatus turns a NoPassive answer to a passive request from a
// failure into the expected outcome.
func passiveStatus(checks []check.Result, resp *saml.Response) {
	if sub := resp.Status.Code.Sub; sub == nil || saml.Short(sub.Value) != "NoPassive" {
		return
	}
	for i, c := range checks {
		if c.Name == "Status" {
			checks[i] = check.Note("Status", "NoPassive: there was no session at the identity provider, so it answered without asking the person, as IsPassive requires")
		}
	}
}
