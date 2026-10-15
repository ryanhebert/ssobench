package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

// Section groups decide where a section appears on the result page.
const (
	GroupIdentity = "identity" // who signed in: attributes or ID token claims
	GroupDetail   = "detail"   // assertion details, access token, UserInfo
	GroupRaw      = "raw"      // XML, encoded tokens, protocol messages
)

func (r *Result) Tally() check.Tally { return check.Count(r.Checks) }

// Status is the overall outcome, used for badges and colours.
func (r *Result) Status() string {
	c := r.Tally()
	switch {
	case r.Refused != "" || c.Fail > 0:
		return "fail"
	case c.Warn > 0:
		return "warn"
	}
	return "pass"
}

// verbs words the outcome for what was run: a sign-in, a machine token, or
// a conformance run, which signs no one in.
func (r *Result) verbs() (ok, okWith, bad string) {
	switch {
	case r.Conformance:
		return "All checks passed", "Passed with", "Checks failed"
	case r.Machine:
		return "Token issued", "Token issued with", "No token"
	}
	if r.Kind == "OAUTH" {
		if c, ok := r.check("Token exchange"); ok && c.Status == check.Pass {
			return "Access granted", "Access granted with", "Token rejected"
		}
		return "Access granted", "Access granted with", "No token"
	}
	return "Signed in", "Signed in with", "Not signed in"
}

func (r *Result) check(name string) (check.Result, bool) {
	for _, x := range r.Checks {
		if x.Name == name {
			return x, true
		}
	}
	return check.Result{}, false
}

// OtherChecks are the checks not already listed under What to fix.
func (r *Result) OtherChecks() []check.Result {
	var out []check.Result
	for _, c := range r.Checks {
		if c.Status != check.Fail && c.Status != check.Warn {
			out = append(out, c)
		}
	}
	return out
}

// Headline is the one-sentence verdict at the top of the result page.
// Headline is the verdict, the same words on every screen.
func (r *Result) Headline() string {
	c := r.Tally()
	if r.Refused != "" {
		return "Sign-in refused by the identity provider"
	}
	if h := r.specialHeadline(c, false); h != "" {
		return h
	}
	return r.Summary()
}

// refusedCode is the OAuth or SAML error code of a refusal, without its
// description.
func (r *Result) refusedCode() string {
	code, _, _ := strings.Cut(r.Refused, ":")
	return strings.TrimSpace(code)
}

func (r *Result) Protocol() string {
	switch r.Kind {
	case "OIDC":
		return "OpenID Connect"
	case "OAUTH":
		return "OAuth 2.1"
	}
	return "SAML 2.0"
}

// DataLabel names the identity data the protocol carries.
func (r *Result) DataLabel() string {
	switch r.Kind {
	case "OIDC":
		return "Claims about the user"
	case "OAUTH":
		return "Token claims"
	}
	return "Attributes"
}

func (r *Result) Sections(group string) []Section {
	var out []Section
	for _, s := range r.All {
		if s.Group == group {
			out = append(out, s)
		}
	}
	return out
}

// IdentityCount is the number of attributes or claims received.
func (r *Result) IdentityCount() int {
	n := 0
	for _, s := range r.Sections(GroupIdentity) {
		n += len(s.Rows)
	}
	return n
}

func (r *Result) Problems() []check.Result {
	var out []check.Result
	for _, c := range r.Checks {
		if c.Status == check.Fail || c.Status == check.Warn {
			out = append(out, c)
		}
	}
	return out
}

func (r *Result) DurationText() string {
	if r.Duration <= 0 {
		return ""
	}
	return humanDur(r.Duration)
}

// Summary is the outcome in a few words, for lists.
// Summary is the outcome in a few words. One vocabulary for the result
// page, History, the app page and the log.
func (r *Result) Summary() string {
	c := r.Tally()
	switch {
	case r.Refused != "":
		return "Refused by the identity provider (" + r.refusedCode() + ")"
	}
	if h := r.specialHeadline(c, true); h != "" {
		return h
	}
	ok, okWith, bad := r.verbs()
	switch {
	case c.Fail > 0:
		return fmt.Sprintf("%s: %d %s failed", bad, c.Fail, plural(c.Fail, "check", "checks"))
	case c.Warn > 0:
		return fmt.Sprintf("%s %d %s", okWith, c.Warn, plural(c.Warn, "warning", "warnings"))
	}
	return ok
}

// Ref is the result ID formatted for reading out.
func (r *Result) Ref() string { return FormatRef(r.ID) }

// CertState describes a certificate's validity for a badge.
type CertState struct{ Class, Label string }

func certStatus(notAfter time.Time) CertState {
	d := time.Until(notAfter)
	switch {
	case d < 0:
		return CertState{"fail", "Expired"}
	case d < 30*24*time.Hour:
		return CertState{"warn", "Expires soon"}
	}
	return CertState{"pass", "Valid"}
}

// Rerun is the action that repeats what produced this result, and its label.
func (r *Result) Rerun() (path, label string) {
	switch {
	case r.Conformance:
		return "/conformance", "Run again"
	case r.Machine:
		return "/machine", "Run again"
	case r.Mode != "":
		return "/check/" + r.Mode, "Run again"
	}
	return "/signin", "Test again"
}

func (r *Result) RerunPath() string  { p, _ := r.Rerun(); return p }
func (r *Result) RerunLabel() string { _, l := r.Rerun(); return l }

// Who is the line under the headline: who signed in, or what was tested.
func (r *Result) Who() string {
	switch {
	case r.Conformance:
		return "Server conformance, no sign-in"
	case r.Machine && r.Subject != "":
		return "Machine token for client " + r.Subject
	case r.Machine:
		return "Machine token"
	case r.Subject != "":
		return r.Subject
	case r.Mode != "":
		return "Guided check"
	}
	return "No user was signed in"
}

// specialHeadline words outcomes that "N checks failed" would hide: a
// guided check, a conformance run, an account problem, a refused machine
// token.
func (r *Result) specialHeadline(c check.Tally, short bool) string {
	main := func(name string) (check.Result, bool) {
		for _, x := range r.Checks {
			if x.Name == name {
				return x, true
			}
		}
		return check.Result{}, false
	}
	switch {
	case r.Mode == ModeNoPKCE || r.Mode == ModeWrongVerifier:
		name := map[string]string{ModeNoPKCE: "PKCE required", ModeWrongVerifier: "PKCE verifier binding"}[r.Mode]
		x, ok := main(name)
		if !ok {
			return ""
		}
		switch x.Status {
		case check.Pass:
			return "Refused, as it should be"
		case check.Fail:
			if r.Mode == ModeNoPKCE {
				return "Accepted a sign-in without PKCE"
			}
			return "Accepted the wrong PKCE verifier"
		}
		if strings.HasPrefix(x.Detail, "could not tell") {
			return "Could not tell: the token endpoint did not answer"
		}
		return "Refused, but only when the code was redeemed"
	case r.Conformance:
		rules := c.Pass + c.Fail + c.Warn
		switch {
		case c.Fail > 0:
			return fmt.Sprintf("%d of %d OAuth 2.1 rules not met", c.Fail, rules)
		case c.Warn > 0:
			return fmt.Sprintf("OAuth 2.1 rules met, with %d %s", c.Warn, plural(c.Warn, "warning", "warnings"))
		}
		return "All tested OAuth 2.1 rules met"
	case r.Machine:
		if x, ok := main("Client credentials"); ok && x.Status == check.Fail {
			if short {
				if i, j := strings.LastIndex(x.Detail, "("), strings.LastIndex(x.Detail, ")"); i >= 0 && j > i {
					return "No machine token " + x.Detail[i:j+1]
				}
			}
			return "No machine token"
		}
	case r.AccountProblem == "notfound" && short:
		return "No account in this app"
	case r.AccountProblem == "notfound":
		return "No account for " + nameOr(r.AccountValue, "this user")
	case r.AccountProblem == "inactive" && short:
		return "Account deactivated"
	case r.AccountProblem == "inactive":
		return nameOr(r.AccountName, r.Account) + "'s account is deactivated"
	case r.AccountProblem == "missing":
		return "Nothing to match an account with"
	case r.AccessProblem == "denied" && short:
		return "No role in this app"
	case r.AccessProblem == "denied":
		return nameOr(r.AccountName, r.Subject) + " has no role in " + nameOr(r.AppName, "this app")
	}
	return ""
}

// IsSignIn reports whether the result is a person's sign-in, as opposed to
// a machine token or a conformance run.
func (r *Result) IsSignIn() bool { return !r.Machine && !r.Conformance }

// ShowIdentity reports whether the attributes or claims section has
// anything to show.
func (r *Result) ShowIdentity() bool {
	return r.IdentityCount() > 0 || (r.IsSignIn() && r.Mode == "" && r.Status() != "fail")
}

// Source says how the test started, to tell similar rows apart.
func (r *Result) Source() string {
	switch {
	case r.Via == ViaPage:
		return "Sign-in page"
	case r.Via == ViaIdP:
		return "Started at the IdP"
	}
	return "Console"
}

// RowTitle names a result in lists: who signed in, or what was tested.
func (r *Result) RowTitle() string {
	switch {
	case r.Conformance:
		return "OAuth 2.1 conformance"
	case r.Machine:
		return "Machine token" + map[bool]string{true: " for " + r.Subject}[r.Subject != ""]
	case r.Mode == ModeNoPKCE:
		return "Check: sign-in without PKCE"
	case r.Mode == ModeWrongVerifier:
		return "Check: wrong PKCE verifier"
	case r.Subject != "":
		return r.Subject
	}
	return "Test sign-in"
}

// Bucket is one of the result page's detail disclosures, holding sections.
type Bucket struct {
	Title    string
	Sections []Section
}

// Buckets groups the detail and raw sections into two disclosures: what
// was received (the assertion or the tokens) and the protocol messages.
func (r *Result) Buckets() []Bucket {
	what := Bucket{Title: "Tokens"}
	if r.Kind == "SAML" {
		what.Title = "Assertion"
	}
	msgs := Bucket{Title: "Protocol messages"}
	for _, sec := range r.All {
		if sec.Group != GroupDetail && sec.Group != GroupRaw {
			continue
		}
		t := strings.ToLower(sec.Title)
		message := strings.Contains(t, "response") || strings.Contains(t, "callback") || strings.Contains(t, "discovery") || strings.Contains(t, "xml")
		if message && sec.Title != "Response and assertion" {
			msgs.Sections = append(msgs.Sections, sec)
		} else {
			what.Sections = append(what.Sections, sec)
		}
	}
	var out []Bucket
	for _, b := range []Bucket{what, msgs} {
		if len(b.Sections) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// IsPerson reports whether a person signed in (or tried to), as opposed to
// a machine token, a conformance run or a guided check.
func (r *Result) IsPerson() bool { return r.IsSignIn() && r.Mode == "" }

// TestName names a test no person signed in to, for the result's meta line.
func (r *Result) TestName() string {
	switch {
	case r.Conformance:
		return "OAuth 2.1 conformance"
	case r.Machine:
		return "machine token"
	case r.Mode == ModeNoPKCE:
		return "guided check: sign-in without PKCE"
	case r.Mode == ModeWrongVerifier:
		return "guided check: wrong PKCE verifier"
	}
	return ""
}
