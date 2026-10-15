// Package decode turns a pasted JWT or SAML message into readable parts.
// Nothing is verified here: there is no key or metadata to verify against.
package decode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/oidc"
	"github.com/ryanhebert/ssobench/internal/saml"
)

type Part struct {
	Title string
	Body  string
	Rows  [][2]string // when set, shown as a key/value list instead of Body
}

type Result struct {
	Kind  string // "JWT" or "SAML"
	Parts []Part
}

func Auto(input string, now time.Time) (*Result, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("nothing to decode")
	}
	if oidc.LooksLikeJWT(input) || strings.Count(input, ".") == 4 {
		return JWT(input, now)
	}
	return SAML(input)
}

func JWT(s string, now time.Time) (*Result, error) {
	j, err := oidc.ParseJWT(s)
	if err != nil {
		return nil, err
	}
	r := &Result{Kind: "JWT"}
	r.Parts = append(r.Parts,
		Part{Title: "Header", Body: indentJSON(j.HeaderRaw)},
		Part{Title: "Claims", Body: indentJSON(j.ClaimsRaw)},
	)
	var times []string
	var rows [][2]string
	for _, c := range TimeClaims {
		if t, ok := j.Time(c); ok {
			times = append(times, fmt.Sprintf("%-10s %s", c, check.When(t, now)))
			rows = append(rows, [2]string{c, check.When(t, now)})
		}
	}
	if len(times) > 0 {
		r.Parts = append(r.Parts, Part{Title: "Times", Body: strings.Join(times, "\n"), Rows: rows})
	}
	r.Parts = append(r.Parts, Part{Title: "Signature", Body: fmt.Sprintf("alg %s, kid %q. Not verified: decode has no key.", j.Alg(), j.Kid())})
	return r, nil
}

// TimeClaims are the JWT claims holding NumericDate values.
var TimeClaims = []string{"exp", "nbf", "iat", "auth_time", "updated_at"}

func SAML(s string) (*Result, error) {
	x, err := saml.DecodeMessage(s)
	if err != nil {
		return nil, fmt.Errorf("this doesn't look like a JWT, a SAML message, a redirect URL or XML (%w)", err)
	}
	r := &Result{Kind: "SAML"}
	if resp, err := saml.ParseResponse(x); err == nil {
		r.Parts = append(r.Parts, Part{Title: "Summary", Body: Summary(resp), Rows: SummaryRows(resp)})
	}
	r.Parts = append(r.Parts, Part{Title: "XML", Body: saml.Pretty(x)})
	if bytes.Contains(x, []byte("SignatureValue")) {
		r.Parts = append(r.Parts, Part{Title: "Signature", Body: "Present. Not verified: decode has no IdP certificate."})
	}
	return r, nil
}

// Summary renders the interesting fields of a Response as aligned text.
func summaryPairs(r *saml.Response) [][2]string {
	var rows [][2]string
	kv := func(k, v string) {
		if v != "" {
			rows = append(rows, [2]string{k, v})
		}
	}
	status := saml.Short(r.Status.Code.Value)
	if r.Status.Code.Sub != nil {
		status += " / " + saml.Short(r.Status.Code.Sub.Value)
	}
	kv("Status", status)
	kv("Status message", r.Status.Message)
	kv("Issuer", r.Issuer)
	kv("Destination", r.Destination)
	kv("InResponseTo", r.InResponseTo)
	kv("IssueInstant", r.IssueInstant)
	for _, a := range r.Assertions {
		kv("Assertion issuer", a.Issuer)
		kv("NameID", a.Subject.NameID.Value)
		kv("NameID format", saml.Short(a.Subject.NameID.Format))
		if c := a.Conditions; c != nil {
			kv("Audience", strings.Join(c.Audiences, ", "))
			kv("NotBefore", c.NotBefore)
			kv("NotOnOrAfter", c.NotOnOrAfter)
		}
		for _, s := range a.AuthnStatements {
			kv("AuthnContext", saml.Short(s.ClassRef))
			kv("SessionIndex", s.SessionIndex)
		}
		attrs := append([]saml.Attribute(nil), a.Attributes...)
		sort.Slice(attrs, func(i, j int) bool { return attrs[i].Name < attrs[j].Name })
		for _, at := range attrs {
			kv(AttrLabel(at), strings.Join(at.Values, ", "))
		}
	}
	return rows
}

// Summary is the response's key facts as aligned text.
func Summary(r *saml.Response) string {
	var b strings.Builder
	for _, kv := range summaryPairs(r) {
		v := strings.ReplaceAll(kv[1], "\n", "\n"+strings.Repeat(" ", 23))
		fmt.Fprintf(&b, "%-22s %s\n", kv[0], v)
	}
	return strings.TrimRight(b.String(), "\n")
}

// AttrLabel prefers the FriendlyName; long claim URIs keep only their tail.
func AttrLabel(a saml.Attribute) string {
	if a.FriendlyName != "" {
		return a.FriendlyName
	}
	if i := strings.LastIndex(a.Name, "/"); i >= 0 && i < len(a.Name)-1 {
		return a.Name[i+1:]
	}
	return a.Name
}

func indentJSON(b []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return string(b)
	}
	return out.String()
}

// SummaryRows is Summary as key/value pairs.
func SummaryRows(r *saml.Response) [][2]string { return summaryPairs(r) }
