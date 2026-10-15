package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ryanhebert/ssobench/internal/check"
)

// ExpectedAttr is an attribute or claim the application needs. With a
// Value, one of the values received must equal it, ignoring case.
type ExpectedAttr struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// parseExpected reads one attribute per line, as "name" or "name = value".
func parseExpected(text string) []ExpectedAttr {
	var out []ExpectedAttr
	for _, line := range strings.Split(text, "\n") {
		name, value, _ := strings.Cut(line, "=")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if name == "" || slices.ContainsFunc(out, func(e ExpectedAttr) bool { return strings.EqualFold(e.Name, name) }) {
			continue
		}
		out = append(out, ExpectedAttr{Name: name, Value: value})
	}
	return out
}

func formatExpected(list []ExpectedAttr) string {
	var b strings.Builder
	for _, e := range list {
		b.WriteString(e.Name)
		if e.Value != "" {
			b.WriteString(" = " + e.Value)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// expectCheck compares a sign-in with the attributes the app expects.
func (s *Server) expectCheck(app *App, res *Result) {
	s.mu.Lock()
	want := slices.Clone(app.Expected)
	s.mu.Unlock()
	if len(want) == 0 || !res.IsSignIn() || res.Status() == "fail" {
		return
	}
	label := "attribute"
	if res.Kind != "SAML" {
		label = "claim"
	}
	var missing, wrong []string
	for _, e := range want {
		got := attrValues(res, e.Name)
		switch {
		case len(got) == 0:
			missing = append(missing, e.Name)
		case e.Value != "" && !slices.ContainsFunc(got, func(v string) bool { return strings.EqualFold(v, e.Value) }):
			wrong = append(wrong, fmt.Sprintf("%s is %s, not %s", e.Name, strings.Join(got, ", "), e.Value))
		}
	}
	const name = "Expected attributes"
	fix := fmt.Sprintf("Send the %ss the app needs: add them to the app's %s mapping at the identity provider, or change the list in this app's Settings.", label, label)
	switch {
	case len(missing) > 0 && len(wrong) > 0:
		res.Checks = append(res.Checks, check.Bad(name, "missing "+strings.Join(missing, ", ")+"; "+strings.Join(wrong, "; "), fix))
	case len(missing) > 0:
		res.Checks = append(res.Checks, check.Bad(name, "missing "+strings.Join(missing, ", "), fix))
	case len(wrong) > 0:
		res.Checks = append(res.Checks, check.Bad(name, strings.Join(wrong, "; "), fix))
	default:
		res.Checks = append(res.Checks, check.OK(name, fmt.Sprintf("all %d received", len(want))))
	}
}

// identityNames lists the attributes or claims res received that describe
// the person, leaving out token plumbing such as iss and exp.
func identityNames(res *Result) []string {
	var out []string
	for _, sec := range res.Sections(GroupIdentity) {
		for _, row := range sec.Rows {
			if row.K == "" || technicalClaims[normKey(row.K)] || slices.Contains(out, row.K) {
				continue
			}
			out = append(out, row.K)
		}
	}
	return out
}

// expectFromResult saves the attributes a sign-in received as the ones the
// app expects.
func (s *Server) expectFromResult(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	res := s.findResult(r.FormValue("result"))
	if app == nil || app.IsOAuth() || res == nil || res.AppID != app.ID {
		http.NotFound(w, r)
		return
	}
	var list []ExpectedAttr
	for _, n := range identityNames(res) {
		list = append(list, ExpectedAttr{Name: n})
	}
	s.mu.Lock()
	app.Expected = list
	s.mu.Unlock()
	s.saveState()
	http.Redirect(w, r, "/result/"+res.ID+"?fixed=expected", http.StatusSeeOther)
}
