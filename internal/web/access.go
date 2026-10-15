package web

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ryanhebert/ssobench/internal/check"
)

// AccessRule gives a role to people whose sign-in carries one of Values in
// an attribute or claim (Source "attr", named Name), or whose directory
// account is in one of the groups named in Values (Source "group"). Rules
// are tried in order; the first match decides the role. With no rules,
// everyone who signs in has access.
type AccessRule struct {
	Role   string   `json:"role"`
	Source string   `json:"source"` // "attr" or "group"
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

// DescribeParts describes the rule as lead-in text and the values, so
// the values can be set apart.
func (r AccessRule) DescribeParts() (lead, values string) {
	values = strings.Join(r.Values, " or ")
	if r.Source == "group" {
		return "the account is in the group", values
	}
	return r.Name + " is", values
}

// attrValues collects every value of the named attribute or claim.
func attrValues(res *Result, name string) []string {
	var out []string
	for _, sec := range res.Sections(GroupIdentity) {
		for _, row := range sec.Rows {
			if strings.EqualFold(row.K, name) || strings.EqualFold(row.Title, name) || strings.EqualFold(shortLabel(row), name) {
				for _, v := range strings.Split(row.V, "\n") {
					if v = strings.TrimSpace(v); v != "" {
						out = append(out, v)
					}
				}
			}
		}
	}
	return out
}

// Decision is the outcome of an app's access rules for one sign-in.
type Decision struct {
	Allowed bool
	Role    string
	Rule    int      // 1-based index of the deciding rule; 0 when none
	Why     string   // what matched, or why nothing did
	Seen    []string // the values each rule looked at, for the tester
}

// decide evaluates app's rules for res. Call with s.mu held.
func decide(app *App, res *Result) Decision {
	if len(app.AccessRules) == 0 {
		return Decision{Allowed: true, Why: "no access rules: everyone who signs in has access"}
	}
	var groups []string
	u := userByName(app.Users, res.Account)
	if u == nil && app.Directory {
		// Match the sign-in against the directory as it is now, so the
		// tester reflects current group membership.
		v, _ := matchValue(res, app.MatchKey, app.MatchAttr)
		u = findUser(app.Users, v)
	}
	if u != nil {
		for _, g := range app.Groups {
			if slices.Contains(g.Members, u.ID) {
				groups = append(groups, g.Name)
			}
		}
	}
	var seen []string
	for i, rule := range app.AccessRules {
		have := groups
		what := "groups"
		if rule.Source != "group" {
			have, what = attrValues(res, rule.Name), rule.Name
		}
		seen = append(seen, fmt.Sprintf("%s: %s", what, nameOr(strings.Join(have, ", "), "none")))
		for _, v := range have {
			if slices.ContainsFunc(rule.Values, func(w string) bool { return strings.EqualFold(w, v) }) {
				return Decision{Allowed: true, Role: rule.Role, Rule: i + 1, Seen: seen,
					Why: fmt.Sprintf("rule %d: %s %s", i+1, map[bool]string{true: "in the group", false: rule.Name + " has"}[rule.Source == "group"], v)}
			}
		}
	}
	return Decision{Seen: seen, Why: "no rule matched (" + strings.Join(seen, "; ") + ")"}
}

// accessCheck applies the app's access rules to a completed sign-in.
func (s *Server) accessCheck(app *App, res *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(app.AccessRules) == 0 || res.Status() == "fail" || !res.IsSignIn() {
		return
	}
	d := decide(app, res)
	if !d.Allowed {
		res.AccessProblem = "denied"
		res.Checks = append(res.Checks, check.Bad("Access", d.Why,
			"Send the attribute or group membership the app's access rules expect from the identity provider, or change the rules under Users › Access."))
		return
	}
	res.Role = d.Role
	res.Checks = append(res.Checks, check.OK("Access", fmt.Sprintf("role %s, by %s", d.Role, d.Why)))
}

// ---- handlers ----

func (s *Server) ruleAdd(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	rule := AccessRule{Role: strings.TrimSpace(r.FormValue("role")), Source: r.FormValue("source"), Name: strings.TrimSpace(r.FormValue("name"))}
	if rule.Source != "group" {
		rule.Source = "attr"
	}
	for _, v := range strings.Split(r.FormValue("values"), ",") {
		if v = strings.TrimSpace(v); v != "" {
			rule.Values = append(rule.Values, v)
		}
	}
	switch {
	case rule.Role == "":
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", View: "access", UserErr: "Name the role this rule gives, such as Admin."})
		return
	case rule.Source == "attr" && rule.Name == "":
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", View: "access", UserErr: "Enter the attribute or claim to look at."})
		return
	case len(rule.Values) == 0:
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", View: "access", UserErr: "Enter at least one value."})
		return
	}
	s.mu.Lock()
	app.AccessRules = append(app.AccessRules, rule)
	s.mu.Unlock()
	s.saveState()
	http.Redirect(w, r, "/apps/"+app.ID+"/users?view=access&done=rule", http.StatusSeeOther)
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	i, err := strconv.Atoi(r.PathValue("n"))
	s.mu.Lock()
	if err == nil && i >= 1 && i <= len(app.AccessRules) {
		app.AccessRules = slices.Delete(app.AccessRules, i-1, i)
	}
	s.mu.Unlock()
	s.saveState()
	http.Redirect(w, r, "/apps/"+app.ID+"/users?view=access", http.StatusSeeOther)
}

// RuleTest is the access tester: the rules applied to the latest sign-in.
type RuleTest struct {
	Result   *Result
	Decision Decision
}
