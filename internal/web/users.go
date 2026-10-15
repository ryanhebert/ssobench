package web

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
)

// Match keys: which value from a sign-in identifies the account.
const (
	MatchNameID   = "nameid"   // SAML NameID, or OIDC sub
	MatchEmail    = "email"    // the email attribute or claim
	MatchUsername = "username" // the username attribute or claim
	MatchAttr     = "attr"     // a named attribute or claim (App.MatchAttr)
)

// matchValue is the value of res that identifies the account, and a label
// for where it came from.
func matchValue(res *Result, key, attr string) (value, from string) {
	p := res.Profile()
	field := func(label string) string {
		for _, f := range p.Fields {
			if f.Label == label && len(f.Values) > 0 {
				return strings.TrimSpace(f.Values[0])
			}
		}
		return ""
	}
	switch key {
	case MatchEmail:
		return firstNonEmpty(field("Email"), p.Email), "email"
	case MatchUsername:
		return field("Username"), "username"
	case MatchAttr:
		for _, sec := range res.Sections(GroupIdentity) {
			for _, row := range sec.Rows {
				if strings.EqualFold(row.K, attr) || strings.EqualFold(row.Title, attr) || strings.EqualFold(shortLabel(row), attr) {
					return strings.TrimSpace(strings.SplitN(row.V, "\n", 2)[0]), attr
				}
			}
		}
		return "", attr
	}
	if res.NameID != "" {
		return res.NameID, "NameID"
	}
	return res.Subject, "subject"
}

// findUser looks the value up by userName, email or externalId, ignoring
// case.
func findUser(users []*User, v string) *User {
	if v == "" {
		return nil
	}
	for _, u := range users {
		if strings.EqualFold(u.UserName, v) || strings.EqualFold(u.ExternalID, v) ||
			slices.ContainsFunc(u.Emails, func(e string) bool { return strings.EqualFold(e, v) }) {
			return u
		}
	}
	return nil
}

// closestUser finds an account that differs from v only in a way people
// mistake: the domain of an email, or a username vs an email.
func closestUser(users []*User, v string) *User {
	local := strings.ToLower(localPart(v))
	if local == "" {
		local = strings.ToLower(v)
	}
	for _, u := range users {
		for _, cand := range append([]string{u.UserName, u.ExternalID}, u.Emails...) {
			cl := strings.ToLower(localPart(cand))
			if cl == "" {
				cl = strings.ToLower(cand)
			}
			if cl != "" && cl == local {
				return u
			}
		}
	}
	return nil
}

// accountCheck matches a completed sign-in to the app's directory, as the
// application would before letting the person in. It may create the
// account (just in time) and records the sign-in. It reports whether the
// directory changed.
func (s *Server) accountCheck(app *App, res *Result) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !app.Directory || res.Status() == "fail" {
		return false
	}
	v, from := matchValue(res, app.MatchKey, app.MatchAttr)
	res.AccountValue = v
	if v == "" {
		res.Checks = append(res.Checks, check.Bad("Account", fmt.Sprintf("the sign-in has no %s to match an account with", from),
			"Send the "+from+" to this app from the identity provider, or change which value this app matches accounts on in Settings."))
		res.AccountProblem = "missing"
		return false
	}
	u := findUser(app.Users, v)
	switch {
	case u == nil && app.JIT:
		p := res.Profile()
		u = &User{ID: newUserID(), UserName: v, Display: p.DisplayName, Active: true, Source: "jit", Created: time.Now(), Updated: time.Now()}
		if p.Email != "" {
			u.Emails = []string{p.Email}
		}
		app.Users = append(app.Users, u)
		res.Checks = append(res.Checks, check.Note("Account", fmt.Sprintf("no account for %q, so one was created just in time", v)))
	case u == nil:
		c := check.Bad("Account", fmt.Sprintf("this app has no account for %s %q", from, v),
			"Provision the user to this app (SCIM), add them under Users, or turn on just-in-time accounts.")
		if near := closestUser(app.Users, v); near != nil {
			c = c.Mismatch(v, firstNonEmpty(near.PrimaryEmail(), near.UserName))
			c.Fix = "An account with a similar identifier exists. The identity provider sends one value and the account has another; change the " + from + " the IdP sends, or this app's matching key."
		}
		res.Checks = append(res.Checks, c)
		res.AccountProblem = "notfound"
		return false
	case !u.Active:
		res.AccountID, res.AccountName, res.Account = u.ID, u.Name(), u.UserName
		res.Checks = append(res.Checks, check.Bad("Account", fmt.Sprintf("the account %q is deactivated", u.UserName),
			"The identity provider still signs this person in, but the app has deactivated them, usually by provisioning. That is the expected result after removing someone from the app."))
		res.AccountProblem = "inactive"
		return false
	default:
		res.Checks = append(res.Checks, check.OK("Account", fmt.Sprintf("matched account %q by %s", u.UserName, from)))
	}
	u.LastSignIn = time.Now()
	res.Account = u.UserName
	res.AccountName = u.Name()
	return true
}

func newSCIMToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// otherEmail is the primary email when it differs from the username.
func otherEmail(u User) string {
	if e := u.PrimaryEmail(); !strings.EqualFold(e, u.UserName) {
		return e
	}
	return ""
}

func sourceLabel(src string) string {
	switch src {
	case "scim":
		return "Provisioned"
	case "csv":
		return "Imported"
	case "jit":
		return "Created at sign-in"
	}
	return "Added by hand"
}

// directoryApp is the app for a user-directory request, or nil after
// answering 404.
func (s *Server) directoryApp(w http.ResponseWriter, r *http.Request) *App {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
	}
	return app
}

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	name := strings.TrimSpace(r.FormValue("userName"))
	if name == "" {
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", UserErr: "Enter a username."})
		return
	}
	s.mu.Lock()
	exists := userByName(app.Users, name) != nil
	if !exists {
		u := &User{ID: newUserID(), UserName: name, GivenName: strings.TrimSpace(r.FormValue("givenName")),
			FamilyName: strings.TrimSpace(r.FormValue("familyName")), Active: true, Source: "manual", Created: time.Now(), Updated: time.Now()}
		if e := strings.TrimSpace(r.FormValue("email")); e != "" {
			u.Emails = []string{e}
		}
		app.Users = append(app.Users, u)
	}
	s.mu.Unlock()
	if exists {
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", UserErr: fmt.Sprintf("A user with username %q already exists.", name)})
		return
	}
	s.saveState()
	s.logf("Directory %s: added %s by hand", app.ID, name)
	if back := backTo(r); back != "" {
		http.Redirect(w, r, back+"?fixed=added", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/apps/"+app.ID+"/users?done=user-added", http.StatusSeeOther)
}

// userImport adds or updates users from CSV: userName,email,givenName,
// familyName,active. A header row is recognised and skipped.
func (s *Server) userImport(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	r.ParseMultipartForm(4 << 20)
	text := r.FormValue("csv")
	if f, _, err := r.FormFile("file"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, 4<<20))
		f.Close()
		if len(bytes.TrimSpace(b)) > 0 {
			text = string(b)
		}
	}
	rows, err := parseUserCSV(text)
	if err != nil {
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Tab: "users", ImportErr: err.Error()})
		return
	}
	var added, updated int
	s.mu.Lock()
	for _, in := range rows {
		u := userByName(app.Users, in.UserName)
		if u == nil {
			in.ID, in.Source, in.Created = newUserID(), "csv", time.Now()
			in.Updated = in.Created
			app.Users = append(app.Users, in)
			added++
			continue
		}
		if len(in.Emails) > 0 {
			u.Emails = in.Emails
		}
		if in.GivenName != "" || in.FamilyName != "" {
			u.GivenName, u.FamilyName = in.GivenName, in.FamilyName
		}
		u.Active, u.Updated = in.Active, time.Now()
		updated++
	}
	s.mu.Unlock()
	s.saveState()
	summary := fmt.Sprintf("%d %s", added, plural(added, "new user", "new users"))
	if updated > 0 {
		summary += " and updated " + fmt.Sprintf("%d %s", updated, plural(updated, "user", "users"))
	}
	s.logf("Directory %s: imported %s", app.ID, summary)
	http.Redirect(w, r, "/apps/"+app.ID+"/users?done=imported&n="+url.QueryEscape(summary), http.StatusSeeOther)
}

func parseUserCSV(text string) ([]*User, error) {
	cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	recs, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("The CSV could not be read: %v", err)
	}
	var out []*User
	seen := map[string]bool{}
	for i, rec := range recs {
		get := func(n int) string {
			if n < len(rec) {
				return strings.TrimSpace(rec[n])
			}
			return ""
		}
		if i == 0 && strings.EqualFold(get(0), "userName") {
			continue
		}
		if get(0) == "" {
			if strings.TrimSpace(strings.Join(rec, "")) == "" {
				continue
			}
			return nil, fmt.Errorf("Row %d has no userName in the first column.", i+1)
		}
		if seen[strings.ToLower(get(0))] {
			return nil, fmt.Errorf("Row %d repeats the username %q.", i+1, get(0))
		}
		seen[strings.ToLower(get(0))] = true
		u := &User{UserName: get(0), GivenName: get(2), FamilyName: get(3), Active: true}
		if e := get(1); e != "" {
			u.Emails = []string{e}
		}
		switch strings.ToLower(get(4)) {
		case "", "true", "yes", "1", "active":
		case "false", "no", "0", "inactive":
			u.Active = false
		default:
			return nil, fmt.Errorf("Row %d: active must be true or false, not %q.", i+1, get(4))
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("Choose a CSV file or paste rows to import.")
	}
	return out, nil
}

func (s *Server) userSetActive(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	var u *User
	s.locked(func() {
		if u = userByID(app.Users, r.PathValue("uid")); u != nil {
			u.Active, u.Updated = r.FormValue("active") == "1", time.Now()
			s.endForAccountsLocked(app)
		}
	})
	if u != nil {
		s.saveState()
	}
	if back := backTo(r); back != "" {
		http.Redirect(w, r, back+"?fixed=reactivated", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/apps/"+app.ID+"/users", http.StatusSeeOther)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	id := r.PathValue("uid")
	s.locked(func() {
		app.Users = deleteUser(app.Users, id)
		for _, g := range app.Groups {
			g.Members = removeString(g.Members, id)
		}
		s.endForAccountsLocked(app)
	})
	s.saveState()
	http.Redirect(w, r, "/apps/"+app.ID+"/users?done=user-deleted", http.StatusSeeOther)
}

func (s *Server) scimNewToken(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	if r.FormValue("confirm") != "1" {
		http.Redirect(w, r, "/apps/"+app.ID+"/setup?rotate=1#provisioning", http.StatusSeeOther)
		return
	}
	s.mu.Lock()
	app.SCIMToken = newSCIMToken()
	s.mu.Unlock()
	s.saveState()
	s.logf("Directory %s: new SCIM token generated from %s", app.ID, clientAddr(r))
	http.Redirect(w, r, "/apps/"+app.ID+"/setup?done=token#provisioning", http.StatusSeeOther)
}

// backTo is a result page to return to after a one-click fix, or "".
func backTo(r *http.Request) string {
	b := r.FormValue("back")
	if strings.HasPrefix(b, "/result/") && !strings.ContainsAny(b[len("/result/"):], "/?#\\") {
		return b
	}
	return ""
}

// directoryOn turns on an app's user directory from its Users tab.
func (s *Server) directoryOn(w http.ResponseWriter, r *http.Request) {
	app := s.directoryApp(w, r)
	if app == nil {
		return
	}
	s.mu.Lock()
	app.Directory = true
	if app.MatchKey == "" {
		app.MatchKey = MatchNameID
	}
	if app.SCIMToken == "" {
		app.SCIMToken = newSCIMToken()
	}
	s.mu.Unlock()
	s.saveState()
	http.Redirect(w, r, "/apps/"+app.ID+"/users?done=directory", http.StatusSeeOther)
}

// matchLabel says what accounts are matched on, for the Users tab.
func matchLabel(a *AppView) string {
	switch a.MatchKey {
	case MatchEmail:
		return "email"
	case MatchUsername:
		return "username"
	case MatchAttr:
		return a.MatchAttr
	}
	if a.IsSAML() {
		return "NameID"
	}
	return "subject (sub)"
}
