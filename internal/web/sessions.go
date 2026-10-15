package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
)

// Session is a person's session in an app, as a real application keeps
// one after sign-in: bound to a browser by a cookie, and ended by signing
// out, by the identity provider, by expiry, or by an administrator.
type Session struct {
	ID           string    `json:"id"`
	ResultID     string    `json:"result"`
	User         string    `json:"user"`              // as shown: the result's subject
	Account      string    `json:"account,omitempty"` // matched directory account
	NameID       string    `json:"nameId,omitempty"`  // SAML
	SessionIndex string    `json:"sessionIndex,omitempty"`
	Sub          string    `json:"sub,omitempty"` // OIDC
	SID          string    `json:"sid,omitempty"`
	Via          string    `json:"via"`
	Claimed      bool      `json:"claimed"` // a browser holds its cookie
	Started      time.Time `json:"started"`
	LastSeen     time.Time `json:"lastSeen"`
	Expires      time.Time `json:"expires"`
	ExpiresWhy   string    `json:"expiresWhy"` // "app" or "idp" (SessionNotOnOrAfter)
	Ended        time.Time `json:"ended,omitempty"`
	EndedHow     string    `json:"endedHow,omitempty"`
}

func (x *Session) Active() bool { return x.Ended.IsZero() }

// Ways a session ends, written for the person whose session it was.
const (
	EndSignedOut   = "you signed out"
	EndIdP         = "your sign-in service ended it"
	EndAdmin       = "an administrator ended it"
	EndDeactivated = "your account was deactivated"
	EndDeleted     = "your account was removed"
)

// Session length choices, in minutes, for the app's settings.
var (
	lifetimeChoices = []int{15, 60, 480, 1440}
	idleChoices     = []int{0, 5, 15, 60}
	defaultLifetime = 480
	maxEndedKept    = 50
)

func minutesLabel(m int) string {
	switch {
	case m == 0:
		return "Off"
	case m%60 == 0 && m >= 60:
		return fmt.Sprintf("%d %s", m/60, plural(m/60, "hour", "hours"))
	}
	return fmt.Sprintf("%d minutes", m)
}

func (a *App) lifetime() time.Duration {
	if a.SessionMinutes <= 0 {
		return time.Duration(defaultLifetime) * time.Minute
	}
	return time.Duration(a.SessionMinutes) * time.Minute
}

func (a *App) HasSessions() bool { return !a.IsOAuth() }

func sessionCookie(appID string) string { return "ssobench_" + appID }

// startSession opens a session for a successful sign-in a person made
// (through the sign-in page or from the identity provider). Console
// tests are diagnostics and open none.
func (s *Server) startSession(app *App, res *Result) {
	if !app.HasSessions() || !res.IsSignIn() || res.Mode != "" || res.Status() == "fail" || (res.Via != ViaPage && res.Via != ViaIdP) {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	x := &Session{ID: newUserID(), ResultID: res.ID, User: res.Subject, Account: res.Account, NameID: res.NameID,
		SessionIndex: res.SessionIndex, Sub: res.Sub, SID: res.SID, Via: res.Via, Started: now, LastSeen: now,
		Expires: now.Add(app.lifetime()), ExpiresWhy: "app"}
	if t := res.SessionNotOnOrAfter; !t.IsZero() && t.Before(x.Expires) {
		x.Expires, x.ExpiresWhy = t, "idp"
	}
	app.Sessions = append(app.Sessions, x)
	res.SessionID = x.ID
}

// checkSessionLocked ends x if it has expired or been idle too long.
func checkSessionLocked(app *App, x *Session, now time.Time) {
	if !x.Active() {
		return
	}
	switch idle := time.Duration(app.IdleMinutes) * time.Minute; {
	case now.After(x.Expires) && x.ExpiresWhy == "idp":
		endLocked(x, x.Expires, "your sign-in service's session limit was reached")
	case now.After(x.Expires):
		endLocked(x, x.Expires, "it reached its "+strings.ToLower(minutesLabel(int(app.lifetime()/time.Minute)))+" limit")
	case idle > 0 && now.Sub(x.LastSeen) > idle:
		endLocked(x, x.LastSeen.Add(idle), "you were inactive for "+strings.ToLower(minutesLabel(app.IdleMinutes)))
	}
}

func endLocked(x *Session, at time.Time, how string) {
	if x.Active() {
		x.Ended, x.EndedHow = at, how
	}
}

// endSessionsLocked ends the app's active sessions that match, and
// trims ended ones. It returns how many it ended.
func (s *Server) endSessionsLocked(app *App, how string, match func(*Session) bool) int {
	n := 0
	now := time.Now()
	for _, x := range app.Sessions {
		if x.Active() && match(x) {
			endLocked(x, now, how)
			if res := s.findResultLocked(x.ResultID); res != nil {
				res.Ended = true
			}
			n++
		}
	}
	pruneSessionsLocked(app)
	return n
}

func pruneSessionsLocked(app *App) {
	var ended []*Session
	for _, x := range app.Sessions {
		if !x.Active() {
			ended = append(ended, x)
		}
	}
	if len(ended) <= maxEndedKept {
		return
	}
	drop := map[*Session]bool{}
	slices.SortFunc(ended, func(a, b *Session) int { return a.Ended.Compare(b.Ended) })
	for _, x := range ended[:len(ended)-maxEndedKept] {
		drop[x] = true
	}
	app.Sessions = slices.DeleteFunc(app.Sessions, func(x *Session) bool { return drop[x] })
}

// browserSession is the session this browser holds for app, after
// checking its expiry. It may be ended.
func (s *Server) browserSession(r *http.Request, app *App) *Session {
	c, err := r.Cookie(sessionCookie(app.ID))
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range app.Sessions {
		if x.ID == c.Value {
			checkSessionLocked(app, x, time.Now())
			return x
		}
	}
	return nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, app *App, id string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie(app.ID), Value: id, Path: "/a/" + app.ID,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request, app *App) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie(app.ID), Value: "", Path: "/a/" + app.ID, MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
}

// SessionView is a session for the Sessions tab.
type SessionView struct {
	Session
	Source string
}

func (s *Server) sessionViews(app *App) (active, ended []SessionView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for i := len(app.Sessions) - 1; i >= 0; i-- {
		x := app.Sessions[i]
		checkSessionLocked(app, x, now)
		v := SessionView{Session: *x, Source: map[string]string{ViaPage: "Sign-in page", ViaIdP: "Started at the IdP"}[x.Via]}
		if x.Active() {
			active = append(active, v)
		} else {
			ended = append(ended, v)
		}
	}
	slices.SortFunc(ended, func(a, b SessionView) int { return b.Ended.Compare(a.Ended) })
	if len(ended) > 20 {
		ended = ended[:20]
	}
	return active, ended
}

// sessionEnd ends one session from the Sessions tab.
func (s *Server) sessionEnd(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("sid")
	s.mu.Lock()
	n := s.endSessionsLocked(app, EndAdmin, func(x *Session) bool { return x.ID == id })
	s.mu.Unlock()
	if n > 0 {
		s.saveState()
		s.saveHistory()
		s.logf("Session %s of %q ended by an administrator from %s", id, s.appName(app), clientAddr(r))
	}
	http.Redirect(w, r, "/apps/"+app.ID+"/sessions?done=ended", http.StatusSeeOther)
}

// backchannelLogout receives an OpenID Connect back-channel logout: the
// provider posts a signed logout_token naming the session (sid) or user
// (sub) to end.
func (s *Server) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("app"))
	if app == nil || app.IsSAML() {
		http.NotFound(w, r)
		return
	}
	f := s.newFlow("OIDC", s.appName(app)+" (back-channel logout)")
	fail := func(msg string) {
		s.event(f, LError, "Logout token", 0, "", "%s", msg)
		s.finish(f, "", "back-channel logout refused")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_request","error_description":%q}`, msg)
	}
	raw := r.PostFormValue("logout_token")
	j, err := oidc.ParseJWT(raw)
	if err != nil {
		fail("logout_token is missing or not a JWT")
		return
	}
	s.event(f, LInfo, "Logout token", 0, string(j.HeaderRaw)+"\n"+string(j.ClaimsRaw), "Received from %s", clientAddr(r))
	s.mu.Lock()
	issuer, clientID := app.Issuer, app.ClientID
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, issuer)
	if err != nil {
		fail("could not load the provider's discovery document: " + err.Error())
		return
	}
	jwks, _, err := oidc.FetchJWKS(ctx, p.JWKSURI)
	if err != nil {
		fail("could not load the provider's keys: " + err.Error())
		return
	}
	k, ok := jwks.Find(j.Kid())
	if !ok || strings.HasPrefix(j.Alg(), "HS") {
		fail("the logout_token is not signed with one of the provider's published keys")
		return
	}
	pub, err := k.PublicKey()
	if err == nil {
		err = j.Verify(pub, nil)
	}
	if err != nil {
		fail("signature: " + err.Error())
		return
	}
	events, _ := j.Claims["events"].(map[string]any)
	_, isLogout := events["http://schemas.openid.net/event/backchannel-logout"]
	switch {
	case !oidc.IssuerMatches(issuer, j.Str("iss"), j.Str("tid")):
		fail(fmt.Sprintf("iss %q is not the provider %q", j.Str("iss"), issuer))
		return
	case !slices.Contains(j.Audiences(), clientID):
		fail("aud does not include this client ID")
		return
	case !isLogout:
		fail("the events claim has no back-channel logout event")
		return
	case j.Claims["nonce"] != nil:
		fail("a logout token must not contain a nonce")
		return
	case j.Str("sid") == "" && j.Str("sub") == "":
		fail("the logout token names neither a session (sid) nor a user (sub)")
		return
	}
	sid, sub := j.Str("sid"), j.Str("sub")
	s.mu.Lock()
	n := s.endSessionsLocked(app, EndIdP, func(x *Session) bool {
		return (sid != "" && x.SID == sid) || (sid == "" && sub != "" && x.Sub == sub)
	})
	s.mu.Unlock()
	s.event(f, LInfo, "Sessions", 0, "", "Ended %d %s (sid %q, sub %q)", n, plural(n, "session", "sessions"), sid, sub)
	s.finish(f, "", fmt.Sprintf("ended %d %s", n, plural(n, "session", "sessions")))
	if n > 0 {
		s.saveState()
		s.saveHistory()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) backchannelURL(r *http.Request, app *App) string {
	return s.base(r) + "/oidc/" + app.ID + "/backchannel-logout"
}

// endForAccountsLocked ends the sessions of accounts that are now
// deactivated or removed, as an application does when provisioning or an
// administrator takes someone's access away.
func (s *Server) endForAccountsLocked(app *App) int {
	// Decide first: ending sessions prunes app.Sessions, which must not
	// happen while it is being walked.
	deleted, deactivated := map[*Session]bool{}, map[*Session]bool{}
	for _, x := range app.Sessions {
		if !x.Active() || x.Account == "" {
			continue
		}
		switch u := userByName(app.Users, x.Account); {
		case u == nil:
			deleted[x] = true
		case !u.Active:
			deactivated[x] = true
		}
	}
	n := 0
	if len(deleted) > 0 {
		n += s.endSessionsLocked(app, EndDeleted, func(y *Session) bool { return deleted[y] })
	}
	if len(deactivated) > 0 {
		n += s.endSessionsLocked(app, EndDeactivated, func(y *Session) bool { return deactivated[y] })
	}
	return n
}

// ActiveSessions counts the app's sessions not yet ended, for its tab.
func (a *App) ActiveSessions() int {
	n := 0
	for _, x := range a.Sessions {
		if x.Active() && time.Now().Before(x.Expires) {
			n++
		}
	}
	return n
}

// endedLabel words how a session ended for the admin's list.
func endedLabel(how string) string {
	r := strings.NewReplacer("you signed out", "signed out", "your sign-in service ended it", "ended by the identity provider",
		"an administrator ended it", "ended by an administrator", "your account was deactivated", "account deactivated",
		"your account was removed", "account removed", "you were inactive for", "inactive for", "it reached its", "reached its",
		"your sign-in service's session limit was reached", "identity provider's session limit reached")
	return r.Replace(how)
}

// locked runs fn holding s.mu, and releases it even if fn panics: a panic
// in a handler is recovered by net/http, and a mutex left locked would
// hang every later request.
func (s *Server) locked(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}
