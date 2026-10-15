package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
	"github.com/ryanhebert/ssobench/internal/saml"
)

// logoutPending is a sign-out sent to the IdP, waiting for its answer.
type logoutPending struct {
	app     *App
	via     string
	flow    *Flow
	started time.Time
}

// SignedOut describes the signed-out screen.
type SignedOut struct {
	Confirmed bool   // the IdP confirmed it ended its session too
	Local     bool   // only this app's session ended
	Reason    string // why, when not confirmed
}

func (s *Server) sloURL(r *http.Request, app *App) string {
	if app.Legacy {
		return s.base(r) + "/saml/slo"
	}
	return s.base(r) + "/saml/" + app.ID + "/slo"
}

// oauthRedirectFor is the redirect URI of an OAuth 2.1 app.
func (s *Server) oauthRedirectFor(r *http.Request, app *App) string {
	return s.base(r) + "/oauth/" + app.ID + "/callback"
}

func (s *Server) postLogoutURL(r *http.Request, app *App) string {
	if app.Legacy {
		return s.base(r) + "/oidc/logout"
	}
	return s.base(r) + "/oidc/" + app.ID + "/logout"
}

// deepLinkURL is the default relay state SSOBench gives an app to set at the
// IdP: a deep link back into the app, as a real service provider would give.
func (s *Server) deepLinkURL(r *http.Request, app *App) string {
	return s.base(r) + "/a/" + app.ID + "/deep-link"
}

func (s *Server) loginURL(r *http.Request, app *App) string {
	return s.base(r) + "/a/" + app.ID + "/login"
}

// signOut starts a sign-out for the sign-in res of app. via is ViaPage
// (the welcome screen) or ViaConsole (Test sign-out on the result page).
func (s *Server) signOut(w http.ResponseWriter, r *http.Request, via string) {
	app := s.app(r.PathValue("id"))
	res := s.findResult(r.PathValue("rid"))
	if app == nil || res == nil || res.AppID != app.ID {
		http.NotFound(w, r)
		return
	}
	f := s.newFlow(app.ProtocolKind(), s.appName(app)+" (sign-out)")
	s.mu.Lock()
	if stored := s.findResultLocked(res.ID); stored != nil {
		stored.Ended = true
	}
	logoutOn := app.Logout
	if res.SessionID != "" {
		s.endSessionsLocked(app, EndSignedOut, func(x *Session) bool { return x.ID == res.SessionID })
	}
	s.mu.Unlock()
	if res.SessionID != "" {
		s.clearSessionCookie(w, r, app)
		s.saveState()
	}
	if !logoutOn {
		s.event(f, LInfo, "Sign-out", 0, "", "Single logout is off for this app; signed out of SSOBench only")
		s.finish(f, "", "signed out locally")
		s.signedOut(w, r, app, via, f, SignedOut{Local: true, Reason: "Single logout is off for this app, so the identity provider was not told."})
		return
	}
	if app.IsSAML() {
		s.mu.Lock()
		dest, binding, _ := app.IdPLogoutURL()
		s.mu.Unlock()
		if dest == "" {
			s.event(f, LWarn, "Sign-out", 0, "", "No IdP single logout URL (none in the metadata or the app's settings); signed out of SSOBench only")
			s.finish(f, "", "signed out locally")
			s.signedOut(w, r, app, via, f, SignedOut{Local: true, Reason: "No single logout URL is known for the identity provider, so it was not told. Add it in the app's settings."})
			return
		}
		id := saml.NewRequestID()
		sp := s.spFor(r, app)
		req := saml.LogoutRequest(sp, id, dest, res.NameID, res.NameIDFormat, res.SessionIndex, time.Now())
		s.event(f, LInfo, "LogoutRequest", 0, saml.Pretty(req), "Sending request %s to %s (%s binding) for NameID %q", id, dest, binding, res.NameID)
		s.pendingLogout.Put(id, &logoutPending{app: app, via: via, flow: f, started: time.Now()})
		// Logout requests are always signed: identity providers may
		// ignore unsigned ones (SAML profiles, section 4.4.3.1).
		if err := s.sendSAML(w, r, app, f, samlOut{dest: dest, binding: binding, param: "SAMLRequest", msg: req, sign: true, plain: true}); err != nil {
			s.pendingLogout.Delete(id)
			s.event(f, LError, "LogoutRequest", 0, "", "%v", err)
			s.finish(f, "", "signed out locally")
			s.signedOut(w, r, app, via, f, SignedOut{Local: true, Reason: "The sign-out request could not be sent, so the identity provider was not told."})
		}
		return
	}

	// OIDC: RP-initiated logout at the provider's end_session_endpoint.
	s.mu.Lock()
	issuer := app.Issuer
	clientID := app.ClientID
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	p, err := oidc.Discover(ctx, issuer)
	var u *url.URL
	if err == nil && p.EndSessionEndpoint != "" {
		u, err = url.Parse(p.EndSessionEndpoint)
		if err == nil && (u.Scheme != "https" && u.Scheme != "http" || u.Host == "") {
			err = fmt.Errorf("end_session_endpoint %q is not an absolute URL", p.EndSessionEndpoint)
		}
	}
	if err != nil || p.EndSessionEndpoint == "" {
		reason := "The provider does not advertise an end_session_endpoint, so it was not told."
		if err != nil {
			reason = "The provider's end-session endpoint could not be used (" + err.Error() + "), so it was not told."
			s.event(f, LError, "End session", 0, "", "%v", err)
		}
		s.event(f, LWarn, "Sign-out", 0, "", "%s", reason)
		s.finish(f, "", "signed out locally")
		s.signedOut(w, r, app, via, f, SignedOut{Local: true, Reason: reason})
		return
	}
	state := oidc.RandomString(18)
	q := u.Query()
	if res.IDToken != "" {
		q.Set("id_token_hint", res.IDToken)
	}
	q.Set("client_id", clientID)
	q.Set("post_logout_redirect_uri", s.postLogoutURL(r, app))
	q.Set("state", state)
	u.RawQuery = q.Encode()
	s.event(f, LInfo, "End session", 0, prettyURL(redactHint(u.String())), "Sending the browser to %s", p.EndSessionEndpoint)
	s.pendingLogout.Put(state, &logoutPending{app: app, via: via, flow: f, started: time.Now()})
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// redactHint shortens id_token_hint for the log.
func redactHint(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := pu.Query()
	if h := q.Get("id_token_hint"); h != "" {
		q.Set("id_token_hint", shortToken(h))
	}
	pu.RawQuery = q.Encode()
	return pu.String()
}

// signedOut finishes a sign-out: the signed-out screen for people, the log
// for Test sign-out.
func (s *Server) signedOut(w http.ResponseWriter, r *http.Request, app *App, via string, f *Flow, so SignedOut) {
	if via == ViaConsole {
		http.Redirect(w, r, "/log", http.StatusSeeOther)
		return
	}
	if so.Reason != "" && f != nil {
		s.event(f, LInfo, "Sign-out", 0, "", "%s", so.Reason)
	}
	// Redirect, so reloading the signed-out screen doesn't sign out again.
	// The technical reason stays in the log; the person sees plain words.
	target := "/a/" + app.ID + "/signed-out"
	if so.Confirmed {
		target += "?confirmed=1"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) signedOutPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r.PathValue("id"))
	if v == nil {
		http.NotFound(w, r)
		return
	}
	confirmed := r.URL.Query().Get("confirmed") == "1"
	so := &SignedOut{Confirmed: confirmed, Local: !confirmed}
	if id := r.URL.Query().Get("session"); id != "" {
		s.mu.Lock()
		for _, x := range v.App.Sessions {
			if x.ID == id && !x.Active() && x.EndedHow != EndSignedOut {
				so.Reason = "It ended because " + x.EndedHow + "."
			}
		}
		s.mu.Unlock()
	}
	s.render(w, r, http.StatusOK, "signedout.html", page{App: v, SignedOut: so})
}

// samlSLO receives single logout messages: the IdP's LogoutResponse to our
// LogoutRequest, or a LogoutRequest the IdP started (another app signed out).
func (s *Server) samlSLO(w http.ResponseWriter, r *http.Request) {
	var app *App
	if id := r.PathValue("app"); id != "" {
		app = s.app(id)
	} else {
		app = s.legacyApp(ProtoSAML)
	}
	if app == nil || !app.IsSAML() {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unreadable request: "+err.Error(), http.StatusBadRequest)
		return
	}
	encoded, param := r.Form.Get("SAMLResponse"), "SAMLResponse"
	if encoded == "" {
		encoded, param = r.Form.Get("SAMLRequest"), "SAMLRequest"
	}
	raw, err := saml.DecodeMessage(encoded)
	f := s.newFlow("SAML", s.appName(app)+" (single logout)")
	if err != nil {
		s.event(f, LError, "Logout", 0, "", "No readable %s: %v", param, err)
		s.finish(f, "", "unreadable logout message")
		http.Error(w, "not a SAML logout message", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	logoutOn, idp := app.Logout, app.idp
	s.mu.Unlock()
	if !logoutOn {
		s.event(f, LWarn, "Logout", 0, saml.Pretty(raw), "Received a %s, but single logout is off for this app", param)
		s.finish(f, "", "ignored: single logout is off")
		s.render(w, r, http.StatusNotFound, "signedout.html", page{App: s.view(app.ID), SignedOut: &SignedOut{Local: true, Reason: "Single logout is off for this app. Turn it on in the app's settings to test it."}})
		return
	}
	m, err := saml.ParseLogout(raw)
	if err != nil {
		s.event(f, LError, "Logout", 0, saml.Pretty(raw), "%v", err)
		s.finish(f, "", "not a logout message")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Signature: detached on the Redirect binding, enveloped on POST.
	sigPresent, sigErr := false, error(nil)
	if idp != nil {
		if r.Method == http.MethodGet {
			sigPresent, sigErr = saml.VerifyRedirectSignature(r.URL.RawQuery, idp.Certs)
		} else {
			sigPresent, sigErr = saml.VerifyEmbeddedSignature(raw, idp.Certs)
		}
	}
	switch {
	case idp == nil:
		s.event(f, LWarn, "Signature", 0, "", "No IdP metadata is loaded, so the %s signature can't be checked", m.XMLName.Local)
	case !sigPresent:
		s.event(f, LWarn, "Signature", 0, "", "The %s is not signed", m.XMLName.Local)
	case sigErr != nil:
		s.event(f, LError, "Signature", 0, "", "The %s signature is invalid: %v", m.XMLName.Local, sigErr)
	default:
		s.event(f, LInfo, "Signature", 0, "", "The %s signature is valid", m.XMLName.Local)
	}
	// problem is why the message can't be trusted, or "". A logout
	// request ends sessions, so, as an application should, SSOBench acts
	// only on one it can verify. An unsigned answer to its own request
	// only confirms a sign-out, and is accepted with the warning above.
	problem := ""
	if m.IsRequest() && (idp == nil || !sigPresent) {
		problem = "it was not signed, so it can't be shown to come from your identity provider"
	}
	if sigErr != nil {
		problem = "its signature is invalid"
	}
	if idp != nil && m.Issuer != "" && m.Issuer != idp.EntityID {
		s.event(f, LError, "Issuer", 0, "", "The %s is from %q, not the IdP in the metadata (%q)", m.XMLName.Local, m.Issuer, idp.EntityID)
		problem = "it came from another issuer"
	}
	if want := s.sloURL(r, app); m.Destination != "" && m.Destination != want {
		s.event(f, LError, "Destination", 0, "", "The %s is addressed to %s, not this app's single logout URL %s", m.XMLName.Local, m.Destination, want)
		problem = "it was addressed to another URL"
	}

	if !m.IsRequest() {
		// The IdP's answer to our LogoutRequest.
		pend, _ := s.pendingLogout.Take(m.InResponseTo)
		lvl := LInfo
		if !m.Success() {
			lvl = LError
		}
		if pend != nil {
			s.event(pend.flow, lvl, "LogoutResponse", 0, saml.Pretty(raw), "Status %s, %s after the request", m.StatusText(), humanDur(time.Since(pend.started)))
			s.finish(pend.flow, "", "single logout: "+m.StatusText())
			s.finish(f, "", "answered a sign-out from this tool")
			so := SignedOut{Confirmed: m.Success() && problem == ""}
			switch {
			case problem != "":
				s.event(pend.flow, LError, "LogoutResponse", 0, "", "Not trusted: %s", problem)
				so.Reason = "The identity provider's answer could not be trusted, because " + problem + ". Your session there may still be active."
			case !m.Success():
				so.Reason = "The identity provider answered " + m.StatusText() + ". Your session there may still be active."
			}
			s.signedOut(w, r, app, pend.via, pend.flow, so)
			return
		}
		s.event(f, LWarn, "LogoutResponse", 0, saml.Pretty(raw), "Status %s, answering no sign-out from this tool (InResponseTo %q)", m.StatusText(), m.InResponseTo)
		s.finish(f, "", "unexpected LogoutResponse")
		s.signedOut(w, r, app, ViaPage, f, SignedOut{Confirmed: m.Success()})
		return
	}

	// A sign-out the IdP started: confirm it.
	s.event(f, LInfo, "LogoutRequest", 0, saml.Pretty(raw), "The IdP asked to end the session of NameID %q", m.NameID.Value)
	if problem != "" {
		s.event(f, LError, "LogoutRequest", 0, "", "Ignored: %s", problem)
		s.finish(f, "", "refused a logout request: "+problem)
		s.render(w, r, http.StatusBadRequest, "signedout.html", page{App: s.view(app.ID), SignedOut: &SignedOut{Local: true, Reason: "A sign-out request was refused, because " + problem + ". You are still signed in to this app."}})
		return
	}
	s.mu.Lock()
	ended := s.endSessionsLocked(app, EndIdP, func(x *Session) bool {
		return x.NameID != "" && x.NameID == m.NameID.Value && (len(m.SessionIndex) == 0 || slices.Contains(m.SessionIndex, x.SessionIndex))
	})
	s.mu.Unlock()
	s.event(f, LInfo, "Sessions", 0, "", "Ended %d %s for NameID %q", ended, plural(ended, "session", "sessions"), m.NameID.Value)
	if ended > 0 {
		s.saveState()
		s.saveHistory()
	}
	s.mu.Lock()
	dest, binding, _ := app.IdPLogoutURL()
	s.mu.Unlock()
	if dest == "" {
		s.event(f, LWarn, "LogoutResponse", 0, "", "No IdP single logout URL to answer to (none in the metadata or the app's settings)")
		s.finish(f, "", "signed out; no answer sent")
		s.signedOut(w, r, app, ViaPage, f, SignedOut{Local: true, Reason: "No single logout URL is known for the identity provider to answer to."})
		return
	}
	resp := saml.LogoutResponse(s.spFor(r, app), saml.NewRequestID(), m.ID, dest, time.Now())
	s.event(f, LInfo, "LogoutResponse", 0, saml.Pretty(resp), "Answering %s with Success (%s binding)", dest, binding)
	s.finish(f, "", "signed out at the IdP's request")
	relay := r.Form.Get("RelayState")
	if err := s.sendSAML(w, r, app, f, samlOut{dest: dest, binding: binding, param: "SAMLResponse", msg: resp, relay: relay, sign: true, plain: true}); err != nil {
		s.event(f, LError, "LogoutResponse", 0, "", "%v", err)
		s.signedOut(w, r, app, ViaPage, f, SignedOut{Local: true, Reason: "The answer to the identity provider could not be sent."})
	}
}

// oidcLogoutReturn receives the browser back from the provider's
// end_session_endpoint.
func (s *Server) oidcLogoutReturn(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	pend, _ := s.pendingLogout.Take(state)
	if pend == nil {
		var app *App
		if id := r.PathValue("app"); id != "" {
			app = s.app(id)
		} else {
			app = s.legacyApp(ProtoOIDC)
		}
		if app == nil {
			http.NotFound(w, r)
			return
		}
		f := s.newFlow("OIDC", s.appName(app)+" (sign-out)")
		s.event(f, LWarn, "End session", 0, rowsText(queryRows(r.URL.Query())), "Returned from the provider without a sign-out from this tool")
		s.finish(f, "", "unexpected return")
		s.signedOut(w, r, app, ViaPage, f, SignedOut{Confirmed: true})
		return
	}
	s.event(pend.flow, LInfo, "End session", 0, rowsText(queryRows(r.URL.Query())), "Provider returned the browser, %s after the request; state matches", humanDur(time.Since(pend.started)))
	s.finish(pend.flow, "", "signed out at the provider")
	s.signedOut(w, r, pend.app, pend.via, pend.flow, SignedOut{Confirmed: true})
}

// spLogin is the service provider login URL: opening it starts a sign-in.
func (s *Server) spLogin(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	on := app.LoginURL
	s.mu.Unlock()
	if !on {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "The login URL is off for this app. Turn it on in the app's settings in SSOBench.")
		return
	}
	s.signIn(w, r, app, ViaPage)
}
