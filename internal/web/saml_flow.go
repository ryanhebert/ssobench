package web

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/saml"
)

type samlPending struct {
	app   *App
	sent  time.Time
	flow  *Flow
	sp    saml.SP           // the URLs this sign-in was started with
	opts  saml.AuthnOptions // what the request asked for
	via   string
	relay string // the RelayState sent, expected back unchanged
}

// samlSignIn sends an AuthnRequest for app, reloading its metadata first
// when it comes from a URL, so a rotated certificate is picked up.
func (s *Server) samlSignIn(w http.ResponseWriter, r *http.Request, app *App, via string) {
	f := s.newFlow("SAML", s.appName(app))
	s.mu.Lock()
	hasURL, idp := app.MetadataURL != "", app.idp
	opts := saml.AuthnOptions{ForceAuthn: app.ForceAuthn, IsPassive: app.IsPassive, NameIDFormat: app.NameIDFormat,
		AuthnContext: slices.Clone(app.AuthnContext), Comparison: app.AuthnComparison}
	s.mu.Unlock()
	if hasURL || idp == nil {
		var err error
		if idp, err = s.loadIdP(r.Context(), f, app); err != nil {
			s.finish(f, "", "stopped: "+err.Error())
			s.appError(w, r, app, err.Error())
			return
		}
	}

	now := time.Now()
	id := saml.NewRequestID()
	sp := s.spFor(r, app)
	relay := "ts-" + randomID()
	s.pendingSAML.Put(id, &samlPending{app: app, sent: now, flow: f, sp: sp, via: via, relay: relay, opts: opts})

	dest, binding := idp.SSORedirect, "HTTP-Redirect"
	if dest == "" {
		dest, binding = idp.SSOPost, "HTTP-POST"
	}
	req := saml.AuthnRequest(sp, id, dest, opts, now)
	s.event(f, LInfo, "AuthnRequest", 0, saml.Pretty(req), "Sending request %s to %s (%s binding, %s, %s, RelayState %q)", id, dest, binding, describeOpts(opts), map[bool]string{true: "signed", false: "unsigned"}[sp.SignRequests], relay)
	if err := s.sendSAML(w, r, app, f, samlOut{dest: dest, binding: binding, param: "SAMLRequest", msg: req, relay: relay, sign: sp.SignRequests, plain: via != ViaConsole}); err != nil {
		s.event(f, LError, "AuthnRequest", 0, "", "%v", err)
		s.finish(f, "", "stopped: could not build the request")
		s.appError(w, r, app, err.Error())
	}
}

// samlOut is a SAML message to send through the browser.
type samlOut struct {
	dest, binding, param string
	msg                  []byte
	relay                string
	sign                 bool
	plain                bool // the end-user look for the POST form
}

// sendSAML sends o with its binding, signed when o.sign: a detached
// signature on the Redirect binding, an enveloped one on POST.
func (s *Server) sendSAML(w http.ResponseWriter, r *http.Request, app *App, f *Flow, o samlOut) error {
	var sg *saml.Signer
	if o.sign {
		var err error
		if sg, err = s.signerFor(app); err != nil {
			return fmt.Errorf("could not sign the %s: %w", o.param, err)
		}
	}
	if o.binding == "HTTP-Redirect" {
		var u string
		var err error
		if sg != nil {
			u, err = saml.EncodeRedirectSigned(o.dest, o.param, o.msg, o.relay, sg)
		} else {
			u, err = saml.EncodeRedirect(o.dest, o.param, o.msg, o.relay)
		}
		if err != nil {
			return err
		}
		if sg != nil {
			s.event(f, LInfo, "Signature", 0, "", "Signed the URL with RSA-SHA256 (certificate %s)", saml.Thumbprints(sg.Cert))
		}
		http.Redirect(w, r, u, http.StatusFound)
		return nil
	}
	msg := o.msg
	if sg != nil {
		signed, err := sg.SignEnveloped(msg)
		if err != nil {
			return fmt.Errorf("could not sign the %s: %w", o.param, err)
		}
		msg = signed
		s.event(f, LInfo, "Signature", 0, "", "Signed the message with RSA-SHA256 (certificate %s)", saml.Thumbprints(sg.Cert))
	}
	s.render(w, r, http.StatusOK, "post.html", page{App: s.view(app.ID), Plain: o.plain,
		PostForm: &postForm{Action: o.dest, Field: o.param, Value: base64.StdEncoding.EncodeToString(msg), RelayState: o.relay}})
	return nil
}

// loadIdP fetches the app's metadata (or reads the pasted copy), stores it
// on the app, logs what it found to f, and saves the state.
func (s *Server) loadIdP(ctx context.Context, f *Flow, app *App) (*saml.IdP, error) {
	s.mu.Lock()
	mdURL, md := app.MetadataURL, []byte(app.MetadataXML)
	s.mu.Unlock()
	if mdURL != "" {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		t0 := time.Now()
		b, err := saml.FetchMetadata(ctx, mdURL)
		if err != nil {
			s.event(f, LError, "Metadata", time.Since(t0), "", "GET %s failed: %v", mdURL, err)
			return nil, fmt.Errorf("could not load the IdP metadata: %w", err)
		}
		md = b
		s.event(f, LInfo, "Metadata", time.Since(t0), "", "Loaded %s (%d bytes)", mdURL, len(b))
	}
	if len(md) == 0 {
		return nil, fmt.Errorf("enter the IdP metadata URL, or paste the metadata XML")
	}
	idp, err := saml.ParseMetadata(md)
	if err != nil {
		s.event(f, LError, "Metadata", 0, "", "Could not read the metadata: %v", err)
		return nil, fmt.Errorf("IdP metadata: %w", err)
	}
	s.event(f, LInfo, "Metadata", 0, metadataDetail(idp),
		"IdP %s, %d signing %s", idp.EntityID, len(idp.Certs), plural(len(idp.Certs), "certificate", "certificates"))
	s.mu.Lock()
	changed := !bytes.Equal(app.idpRaw, md)
	app.idp, app.idpRaw, app.idpLoadedAt = idp, md, time.Now()
	s.mu.Unlock()
	// Metadata fetched at every sign-in is usually the same, and a trial
	// copy (Settings checking a new URL) is not stored at all.
	if changed && s.app(app.ID) == app {
		s.saveState()
	}
	return idp, nil
}

func metadataDetail(idp *saml.IdP) string {
	var b strings.Builder
	fmt.Fprintf(&b, "entityID      %s\nSSO redirect  %s\nSSO POST      %s", idp.EntityID, orNone(idp.SSORedirect), orNone(idp.SSOPost))
	for _, c := range idp.Certs {
		fmt.Fprintf(&b, "\nsigning cert  %s\n              valid %s to %s", saml.Thumbprints(c),
			c.NotBefore.UTC().Format("Jan 2, 2006"), c.NotAfter.UTC().Format("Jan 2, 2006"))
	}
	return b.String()
}

// samlMetadata serves the SP metadata for one app (or the legacy app).
func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(saml.Metadata(s.spFor(r, app)))
}

// samlCert serves the app's signing or encryption certificate.
func (s *Server) samlCert(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("app"))
	if app == nil || !app.IsSAML() {
		http.NotFound(w, r)
		return
	}
	get, name := s.signerFor, "ssobench-signing.pem"
	if strings.HasSuffix(r.URL.Path, "/encryption.pem") {
		get, name = s.encKeyFor, "ssobench-encryption.pem"
	}
	sg, err := get(app)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(sg.CertPEM())
}

// samlACS receives a response. The app comes from the URL; on the legacy
// /saml/acs URL it comes from the request being answered, then the legacy
// app, then the IdP entity ID in the response.
func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	res := &Result{Kind: "SAML", Title: "SAML response", Via: ViaIdP}
	var f *Flow
	var app *App
	defer func() {
		s.save(res, f)
		http.Redirect(w, r, s.landing(res, app), http.StatusSeeOther)
	}()
	encoded := r.FormValue("SAMLResponse")
	relay := r.FormValue("RelayState")
	raw, err := saml.DecodeMessage(encoded)
	if err != nil {
		f = s.newFlow("SAML", "unreadable response")
		s.event(f, LError, "Response", 0, "", "POST to the ACS URL without a readable SAMLResponse: %v", err)
		res.Checks = []check.Result{check.Bad("SAMLResponse", "could not decode: "+err.Error(), "The IdP must POST a base64 SAMLResponse to this URL.")}
		return
	}
	xmlSec := Section{Group: GroupRaw, Title: "Response XML", Pre: saml.Pretty(raw), Open: true}

	// Attach to the attempt that sent the request, if any.
	var inResponseTo, issuer string
	if pr, err := saml.ParseResponse(raw); err == nil {
		inResponseTo, issuer = pr.InResponseTo, pr.Issuer
		if len(pr.Assertions) > 0 && pr.Assertions[0].Issuer != "" {
			issuer = pr.Assertions[0].Issuer
		}
	}
	pend, _ := s.pendingSAML.Peek(inResponseTo)
	switch id := r.PathValue("app"); {
	case pend != nil:
		app, res.Via = pend.app, pend.via
	case id != "":
		app = s.app(id)
	default:
		if app = s.legacyApp(ProtoSAML); app == nil {
			app = s.appByIssuer(issuer)
		}
	}
	if app == nil {
		f = s.newFlow("SAML", "no matching app")
		s.event(f, LError, "Response", 0, "", "Response from %q matches no app in SSOBench", issuer)
		res.Checks = []check.Result{check.Bad("App", fmt.Sprintf("no app in SSOBench matches this response (issuer %q)", issuer),
			"Create an app for this identity provider and register that app's ACS URL, or open Decode to just read the response.")}
		res.All = []Section{xmlSec}
		return
	}
	res.AppID, res.AppName = app.ID, s.appName(app)
	s.mu.Lock()
	idp := app.idp
	s.mu.Unlock()
	sp := s.spFor(r, app)
	var addrCheck *check.Result
	var alt *saml.SP
	if pend != nil {
		f = pend.flow
		if pend.sp != sp {
			arrived := sp
			alt = &arrived
			c := check.Meh("Sign-in address",
				fmt.Sprintf("the sign-in started at %s, but the IdP posted the response to %s", pend.sp.ACSURL, sp.ACSURL),
				"The IdP sends responses to the address registered for the app, not the one you opened, so both are accepted as SSOBench here. To test exactly what the app will see, open SSOBench at "+s.base(r)+" and sign in again.")
			addrCheck = &c
			s.event(f, LWarn, "Response", 0, "", "Started at %s, response arrived at %s", pend.sp.ACSURL, sp.ACSURL)
		}
		sp = pend.sp
		msg := fmt.Sprintf("IdP posted a response to the ACS URL, %s after the request (%d bytes)", humanDur(time.Since(pend.sent)), len(encoded))
		if relay != "" {
			msg += fmt.Sprintf(", RelayState %q", relay)
		}
		s.event(f, LInfo, "Response", 0, "", "%s", msg)
	} else {
		label := "IdP-initiated"
		if inResponseTo != "" {
			label = "response to an unknown or expired request"
		}
		f = s.newFlow("SAML", s.appName(app)+" ("+label+")")
		s.event(f, LWarn, "Response", 0, "", "IdP posted a response that answers no request from this tool (InResponseTo %q, %d bytes)", inResponseTo, len(encoded))
	}

	if idp == nil {
		s.event(f, LError, "Signature", 0, "", "App %q has no IdP metadata loaded, so the signature cannot be checked", s.appName(app))
		res.Checks = []check.Result{check.Bad("IdP metadata", "this app has no IdP metadata loaded, so the signature cannot be checked",
			"Save the IdP metadata URL in the app's settings, or open Decode to just read this response.")}
		res.All = []Section{xmlSec}
		return
	}

	// The callbacks consume state (a pending request, a replay marker), so
	// they are evaluated once and reused if the response is re-checked after
	// a metadata refresh.
	known := map[string]bool{}
	s.mu.Lock()
	wantEnc, hasEncKey := app.EncryptAssertions, app.EncKeyPEM != ""
	s.mu.Unlock()
	var decryptKey *rsa.PrivateKey
	if wantEnc || hasEncKey {
		if k, err := s.encKeyFor(app); err == nil {
			decryptKey = k.Key
		}
	}
	expect := saml.Expect{
		DecryptKey:    decryptKey,
		WantEncrypted: wantEnc,
		SP:            sp,
		Alt:           alt,
		IdP:           idp,
		RequestKnown: func(id string) bool {
			if v, ok := known[id]; ok {
				return v
			}
			_, ok := s.pendingSAML.Take(id)
			known[id] = ok
			return ok
		},
		// Only verified assertions are recorded, below, so a forged
		// response can't make a real one look like a replay.
		AssertionSeen: func(id string) bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			until, ok := s.seen[id]
			return ok && time.Now().Before(until)
		},
		Now:  time.Now(),
		Skew: s.Skew,
	}
	rep, err := saml.Inspect(raw, expect)

	// Signed with a certificate the metadata does not have: the IdP most
	// likely rolled its signing certificate. Refresh once from the URL.
	s.mu.Lock()
	mdURL := app.MetadataURL
	s.mu.Unlock()
	s.mu.Lock()
	recent := time.Since(app.idpRefreshAt) < time.Minute
	if err == nil && rep.UnknownSigner && mdURL != "" && !recent {
		app.idpRefreshAt = time.Now()
	}
	s.mu.Unlock()
	if err == nil && rep.UnknownSigner && mdURL != "" && recent {
		s.event(f, LWarn, "Metadata", 0, "", "Response is signed with a certificate the saved metadata does not have; the metadata was reloaded less than a minute ago, so not again")
	}
	if err == nil && rep.UnknownSigner && mdURL != "" && !recent {
		s.event(f, LWarn, "Metadata", 0, "", "Response is signed with a certificate the saved metadata does not have; reloading %s", mdURL)
		if fresh, ferr := s.loadIdP(r.Context(), f, app); ferr == nil {
			idp, expect.IdP = fresh, fresh
			rep, err = saml.Inspect(raw, expect)
			if err == nil && !rep.UnknownSigner {
				rep.Checks = append(rep.Checks, check.Meh("Metadata refresh",
					"the IdP signed with a certificate missing from the saved metadata; reloading the metadata fixed it",
					"The IdP rotated its signing certificate. Every SP that pins the old certificate needs the new metadata."))
			}
		}
	}
	if err == nil {
		s.recordAssertion(rep)
	}
	if err != nil {
		s.event(f, LError, "Response", 0, "", "%v", err)
		res.Checks = []check.Result{check.Bad("SAMLResponse", err.Error(), "The response could not be read as a SAML Response. Check that the identity provider posts a SAML 2.0 response to this app's ACS URL, or paste it into Decode to see what arrived.")}
		res.All = []Section{xmlSec}
		return
	}
	status := saml.Short(rep.Response.Status.Code.Value)
	if sub := rep.Response.Status.Code.Sub; sub != nil {
		status += " / " + saml.Short(sub.Value)
	}
	lvl := LInfo
	if status != "Success" {
		lvl = LError
		res.Refused = status
		if m := rep.Response.Status.Message; m != "" {
			res.Refused += ": " + m
		}
	}
	s.event(f, lvl, "Status", 0, rep.Response.Status.Message, "%s", status)
	sigLvl := LInfo
	if !rep.Verified {
		sigLvl = LError
	}
	s.event(f, sigLvl, "Signature", 0, strings.Join(rep.SigLog, "\n"), "%s", map[bool]string{true: "Assertion content verified", false: "No valid signature covers the assertion"}[rep.Verified])

	res.Checks = rep.Checks
	if pend != nil && pend.opts.IsPassive {
		passiveStatus(res.Checks, rep.Response)
	}
	if addrCheck != nil {
		res.Checks = append(res.Checks, *addrCheck)
	}
	res.RelayState = relay
	res.Checks = append(res.Checks, s.relayCheck(app, pend, relay, s.deepLinkURL(r, app))...)
	res.DeepLink = pend == nil && relay != "" && relay == s.deepLinkURL(r, app)
	res.Title, res.Issuer = idp.EntityID, idp.EntityID
	if a := rep.Assertion; a != nil {
		if a.Subject.NameID.Value != "" {
			res.Subject = a.Subject.NameID.Value
			res.Title = res.Subject + " at " + idp.EntityID
		}
		res.NameID, res.NameIDFormat = a.Subject.NameID.Value, a.Subject.NameID.Format
		if len(a.AuthnStatements) > 0 {
			res.SessionIndex = a.AuthnStatements[0].SessionIndex
			if t, err := time.Parse(time.RFC3339, a.AuthnStatements[0].SessionNotOnOrAfter); err == nil {
				res.SessionNotOnOrAfter = t
			}
		}
		s.event(f, LInfo, "Assertion", 0, "", "NameID %q, %d attributes", a.Subject.NameID.Value, len(a.Attributes))
		var requested time.Time
		var opts saml.AuthnOptions
		if pend != nil {
			requested, opts = pend.sent, pend.opts
		}
		if res.Auth = samlAuthInfo(a, requested, opts.ForceAuthn); rep.Verified {
			res.Checks = append(res.Checks, authChecks(res.Auth, time.Now(), s.Skew)...)
			res.Checks = append(res.Checks, requestChecks(opts, a, res.Auth)...)
		}
		res.All = append(res.All, attributesSection(a, rep.Verified))
		res.All = append(res.All, assertionSections(rep.Response, a, rep.SigLog)...)
	}
	if rep.DecryptedXML != "" {
		res.All = append(res.All, Section{Group: GroupRaw, Title: "Decrypted assertion", Pre: rep.DecryptedXML})
	}
	res.All = append(res.All, xmlSec)
}

// relayCheck checks RelayState. SP-initiated sign-ins must get back the
// value SSOBench sent. IdP-initiated ones, when the default relay state
// option is on, must carry the deep link SSOBench gives the app (want).
func (s *Server) relayCheck(app *App, pend *samlPending, got, want string) []check.Result {
	if pend != nil {
		switch {
		case pend.relay == "":
			return nil
		case got == pend.relay:
			return []check.Result{check.OK("RelayState", "returned unchanged")}
		case got == "":
			return []check.Result{check.Meh("RelayState", "not returned",
				"The IdP should return the RelayState it receives. Apps that use it for deep links lose the user's place.").Mismatch("", pend.relay)}
		}
		return []check.Result{check.Bad("RelayState", "changed on the way back",
			"The IdP must return the RelayState it receives, unchanged.").Mismatch(got, pend.relay)}
	}
	s.mu.Lock()
	on := app.RelayStateOn
	s.mu.Unlock()
	gu, gerr := url.Parse(got)
	wu, _ := url.Parse(want)
	switch {
	case on && got == want:
		return []check.Result{check.OK("Default relay state", "arrived through the app's deep link")}
	case on && got == "":
		return []check.Result{check.Bad("Default relay state", "none received",
			"Set the default relay state of this application at the IdP to the value under Set up at your identity provider.").Mismatch("", want)}
	case on && gerr == nil && gu.Path == wu.Path && gu.Host != wu.Host:
		return []check.Result{check.Meh("Default relay state", "the deep link points at another address of SSOBench",
			"The IdP has the relay state for a different address. If that is the address you use, ignore this; otherwise update it at the IdP.").Mismatch(got, want)}
	case on:
		return []check.Result{check.Bad("Default relay state", "not the value SSOBench gave this app",
			"Set the default relay state of this application at the IdP to exactly the value under Set up at your identity provider"+nearMissText(got, want)+".").Mismatch(got, want)}
	case got != "":
		return []check.Result{check.Note("RelayState", fmt.Sprintf("%q (turn on Default relay state in the app's settings to check it)", got))}
	}
	return nil
}

func nearMissText(got, want string) string {
	switch {
	case strings.TrimRight(got, "/") == strings.TrimRight(want, "/"):
		return " (they differ only by a trailing slash)"
	case strings.EqualFold(got, want):
		return " (they differ only by upper/lower case)"
	case strings.TrimSpace(got) == strings.TrimSpace(want):
		return " (they differ only by spaces)"
	}
	return ""
}

// attributesSection lists every attribute with its full name. The friendly
// name and the name format go in the hint; FriendlyName is also the Title,
// which the welcome screen uses for its labels.
func attributesSection(a *saml.Assertion, verified bool) Section {
	sec := Section{Group: GroupIdentity, Title: "Attributes", Open: true}
	if !verified {
		sec.Note = "Unverified: no valid signature covers these values."
	}
	for _, at := range a.Attributes {
		hint := []string{at.Name}
		if at.FriendlyName != "" {
			hint = append(hint, "friendly name "+at.FriendlyName)
		}
		if at.NameFormat != "" {
			hint = append(hint, "name format "+saml.Short(at.NameFormat))
		}
		if len(at.Values) > 1 {
			hint = append(hint, fmt.Sprintf("%d values", len(at.Values)))
		}
		row := Row{K: at.Name, V: strings.Join(at.Values, "\n"), Title: at.FriendlyName}
		row.K = shortLabel(row) // readable label; the full name is the first line of the hint
		if row.K == at.Name {
			hint = hint[1:]
		}
		row.Hint = strings.Join(hint, ", ")
		sec.Rows = append(sec.Rows, row)
	}
	if len(sec.Rows) == 0 {
		sec.Note = strings.TrimSpace(sec.Note + " The assertion has no attributes. Add attribute mappings at the IdP to release some.")
	}
	return sec
}

// assertionSections break the whole response down, section by section, so
// nothing the IdP sent needs digging out of the XML.
func assertionSections(r *saml.Response, a *saml.Assertion, sigLog []string) []Section {
	kv := func(rows *[]Row, k, v string) {
		if v != "" {
			*rows = append(*rows, Row{K: k, V: v})
		}
	}
	timeRow := func(rows *[]Row, k, v string) {
		if v == "" {
			return
		}
		row := Row{K: k, V: v}
		if t := saml.ParseTime(v); !t.IsZero() {
			row.Hint = check.Rel(t, time.Now())
		}
		*rows = append(*rows, row)
	}

	var resp []Row
	kv(&resp, "Response ID", r.ID)
	kv(&resp, "Version", r.Version)
	timeRow(&resp, "Issue instant", r.IssueInstant)
	kv(&resp, "Issuer", r.Issuer)
	kv(&resp, "Destination", r.Destination)
	kv(&resp, "InResponseTo", r.InResponseTo)
	status := r.Status.Code.Value
	if r.Status.Code.Sub != nil {
		status += "\n" + r.Status.Code.Sub.Value
	}
	kv(&resp, "Status", status)
	kv(&resp, "Status message", r.Status.Message)
	kv(&resp, "Assertion ID", a.ID)
	timeRow(&resp, "Assertion issue instant", a.IssueInstant)
	kv(&resp, "Assertion issuer", a.Issuer)

	var subj []Row
	kv(&subj, "NameID", a.Subject.NameID.Value)
	kv(&subj, "NameID format", a.Subject.NameID.Format)
	kv(&subj, "NameQualifier", a.Subject.NameID.NameQualifier)
	kv(&subj, "SPNameQualifier", a.Subject.NameID.SPNameQualifier)
	for i, sc := range a.Subject.Confirmations {
		p := "Confirmation"
		if len(a.Subject.Confirmations) > 1 {
			p = fmt.Sprintf("Confirmation %d", i+1)
		}
		kv(&subj, p+" method", sc.Method)
		kv(&subj, p+" recipient", sc.Data.Recipient)
		timeRow(&subj, p+" not before", sc.Data.NotBefore)
		timeRow(&subj, p+" not on or after", sc.Data.NotOnOrAfter)
		kv(&subj, p+" InResponseTo", sc.Data.InResponseTo)
		kv(&subj, p+" address", sc.Data.Address)
	}

	var cond []Row
	if c := a.Conditions; c != nil {
		timeRow(&cond, "Not before", c.NotBefore)
		timeRow(&cond, "Not on or after", c.NotOnOrAfter)
		kv(&cond, "Audience", strings.Join(c.Audiences, "\n"))
		if c.OneTimeUse != nil {
			kv(&cond, "One-time use", "yes")
		}
		if pr := c.ProxyRestriction; pr != nil {
			kv(&cond, "Proxy restriction count", pr.Count)
			kv(&cond, "Proxy restriction audience", strings.Join(pr.Audiences, "\n"))
		}
	}

	var authn []Row
	for i, st := range a.AuthnStatements {
		p := ""
		if len(a.AuthnStatements) > 1 {
			p = fmt.Sprintf("%d: ", i+1)
		}
		timeRow(&authn, p+"Authenticated at", st.AuthnInstant)
		kv(&authn, p+"Session index", st.SessionIndex)
		timeRow(&authn, p+"Session not on or after", st.SessionNotOnOrAfter)
		kv(&authn, p+"Authentication context", st.ClassRef)
		kv(&authn, p+"Context declaration", st.DeclRef)
		kv(&authn, p+"Authenticating authority", strings.Join(st.Authorities, "\n"))
		if l := st.Locality; l != nil {
			kv(&authn, p+"Client address", l.Address)
			kv(&authn, p+"Client DNS name", l.DNSName)
		}
	}

	secs := []Section{{Group: GroupDetail, Title: "Response and assertion", Rows: resp}}
	if len(subj) > 0 {
		secs = append(secs, Section{Group: GroupDetail, Title: "Subject", Rows: subj})
	}
	if len(cond) > 0 {
		secs = append(secs, Section{Group: GroupDetail, Title: "Conditions", Rows: cond})
	}
	if len(authn) > 0 {
		secs = append(secs, Section{Group: GroupDetail, Title: "Authentication", Rows: authn})
	}
	if len(sigLog) > 0 {
		secs = append(secs, Section{Group: GroupDetail, Title: "Signatures", Pre: strings.Join(sigLog, "\n")})
	}
	return secs
}

// seenFallback is how long an assertion ID is kept when the assertion
// gives no end to its lifetime.
const seenFallback = 24 * time.Hour

// recordAssertion remembers a verified assertion's ID until it expires,
// for replay detection, and forgets expired ones.
func (s *Server) recordAssertion(rep *saml.Report) {
	a := rep.Assertion
	if !rep.Verified || a == nil || a.ID == "" {
		return
	}
	now := time.Now()
	until := now.Add(seenFallback)
	if c := a.Conditions; c != nil {
		if t, err := time.Parse(time.RFC3339, c.NotOnOrAfter); err == nil && t.Add(s.Skew).Before(until) {
			until = t.Add(s.Skew)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.seen {
		if now.After(t) {
			delete(s.seen, id)
		}
	}
	if until.After(s.seen[a.ID]) {
		s.seen[a.ID] = until
	}
}
