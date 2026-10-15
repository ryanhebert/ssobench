package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanhebert/ssobench/internal/webauthn"
)

// The console (apps, settings, results, activity) is open by default. Its
// admin can require a password, passkeys, or both, under Settings; a
// password can also be given at start (Server.AdminPassword). The pages
// people sign in from, the identity provider's endpoints and SCIM always
// stay open: they are what the identity provider and test users reach.

const (
	consoleCookie  = "ssobench-console"
	consoleSession = 12 * time.Hour
	minPassword    = 8
)

// failedDelay slows guessing: each failed sign-in waits this long.
var failedDelay = time.Second

// pbkdf2Iterations follows the OWASP recommendation for PBKDF2-SHA256.
// Each hash records its own count, so raising it later is safe.
var pbkdf2Iterations = 600_000

// ConsoleAccess is what the console asks for, as saved in the state file.
// Both empty means no sign-in.
type ConsoleAccess struct {
	Password string    `json:"password,omitempty"` // pbkdf2-sha256$iterations$salt$hash
	Passkeys []Passkey `json:"passkeys,omitempty"`
}

// Passkey is a registered WebAuthn credential. It works only at the host
// name it was added at (RPID).
type Passkey struct {
	ID        []byte    `json:"id"`
	PublicKey []byte    `json:"public_key"` // COSE_Key
	RPID      string    `json:"rp_id"`
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used,omitzero"`
	SignCount uint32    `json:"sign_count,omitempty"`
}

func (a ConsoleAccess) empty() bool { return a.Password == "" && len(a.Passkeys) == 0 }

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iterations, 32)
	enc := base64.RawStdEncoding.EncodeToString
	return "pbkdf2-sha256$" + strconv.Itoa(pbkdf2Iterations) + "$" + enc(salt) + "$" + enc(key)
}

func checkPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	salt, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err3 := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || err2 != nil || err3 != nil || iter < 1 || iter > 10_000_000 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// consoleSessions are the signed-in console browsers, by cookie value,
// with when each expires. They live in memory: a restart signs everyone out.
type consoleSessions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (c *consoleSessions) add() string {
	b := make([]byte, 32)
	rand.Read(b)
	id := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]time.Time{}
	}
	now := time.Now()
	for k, exp := range c.m {
		if now.After(exp) {
			delete(c.m, k)
		}
	}
	c.m[id] = now.Add(consoleSession)
	return id
}

// valid reports whether id is a live session, extending it when it is.
func (c *consoleSessions) valid(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[id]
	if !ok || time.Now().After(exp) {
		delete(c.m, id)
		return false
	}
	c.m[id] = time.Now().Add(consoleSession)
	return true
}

func (c *consoleSessions) end(id string) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}

// endOthers signs out every browser but keep's.
func (c *consoleSessions) endOthers(keep string) {
	c.mu.Lock()
	for k := range c.m {
		if k != keep {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

// openPath reports whether a path stays reachable without console sign-in.
func openPath(p string) bool {
	for _, pre := range []string{"/assets/", "/a/", "/saml/", "/oidc/", "/oauth/", "/scim/", "/console/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// protected reports whether the console asks for sign-in.
func (s *Server) protected() bool {
	if s.AdminPassword != "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.access.empty()
}

func (s *Server) consoleSignedIn(r *http.Request) bool {
	if !s.protected() {
		return true
	}
	c, err := r.Cookie(consoleCookie)
	return err == nil && s.console.valid(c.Value)
}

// startConsoleSession signs this browser in to the console.
func (s *Server) startConsoleSession(w http.ResponseWriter, r *http.Request) string {
	id := s.console.add()
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	return id
}

// guard sends visitors without a console session to the sign-in page.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if openPath(r.URL.Path) || s.consoleSignedIn(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Sign in to the SSOBench console first.", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/console/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	})
}

// localPath keeps a post-sign-in destination on this site.
func localPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") || strings.HasPrefix(next, "/console/") {
		return "/"
	}
	return next
}

// ---- passkey context ----

// rpID is the WebAuthn relying party ID for this request: the host name.
// Browsers refuse IP addresses, and want HTTPS except on localhost.
func (s *Server) rpID(r *http.Request) (id, why string) {
	u, err := url.Parse(s.base(r))
	if err != nil {
		return "", "the address SSOBench was opened at could not be read"
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case net.ParseIP(host) != nil:
		return "", "Passkeys need a host name, not an IP address. Open SSOBench by its name to add or use one."
	case u.Scheme != "https" && host != "localhost" && !strings.HasSuffix(host, ".localhost"):
		return "", "Passkeys need HTTPS (or localhost). Start SSOBench with -tls or -cert to use them."
	}
	return host, ""
}

func (s *Server) origin(r *http.Request) string {
	u, _ := url.Parse(s.base(r))
	return u.Scheme + "://" + u.Host
}

// webauthnChallenge is a challenge handed to the browser, waiting for its
// answer.
type webauthnChallenge struct {
	challenge []byte
	register  bool
	rpID      string
}

func (s *Server) newChallenge(register bool, rpID string) string {
	b := make([]byte, 32)
	rand.Read(b)
	key := base64.RawURLEncoding.EncodeToString(b)
	s.pendingWebAuthn.Put(key, &webauthnChallenge{challenge: b, register: register, rpID: rpID})
	return key
}

// takeChallenge finds the challenge a WebAuthn answer is for; each is used once.
func (s *Server) takeChallenge(clientDataJSON []byte, register bool) (*webauthnChallenge, error) {
	key, err := webauthn.Challenge(clientDataJSON)
	if err != nil {
		return nil, err
	}
	c, ok := s.pendingWebAuthn.Take(key)
	if !ok || c.register != register {
		return nil, errors.New("this request expired or was already used; try again")
	}
	return c, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// b64 is how WebAuthn binary values travel in JSON: base64url, no padding.
type b64 []byte

func (b *b64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	*b = v
	return err
}

func (b b64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// ---- sign-in page ----

// AccessView describes console sign-in for the sign-in and Settings pages.
type AccessView struct {
	Protected   bool // the console asks for sign-in
	Password    bool // a password is saved here
	Startup     bool // a password was given at start
	Persisting  bool // saved to the state file
	Passkeys    []PasskeyView
	PasskeyHere int    // passkeys that work at this host name
	Host        string // this request's host name, when passkeys can work
	PasskeyWhy  string // why passkeys cannot work at this address
	Next        string
}

type PasskeyView struct {
	ID, Name, RPID string
	Created        time.Time
	LastUsed       time.Time
	Here           bool
}

func (s *Server) accessView(r *http.Request) *AccessView {
	host, why := s.rpID(r)
	v := &AccessView{Startup: s.AdminPassword != "", Persisting: s.StatePath != "", Host: host, PasskeyWhy: why}
	s.mu.Lock()
	v.Password = s.access.Password != ""
	for _, p := range s.access.Passkeys {
		here := host != "" && p.RPID == host
		if here {
			v.PasskeyHere++
		}
		v.Passkeys = append(v.Passkeys, PasskeyView{ID: base64.RawURLEncoding.EncodeToString(p.ID), Name: p.Name, RPID: p.RPID,
			Created: p.Created, LastUsed: p.LastUsed, Here: here})
	}
	v.Protected = v.Startup || !s.access.empty()
	s.mu.Unlock()
	return v
}

func (s *Server) consoleLogin(w http.ResponseWriter, r *http.Request) {
	next := localPath(r.FormValue("next"))
	if !s.protected() || (r.Method == http.MethodGet && s.consoleSignedIn(r)) {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	p := page{Access: s.accessView(r)}
	p.Access.Next = next
	if r.Method == http.MethodPost {
		pw := r.FormValue("password")
		s.mu.Lock()
		saved := s.access.Password
		s.mu.Unlock()
		ok := saved != "" && checkPassword(saved, pw)
		if s.AdminPassword != "" {
			got, want := sha256.Sum256([]byte(pw)), sha256.Sum256([]byte(s.AdminPassword))
			ok = ok || subtle.ConstantTimeCompare(got[:], want[:]) == 1
		}
		if ok {
			s.startConsoleSession(w, r)
			s.logf("console: signed in with the password from %s", r.RemoteAddr)
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		s.logf("console: wrong password from %s", r.RemoteAddr)
		time.Sleep(failedDelay)
		p.Errs = map[string]FieldError{"password": {Msg: "Wrong password."}}
		s.render(w, r, http.StatusUnauthorized, "console_login.html", p)
		return
	}
	s.render(w, r, http.StatusOK, "console_login.html", p)
}

func (s *Server) consoleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(consoleCookie); err == nil {
		s.console.end(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: consoleCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	http.Redirect(w, r, "/console/login", http.StatusSeeOther)
}

// passkeyLoginOptions starts a passkey sign-in: the options for
// navigator.credentials.get().
func (s *Server) passkeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	rp, why := s.rpID(r)
	if rp == "" {
		jsonError(w, http.StatusBadRequest, why)
		return
	}
	var allow []map[string]any
	s.mu.Lock()
	for _, p := range s.access.Passkeys {
		if p.RPID == rp {
			allow = append(allow, map[string]any{"type": "public-key", "id": b64(p.ID)})
		}
	}
	s.mu.Unlock()
	if len(allow) == 0 {
		jsonError(w, http.StatusBadRequest, "No passkey was added at "+rp+".")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": s.newChallenge(false, rp), "rpId": rp, "allowCredentials": allow,
		"userVerification": "required", "timeout": 120000,
	})
}

// passkeyLogin checks a navigator.credentials.get() answer and signs the
// browser in.
func (s *Server) passkeyLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID                b64 `json:"id"`
		ClientDataJSON    b64 `json:"clientDataJSON"`
		AuthenticatorData b64 `json:"authenticatorData"`
		Signature         b64 `json:"signature"`
	}
	fail := func(msg string) {
		s.logf("console: passkey sign-in failed from %s: %s", r.RemoteAddr, msg)
		time.Sleep(failedDelay)
		jsonError(w, http.StatusUnauthorized, "That passkey could not sign you in: "+msg)
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		fail("the browser's answer could not be read")
		return
	}
	c, err := s.takeChallenge(in.ClientDataJSON, false)
	if err != nil {
		fail(err.Error())
		return
	}
	s.mu.Lock()
	i := slices.IndexFunc(s.access.Passkeys, func(p Passkey) bool { return p.RPID == c.rpID && string(p.ID) == string(in.ID) })
	var cred webauthn.Credential
	if i >= 0 {
		p := s.access.Passkeys[i]
		cred = webauthn.Credential{ID: p.ID, PublicKey: p.PublicKey, SignCount: p.SignCount}
	}
	s.mu.Unlock()
	if i < 0 {
		fail("it is not one of the passkeys added in Settings")
		return
	}
	count, err := webauthn.VerifyAssertion(cred, in.ClientDataJSON, in.AuthenticatorData, in.Signature, c.challenge, s.origin(r), c.rpID)
	if err != nil {
		fail(err.Error())
		return
	}
	name := ""
	s.locked(func() {
		if j := slices.IndexFunc(s.access.Passkeys, func(p Passkey) bool { return string(p.ID) == string(in.ID) }); j >= 0 {
			s.access.Passkeys[j].SignCount, s.access.Passkeys[j].LastUsed = count, time.Now()
			name = s.access.Passkeys[j].Name
		}
	})
	s.saveState()
	s.startConsoleSession(w, r)
	s.logf("console: signed in with passkey %q from %s", name, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"next": localPath(r.URL.Query().Get("next"))})
}

// ---- Settings ----

var settingsNotices = map[string]string{
	"password":         "Password saved. The console now asks for it.",
	"password-changed": "Password changed. Other browsers were signed out.",
	"password-removed": "Password removed.",
	"passkey":          "Passkey added.",
	"passkey-removed":  "Passkey removed.",
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	p := page{Nav: "settings", Access: s.accessView(r), Notice: settingsNotices[r.URL.Query().Get("done")]}
	if !p.Access.Protected && p.Notice != "" && strings.HasSuffix(r.URL.Query().Get("done"), "removed") {
		p.Notice += " The console no longer asks for sign-in."
	}
	s.render(w, r, http.StatusOK, "settings.html", p)
}

func (s *Server) passwordSave(w http.ResponseWriter, r *http.Request) {
	pw, confirm := r.FormValue("password"), r.FormValue("confirm")
	errs := map[string]FieldError{}
	switch {
	case len([]rune(pw)) < minPassword:
		errs["password"] = FieldError{Msg: "Use at least " + strconv.Itoa(minPassword) + " characters."}
	case pw != confirm:
		errs["confirm"] = FieldError{Msg: "The two passwords are different."}
	}
	if len(errs) > 0 {
		p := page{Nav: "settings", Access: s.accessView(r), Errs: errs}
		s.render(w, r, http.StatusBadRequest, "settings.html", p)
		return
	}
	hash := hashPassword(pw)
	var wasProtected, changed bool
	s.locked(func() {
		wasProtected, changed = !s.access.empty(), s.access.Password != ""
		s.access.Password = hash
	})
	s.saveState()
	s.keepSignedIn(w, r, wasProtected)
	done := "password"
	if changed {
		done = "password-changed"
	}
	s.logf("console: password %s", map[bool]string{true: "changed", false: "set"}[changed])
	http.Redirect(w, r, "/settings?done="+done, http.StatusSeeOther)
}

// keepSignedIn makes sure the browser that turned sign-in on stays signed
// in, and signs out every other browser.
func (s *Server) keepSignedIn(w http.ResponseWriter, r *http.Request, wasProtected bool) {
	var keep string
	if c, err := r.Cookie(consoleCookie); err == nil && wasProtected && s.console.valid(c.Value) {
		keep = c.Value
	} else {
		keep = s.startConsoleSession(w, r)
	}
	s.console.endOthers(keep)
}

func (s *Server) passwordRemove(w http.ResponseWriter, r *http.Request) {
	s.locked(func() { s.access.Password = "" })
	s.saveState()
	s.logf("console: password removed")
	http.Redirect(w, r, "/settings?done=password-removed", http.StatusSeeOther)
}

// passkeyOptions starts adding a passkey: the options for
// navigator.credentials.create().
func (s *Server) passkeyOptions(w http.ResponseWriter, r *http.Request) {
	rp, why := s.rpID(r)
	if rp == "" {
		jsonError(w, http.StatusBadRequest, why)
		return
	}
	var exclude []map[string]any
	s.mu.Lock()
	for _, p := range s.access.Passkeys {
		if p.RPID == rp {
			exclude = append(exclude, map[string]any{"type": "public-key", "id": b64(p.ID)})
		}
	}
	s.mu.Unlock()
	var params []map[string]any
	for _, alg := range webauthn.Algorithms {
		params = append(params, map[string]any{"type": "public-key", "alg": alg})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": s.newChallenge(true, rp),
		"rp":        map[string]string{"id": rp, "name": "SSOBench"},
		// One console admin: every passkey belongs to the same user.
		"user":                   map[string]any{"id": b64("ssobench-console"), "name": "admin", "displayName": "SSOBench console"},
		"pubKeyCredParams":       params,
		"excludeCredentials":     exclude,
		"authenticatorSelection": map[string]any{"residentKey": "preferred", "userVerification": "required"},
		"attestation":            "none",
		"timeout":                120000,
	})
}

func (s *Server) passkeyAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name              string `json:"name"`
		ClientDataJSON    b64    `json:"clientDataJSON"`
		AttestationObject b64    `json:"attestationObject"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "The browser's answer could not be read.")
		return
	}
	c, err := s.takeChallenge(in.ClientDataJSON, true)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "The passkey was not added: "+err.Error())
		return
	}
	cred, err := webauthn.VerifyRegistration(in.ClientDataJSON, in.AttestationObject, c.challenge, s.origin(r), c.rpID)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "The passkey was not added: "+err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Passkey"
	}
	if len([]rune(name)) > 60 {
		name = string([]rune(name)[:60])
	}
	var wasProtected, dup bool
	s.locked(func() {
		wasProtected = !s.access.empty()
		if dup = slices.ContainsFunc(s.access.Passkeys, func(p Passkey) bool { return string(p.ID) == string(cred.ID) }); !dup {
			s.access.Passkeys = append(s.access.Passkeys, Passkey{ID: cred.ID, PublicKey: cred.PublicKey, RPID: c.rpID,
				Name: name, Created: time.Now(), SignCount: cred.SignCount})
		}
	})
	if dup {
		jsonError(w, http.StatusBadRequest, "That passkey is already added.")
		return
	}
	s.saveState()
	if !wasProtected {
		s.keepSignedIn(w, r, false)
	}
	s.logf("console: passkey %q added for %s", name, c.rpID)
	writeJSON(w, http.StatusOK, map[string]string{"next": "/settings?done=passkey"})
}

func (s *Server) passkeyRemove(w http.ResponseWriter, r *http.Request) {
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var found bool
	s.locked(func() {
		n := len(s.access.Passkeys)
		s.access.Passkeys = slices.DeleteFunc(s.access.Passkeys, func(p Passkey) bool { return string(p.ID) == string(id) })
		found = len(s.access.Passkeys) < n
	})
	if !found {
		http.NotFound(w, r)
		return
	}
	s.saveState()
	s.logf("console: passkey removed")
	http.Redirect(w, r, "/settings?done=passkey-removed", http.StatusSeeOther)
}

// ResetConsoleAccess removes the saved password and passkeys: the way back
// in for an admin who lost them.
func (s *Server) ResetConsoleAccess() bool {
	var had bool
	s.locked(func() {
		had = !s.access.empty()
		s.access = ConsoleAccess{}
	})
	if had {
		s.saveState()
	}
	return had
}

// Protected reports whether the console asks for sign-in.
func (s *Server) Protected() bool { return s.protected() }
