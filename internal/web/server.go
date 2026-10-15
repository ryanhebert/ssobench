// Package web serves the UI and the OIDC/SAML endpoints. Sign-in results
// and logs live in memory; apps are kept in the state file when one is set.
package web

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanhebert/ssobench/internal/check"
	"github.com/ryanhebert/ssobench/internal/decode"
	"github.com/ryanhebert/ssobench/internal/oidc"
	"github.com/ryanhebert/ssobench/internal/saml"
)

//go:embed assets
var assets embed.FS

const (
	maxResults    = 50
	defaultScopes = "openid profile email"
)

type Server struct {
	// BaseURL pins the public URL (behind a reverse proxy). When empty, URLs
	// follow how the browser reached SSOBench: scheme plus Host header.
	BaseURL string
	// AllowedHosts are the host names SSOBench answers to, besides IP
	// addresses and localhost. Empty accepts any.
	AllowedHosts []string
	Skew         time.Duration
	Version      string
	Quiet        bool // do not echo log events to the terminal
	// StatePath, when set, keeps the apps across restarts (see apps.go).
	StatePath string
	// AdminPassword, given at start, always signs in to the console, besides
	// the password and passkeys saved under Settings (see console.go).
	AdminPassword   string
	console         consoleSessions
	access          ConsoleAccess // console sign-in, under mu
	pendingWebAuthn pendingSet[*webauthnChallenge]
	historyOff      bool          // the history file is from a newer version: leave it alone
	onSave          func(*Result) // tests: inspect every result as it is saved

	pages map[string]*template.Template

	mu            sync.Mutex
	stateSaver    fileSaver
	historySaver  fileSaver
	apps          []*App
	pendingOIDC   pendingSet[*codePending]   // by state
	pendingSAML   pendingSet[*samlPending]   // by AuthnRequest ID
	pendingLogout pendingSet[*logoutPending] // by LogoutRequest ID or OIDC state
	pendingOAuth  pendingSet[*codePending]   // by state
	seen          map[string]time.Time       // verified assertion IDs, until when a replay is possible
	results       []*Result                  // newest first
	flows         []*Flow                    // newest first
}

// Result is one completed (or failed) sign-in attempt.
type Result struct {
	ID       string         `json:"ID"`
	FlowID   string         `json:"FlowID"`
	AppID    string         `json:"AppID"`
	AppName  string         `json:"AppName"`
	Kind     string         `json:"Kind"`
	Title    string         `json:"Title"`   // one line, for lists
	Subject  string         `json:"Subject"` // who signed in
	Issuer   string         `json:"Issuer"`  // which IdP
	Time     time.Time      `json:"Time"`
	Duration time.Duration  `json:"Duration"` // from the button press to the result
	Checks   []check.Result `json:"Checks"`
	All      []Section      `json:"All"`
	// Refused is set when the IdP itself declined the sign-in, which is a
	// different story from a sign-in that arrived with problems.
	Refused string `json:"Refused"`
	Via     string `json:"Via"` // ViaConsole, ViaPage or ViaIdP

	// For signing out later, and for the welcome screen.
	NameID       string `json:"NameID"` // SAML
	NameIDFormat string `json:"NameIDFormat"`
	SessionIndex string `json:"SessionIndex"`
	IDToken      string `json:"IDToken"`    // OIDC, for id_token_hint
	RelayState   string `json:"RelayState"` // SAML RelayState received
	DeepLink     bool   `json:"DeepLink"`   // arrived through the app's default relay state
	Ended        bool   `json:"Ended"`      // signed out: the welcome screen is no longer shown

	// User directory
	Account        string `json:"Account"` // matched account userName
	AccountName    string `json:"AccountName"`
	AccountProblem string `json:"AccountProblem"` // "", "missing", "notfound" or "inactive"
	AccountValue   string `json:"AccountValue"`   // the value matched against the directory

	// Sessions
	SessionID           string     `json:"SessionID"` // the session this sign-in opened, if any
	Sub                 string     `json:"Sub"`       // OIDC sub and sid, to match back-channel logouts
	SID                 string     `json:"SID"`
	SessionNotOnOrAfter time.Time  `json:"SessionNotOnOrAfter"` // SAML: when the IdP says the session ends
	Auth                *AuthInfo  `json:"Auth"`                // how and when the person authenticated
	Scopes              []ScopeRow `json:"Scopes"`              // OpenID Connect: scopes asked for, granted and the claims they brought
	AccountID           string     `json:"AccountID"`           // the matched account, when found
	Role                string     `json:"Role"`                // the role the app\'s access rules gave
	AccessProblem       string     `json:"AccessProblem"`       // "denied" when no access rule matched

	// OAuth 2.1
	GrantedScopes []string  `json:"GrantedScopes"`
	TokenExpiry   time.Time `json:"TokenExpiry"`
	Machine       bool      `json:"Machine"`     // a client credentials token
	Conformance   bool      `json:"Conformance"` // a conformance check run, not a sign-in
	Mode          string    `json:"Mode"`        // the guided check this sign-in ran (ModeNoPKCE...), if any
}

type Section struct {
	Group string `json:"Group"` // GroupIdentity, GroupDetail or GroupRaw
	Title string `json:"Title"`
	Note  string `json:"Note"`
	Rows  []Row  `json:"Rows"`
	Pre   string `json:"Pre"`
	Open  bool   `json:"Open"`
}

// Row is one key/value line. Hint shows under the value; Title (a SAML
// attribute's full name, say) appears on hover over the key.
type Row struct {
	K      string `json:"K"`
	V      string `json:"V"`
	Hint   string `json:"Hint"`
	Title  string `json:"Title"`
	Status string `json:"Status"`
}

func New(baseURL string, skew time.Duration, version string) (*Server, error) {
	funcs := template.FuncMap{
		"ago":              ago,
		"until":            until,
		"plural":           plural,
		"lower":            strings.ToLower,
		"expectedText":     formatExpected,
		"highlight":        highlight,
		"join":             strings.Join,
		"nameIDFormats":    func() any { return nameIDFormats },
		"authnComparisons": func() []string { return authnComparisons },
		"nameIDLabel":      nameIDLabel,
		"hasPrefix":        strings.HasPrefix,
		"hasSuffix":        strings.HasSuffix,
		"capitalize":       capitalize,
		"initialsOf":       initials,
		"otherEmail":       otherEmail,
		"sourceLabel":      sourceLabel,
		"matchLabel":       matchLabel,
		"add":              func(a, b int) int { return a + b },
		"ruleLead":         func(r AccessRule) string { l, _ := r.DescribeParts(); return l },
		"ruleValues":       func(r AccessRule) string { _, v := r.DescribeParts(); return v },
		"minutesLabel":     minutesLabel,
		"endedLabel":       endedLabel,
		"lasted":           func(a, b time.Time) string { return humanDur(b.Sub(a)) },
		"agoLong":          agoLong,
		"certStatus":       certStatus,
		"diff":             diffParts,
		"fieldErr": func(m map[string]FieldError, k string) *FieldError {
			if e, ok := m[k]; ok {
				return &e
			}
			return nil
		},
		"ref": FormatRef,
		"utc": func(t time.Time) string { return t.UTC().Format("Jan 2, 15:04:05 UTC") },
		"sha1": func(c *x509.Certificate) string {
			sum := sha1.Sum(c.Raw)
			return strings.ToUpper(hex.EncodeToString(sum[:]))
		},
		"ms": func(d time.Duration) string {
			if d < time.Second {
				return fmt.Sprintf("%d ms", d.Milliseconds())
			}
			return d.Round(10 * time.Millisecond).String()
		},
	}
	// Each page gets its own set so their "title" blocks do not collide.
	pages := map[string]*template.Template{}
	for _, name := range []string{"apps.html", "app.html", "app_setup.html", "app_users.html", "app_settings.html", "app_sessions.html", "app_new.html", "history.html", "result.html", "decode.html", "post.html", "log.html", "signin.html", "welcome.html", "signedout.html", "app_delete.html", "blocked.html", "console_login.html", "settings.html"} {
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "assets/layout.html", "assets/app_parts.html", "assets/"+name)
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return &Server{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Skew:    skew,
		Version: version,
		pages:   pages,
		seen:    map[string]time.Time{},
	}, nil
}

// base is the public URL for this request.
func (s *Server) base(r *http.Request) string {
	if s.BaseURL != "" {
		return s.BaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// spFor is the SAML service provider identity of app at this address.
// app may be a page's snapshot; keys are made on the live app.
func (s *Server) spFor(r *http.Request, app *App) saml.SP {
	if live := s.app(app.ID); live != nil {
		app = live
	}
	b := s.base(r)
	sp := saml.SP{EntityID: b + "/saml/" + app.ID + "/metadata", ACSURL: b + "/saml/" + app.ID + "/acs"}
	if app.Legacy {
		sp = saml.SP{EntityID: b + "/saml/metadata", ACSURL: b + "/saml/acs"}
	}
	s.mu.Lock()
	logout, signAuthn, encrypt := app.Logout, app.SignAuthn, app.EncryptAssertions
	sp.NameIDFormat = app.NameIDFormat
	s.mu.Unlock()
	if encrypt {
		if k, err := s.encKeyFor(app); err == nil {
			sp.EncryptionCert = k.CertBase64()
		} else {
			s.logf("%s: no SAML encryption key: %v", app.ID, err)
		}
	}
	if logout {
		sp.SLOURL = s.sloURL(r, app)
	}
	if sg, err := s.signerFor(app); err == nil {
		sp.SigningCert, sp.SignRequests = sg.CertBase64(), signAuthn
	} else {
		s.logf("%s: no SAML signing key: %v", app.ID, err)
	}
	return sp
}

func (s *Server) redirectFor(r *http.Request, app *App) string {
	if app.IsOAuth() {
		return s.oauthRedirectFor(r, app)
	}
	if app.Legacy {
		return s.base(r) + "/oidc/callback"
	}
	return s.base(r) + "/oidc/" + app.ID + "/callback"
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Only the static files: no directory listing, no raw templates.
	static := http.FileServerFS(assets)
	mux.HandleFunc("GET /assets/{file}", func(w http.ResponseWriter, r *http.Request) {
		switch path.Ext(r.PathValue("file")) {
		case ".css", ".js", ".svg":
			static.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("GET /{$}", s.appsPage)
	mux.HandleFunc("GET /apps/new", s.appNewPage)
	mux.HandleFunc("POST /apps", s.appCreate)
	mux.HandleFunc("GET /apps/{id}", s.appPage)
	mux.HandleFunc("POST /apps/{id}", s.appUpdate)
	mux.HandleFunc("GET /apps/{id}/setup", func(w http.ResponseWriter, r *http.Request) { s.appTab(w, r, "setup") })
	mux.HandleFunc("GET /apps/{id}/users", func(w http.ResponseWriter, r *http.Request) { s.appTab(w, r, "users") })
	mux.HandleFunc("GET /apps/{id}/settings", func(w http.ResponseWriter, r *http.Request) { s.appTab(w, r, "settings") })
	mux.HandleFunc("GET /apps/{id}/sessions", func(w http.ResponseWriter, r *http.Request) { s.appTab(w, r, "sessions") })
	mux.HandleFunc("POST /apps/{id}/sessions/{sid}/end", s.sessionEnd)
	mux.HandleFunc("POST /oidc/{app}/backchannel-logout", s.backchannelLogout)
	mux.HandleFunc("POST /apps/{id}/directory", s.directoryOn)
	mux.HandleFunc("POST /apps/{id}/rules", s.ruleAdd)
	mux.HandleFunc("POST /apps/{id}/rules/{n}/delete", s.ruleDelete)
	mux.HandleFunc("POST /apps/{id}/secret", s.secretSave)
	mux.HandleFunc("POST /apps/{id}/signin", s.appSignIn)
	mux.HandleFunc("POST /apps/{id}/users", s.userAdd)
	mux.HandleFunc("POST /apps/{id}/users/import", s.userImport)
	mux.HandleFunc("POST /apps/{id}/users/{uid}/active", s.userSetActive)
	mux.HandleFunc("POST /apps/{id}/users/{uid}/delete", s.userDelete)
	mux.HandleFunc("POST /apps/{id}/scim-token", s.scimNewToken)
	mux.HandleFunc("/scim/{app}/v2/{rest...}", s.scimHandler)
	mux.HandleFunc("GET /apps/{id}/delete", s.appDeleteConfirm)
	mux.HandleFunc("POST /apps/{id}/delete", s.appDelete)
	// Each app's own sign-in page and welcome screen, for the person signing in.
	mux.HandleFunc("GET /a/{id}", s.signinPage)
	mux.HandleFunc("POST /a/{id}/login", s.signinStart)
	mux.HandleFunc("GET /a/{id}/welcome/{rid}", s.welcomePage)
	mux.HandleFunc("GET /a/{id}/signed-out", s.signedOutPage)
	mux.HandleFunc("GET /a/{id}/login", s.spLogin)
	// The deep link given as the default relay state. Opened directly, it
	// leads to the sign-in page, as an app's deep link would.
	mux.HandleFunc("GET /a/{id}/deep-link", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/a/"+r.PathValue("id"), http.StatusSeeOther)
	})
	mux.HandleFunc("POST /a/{id}/logout/{rid}", func(w http.ResponseWriter, r *http.Request) { s.signOut(w, r, ViaPage) })
	mux.HandleFunc("POST /apps/{id}/logout/{rid}", func(w http.ResponseWriter, r *http.Request) { s.signOut(w, r, ViaConsole) })
	mux.HandleFunc("GET /saml/{app}/slo", s.samlSLO)
	mux.HandleFunc("POST /saml/{app}/slo", s.samlSLO)
	mux.HandleFunc("GET /saml/slo", s.samlSLO)
	mux.HandleFunc("POST /saml/slo", s.samlSLO)
	mux.HandleFunc("GET /oidc/{app}/logout", s.oidcLogoutReturn)
	mux.HandleFunc("GET /oidc/logout", s.oidcLogoutReturn)
	mux.HandleFunc("GET /saml/{app}/metadata", s.samlMetadata)
	mux.HandleFunc("GET /saml/{app}/cert.pem", s.samlCert)
	mux.HandleFunc("GET /saml/{app}/encryption.pem", s.samlCert)
	mux.HandleFunc("POST /apps/{id}/expected", s.expectFromResult)
	mux.HandleFunc("POST /saml/{app}/acs", s.samlACS)
	mux.HandleFunc("GET /oidc/{app}/callback", s.oidcCallback)
	mux.HandleFunc("GET /oauth/{app}/callback", s.oauthCallback)
	mux.HandleFunc("POST /apps/{id}/machine", s.oauthMachine)
	mux.HandleFunc("POST /apps/{id}/conformance", s.oauthConformance)
	mux.HandleFunc("POST /apps/{id}/check/{mode}", s.oauthProbeSignIn)
	// The original single-app URLs, still registered at some IdPs.
	mux.HandleFunc("GET /saml/metadata", s.samlMetadata)
	mux.HandleFunc("POST /saml/acs", s.samlACS)
	mux.HandleFunc("GET /oidc/callback", s.oidcCallback)
	mux.HandleFunc("GET /saml", s.toApps)
	mux.HandleFunc("GET /oidc", s.toApps)

	mux.HandleFunc("GET /history", s.history)
	mux.HandleFunc("GET /result/{id}", s.result)
	mux.HandleFunc("GET /result/{id}/log.txt", s.resultLogText)
	mux.HandleFunc("GET /log", s.logPage)
	mux.HandleFunc("GET /log.txt", s.logText)
	mux.HandleFunc("GET /decode", s.decodePage)
	mux.HandleFunc("POST /decode", s.decodePage)
	mux.HandleFunc("GET /console/login", s.consoleLogin)
	mux.HandleFunc("POST /console/login", s.consoleLogin)
	mux.HandleFunc("POST /console/logout", s.consoleLogout)
	mux.HandleFunc("POST /console/passkey/options", s.passkeyLoginOptions)
	mux.HandleFunc("POST /console/passkey", s.passkeyLogin)
	mux.HandleFunc("GET /settings", s.settingsPage)
	mux.HandleFunc("POST /settings/password", s.passwordSave)
	mux.HandleFunc("POST /settings/password/remove", s.passwordRemove)
	mux.HandleFunc("POST /settings/passkeys/options", s.passkeyOptions)
	mux.HandleFunc("POST /settings/passkeys", s.passkeyAdd)
	mux.HandleFunc("POST /settings/passkeys/{id}/delete", s.passkeyRemove)
	return s.secure(s.guard(mux))
}

// secure sets headers and blocks two kinds of request a web page elsewhere
// could make the browser send:
//   - cross-site POSTs (CSRF), except to the ACS and SLO URLs, which the IdP
//     posts to by design, and SCIM, which uses a bearer token;
//   - requests for a Host name SSOBench does not answer to (DNS rebinding,
//     which would let another site read results and tokens).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !s.hostAllowed(r.Host) {
			// Plain text: a page for a foreign host must not load our assets.
			http.Error(w, "SSOBench does not answer to the host name "+strconv.Quote(r.Host)+
				". If you opened it at that name on purpose, start SSOBench with -allow-host "+hostOnly(r.Host)+".", http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodPost && !strings.HasSuffix(r.URL.Path, "/acs") && !strings.HasSuffix(r.URL.Path, "/slo") && !strings.HasPrefix(r.URL.Path, "/scim/") && crossSite(r) {
			s.render(w, r, http.StatusForbidden, "blocked.html", page{Error: "SSOBench blocked a request that came from another website. If you clicked a button in SSOBench, reload the page and try again."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// crossSite reports whether a POST came from another site. Browsers say so
// in Sec-Fetch-Site, which also covers sandboxed frames and data: pages.
// Origin alone can't tell: with SSOBench's Referrer-Policy no-referrer,
// browsers send "Origin: null" for SSOBench's own forms too.
func crossSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "cross-site", "same-site":
		return true
	case "same-origin", "none":
		return false
	}
	// Older browsers: compare Origin when it names a site.
	o := r.Header.Get("Origin")
	if o == "" || o == "null" {
		return false
	}
	u, err := url.Parse(o)
	return err != nil || u.Host != r.Host
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostport, "[]")
}

// hostAllowed accepts IP addresses (DNS rebinding needs a name), localhost,
// and the names in AllowedHosts. An empty AllowedHosts accepts any name.
func (s *Server) hostAllowed(hostport string) bool {
	if len(s.AllowedHosts) == 0 {
		return true
	}
	h := strings.TrimSuffix(strings.ToLower(hostOnly(hostport)), ".")
	if net.ParseIP(h) != nil || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	return slices.Contains(s.AllowedHosts, h)
}

// AppView is a copy of an app for a template, with its latest result.
type AppView struct {
	*App
	Last  *Result
	Count int
}

// appForm holds submitted app settings, for redisplay after an error.
type appForm struct {
	Name, Protocol           string
	MetadataURL, MetadataXML string
	ForceAuthn               bool
	Issuer, ClientID, Scopes string
	ExtraParams              string
}

type page struct {
	Version        string // for the footer
	Persisting     bool   // apps are kept in a state file
	Guarded        bool   // the console asks for sign-in: show Sign out
	Access         *AccessView
	Nav            string
	Error          string
	Notice         string
	Apps           []AppView
	App            *AppView
	Form           appForm
	SetupOpen      bool
	SP             saml.SP
	Redirect       string
	SignInURL      string
	ByIP           bool // the page was opened by IP address
	Results        []*Result
	Result         *Result
	Flows          []Flow
	Decoded        *decode.Result
	Input          string
	PostForm       *postForm
	Plain          bool // render the POST hand-off in the plain, end-user layout
	Errs           map[string]FieldError
	SettingsOpen   bool
	SetupHighlight bool   // open Set up: new values were just added there
	Query          string // History search
	SignedOut      *SignedOut
	// Optional URLs shown under Set up at your identity provider.
	SLOURL, PostLogoutURL, LoginURL, DeepLinkURL, BackchannelURL string
	Tab                                                          string   // app pages: overview, setup, users or settings
	Current                                                      *Session // sign-in page: this browser\'s active session
	Active                                                       []SessionView
	EndedList                                                    []SessionView
	Lifetime                                                     int
	Rules                                                        []AccessRule
	FilterApp, FilterStatus                                      string
	RuleTest                                                     *RuleTest
	LifetimeChoices, IdleChoices                                 []int
	View                                                         string // Users: accounts, groups or provisioning
	Groups                                                       []GroupView
	Tests                                                        []TestView // OAuth: the other tests, with their last results
	TokenMask                                                    string
	ConfirmToken                                                 bool
	// User directory: copies taken under the lock.
	Users              []User
	ProvLog            []ProvEvent
	SCIMURL            string
	UserErr, ImportErr string
}

// appNotices confirm what an app page action did, by its done= value.
var appNotices = map[string]string{
	"created":      "App created. Register it at your identity provider with the values below.",
	"connected":    "Connected. Test sign-in to see what your identity provider sends.",
	"saved":        "Settings saved.",
	"secret":       "Client secret saved.",
	"ended":        "Session ended. The next time that browser opens the app, it is asked to sign in.",
	"user-added":   "User added.",
	"user-deleted": "User deleted.",
	"directory":    "User directory turned on. Add accounts, or give your identity provider the SCIM values under Set up.",
	"token":        "New SCIM token generated. Give it to your identity provider; the old one no longer works.",
	"rule":         "Rule added.",
}

// postForm auto-submits a SAML message with the HTTP-POST binding.
type postForm struct {
	Action, Field, Value, RelayState string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Version, p.Persisting, p.Guarded = s.Version, s.StatePath != "", s.protected()
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		p.ByIP = net.ParseIP(h) != nil && s.BaseURL == ""
	} else {
		p.ByIP = net.ParseIP(r.Host) != nil && s.BaseURL == ""
	}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, name, p); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "internal error rendering the page; see the terminal output", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// logf writes an operational message to the terminal.
func (s *Server) logf(format string, args ...any) {
	if !s.Quiet {
		// Names and paths can come from an identity provider: keep each
		// entry on one line.
		log.Print(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(fmt.Sprintf(format, args...)))
	}
}

// views snapshots the apps with their latest results.
func (s *Server) views() []AppView {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []AppView
	for _, a := range s.apps {
		out = append(out, s.viewLocked(a))
	}
	return out
}

func (s *Server) view(id string) *AppView {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if a.ID == id {
			v := s.viewLocked(a)
			return &v
		}
	}
	return nil
}

// viewLocked is a's snapshot for pages, with its latest result.
func (s *Server) viewLocked(a *App) AppView {
	v := AppView{App: snapshotApp(a)}
	for _, r := range s.results {
		if r.AppID == a.ID {
			if v.Last == nil {
				v.Last = snapshotResult(r)
			}
			v.Count++
		}
	}
	return v
}

func (s *Server) resultsFor(appID string, n int) []*Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Result
	for _, r := range s.results {
		if (appID == "" || r.AppID == appID) && (n == 0 || len(out) < n) {
			out = append(out, snapshotResult(r))
		}
	}
	return out
}

// ---- Apps ----

func (s *Server) toApps(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) appsPage(w http.ResponseWriter, r *http.Request) {
	p := page{Nav: "apps", Apps: s.views()}
	if name := r.URL.Query().Get("deleted"); name != "" {
		p.Notice = "Deleted " + name + "."
	}
	s.render(w, r, http.StatusOK, "apps.html", p)
}

func (s *Server) appNewPage(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Query().Get("protocol")
	if proto != ProtoSAML && proto != ProtoOIDC && proto != ProtoOAuth {
		proto = "" // ask first; no protocol is the default
	}
	s.render(w, r, http.StatusOK, "app_new.html", page{Nav: "apps", Form: appForm{Protocol: proto, Scopes: defaultScopes}})
}

func readAppForm(r *http.Request) appForm {
	return appForm{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Protocol:    r.FormValue("protocol"),
		MetadataURL: strings.TrimSpace(r.FormValue("metadata_url")),
		MetadataXML: strings.TrimSpace(r.FormValue("metadata_xml")),
		ForceAuthn:  r.FormValue("force_authn") != "",
		Issuer:      strings.TrimSpace(r.FormValue("issuer")),
		ClientID:    strings.TrimSpace(r.FormValue("client_id")),
		Scopes:      strings.TrimSpace(r.FormValue("scopes")),
		ExtraParams: strings.TrimSpace(r.FormValue("extra")),
	}
}

// FieldError is a problem with one form field, in plain words, with the
// raw error kept for a Technical details disclosure.
type FieldError struct{ Msg, Detail string }

// friendlyLoadError explains a failure to load IdP metadata or discovery.
func friendlyLoadError(rawURL string, err error) FieldError {
	raw := err.Error()
	host := hostOf(rawURL)
	fe := FieldError{Detail: raw}
	switch {
	case strings.Contains(raw, "no such host"):
		fe.Msg = "Couldn't find " + host + ". Check the URL."
	case strings.Contains(raw, "connection refused"), strings.Contains(raw, "i/o timeout"), strings.Contains(raw, "deadline exceeded"), strings.Contains(raw, "network is unreachable"):
		fe.Msg = "Couldn't connect to " + host + ". Check that it can be reached from the computer running SSOBench."
	case strings.Contains(raw, "x509:"), strings.Contains(raw, "certificate"):
		fe.Msg = "The certificate of " + host + " isn't trusted by the computer running SSOBench."
	case strings.Contains(raw, "HTTP 404"):
		fe.Msg = "Nothing was found at that URL (HTTP 404)."
	case strings.Contains(raw, "HTTP "):
		fe.Msg = "The server answered with an error (" + raw[strings.Index(raw, "HTTP "):min(len(raw), strings.Index(raw, "HTTP ")+8)] + ")."
	case strings.Contains(raw, "not valid XML"), strings.Contains(raw, "no EntityDescriptor"), strings.Contains(raw, "IDPSSODescriptor"):
		fe.Msg = "That isn't identity provider metadata. " + capitalize(strings.TrimPrefix(strings.TrimPrefix(raw, "IdP metadata: "), "metadata ")) + "."
	case strings.Contains(raw, "discovery document"):
		fe.Msg = "That URL doesn't serve a valid OpenID Connect discovery document."
	default:
		fe.Msg = capitalize(raw) + "."
	}
	return fe
}

// clientAddr is where a request came from, for the log.
func clientAddr(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (s *Server) appCreate(w http.ResponseWriter, r *http.Request) {
	form := readAppForm(r)
	errs := map[string]FieldError{}
	fail := func() {
		s.render(w, r, http.StatusBadRequest, "app_new.html", page{Nav: "apps", Form: form, Errs: errs})
	}
	app := &App{AppConfig: AppConfig{Name: form.Name, Protocol: form.Protocol, Created: time.Now()}}
	f := s.newFlow(strings.ToUpper(form.Protocol), nameOr(form.Name, "new app")+" (new app)")
	switch form.Protocol {
	case ProtoSAML:
		// The IdP can be connected now or later: most IdPs want SSOBench's
		// URLs first, and those only exist once the app does.
		app.MetadataURL, app.ForceAuthn = form.MetadataURL, form.ForceAuthn
		if form.MetadataURL == "" {
			app.MetadataXML = form.MetadataXML
		}
		if app.MetadataURL != "" || app.MetadataXML != "" {
			if _, err := s.loadIdP(r.Context(), f, app); err != nil {
				s.finish(f, "", "app not created")
				field, fe := metadataFieldError(app.MetadataURL, err)
				errs[field] = fe
				fail()
				return
			}
		}
		if app.Name == "" {
			app.Name = "SAML app"
			if app.idp != nil {
				app.Name = hostOf(app.idp.EntityID)
			}
		}
	case ProtoOIDC, ProtoOAuth:
		app.Issuer, app.ClientID, app.ClientSecret = form.Issuer, form.ClientID, r.FormValue("client_secret")
		app.Scopes, app.ExtraParams = nameOr(form.Scopes, defaultScopes), form.ExtraParams
		app.KeepSecret = s.StatePath != "" && r.FormValue("keep_secret") != ""
		if form.Issuer != "" {
			p, err := s.discover(r.Context(), f, app, form.Issuer)
			if err != nil {
				s.finish(f, "", "app not created")
				errs["issuer"] = issuerFieldError(form.Issuer, err)
				fail()
				return
			}
			app.provider, app.providerAt = p, time.Now()
		}
		if form.Protocol == ProtoOAuth {
			app.Resource = strings.TrimSpace(r.FormValue("resource"))
			app.MachineScopes = strings.TrimSpace(r.FormValue("machine_scopes"))
		}
		if app.Name == "" && form.Protocol == ProtoOAuth {
			app.Name = "OAuth app"
			if form.Issuer != "" {
				app.Name = hostOf(form.Issuer)
			}
		}
		if app.Name == "" {
			app.Name = "OpenID Connect app"
			if form.Issuer != "" {
				app.Name = hostOf(form.Issuer)
			}
		}
	default:
		s.finish(f, "", "app not created")
		errs["protocol"] = FieldError{Msg: "Choose SAML, OpenID Connect or OAuth 2.1."}
		fail()
		return
	}
	s.mu.Lock()
	app.ID = newAppID(func(id string) bool {
		for _, a := range s.apps {
			if a.ID == id {
				return true
			}
		}
		return false
	})
	s.apps = append(s.apps, app)
	s.mu.Unlock()
	s.saveState()
	s.event(f, LInfo, "App", 0, "", "Created app %q (%s) from %s", s.appName(app), app.ID, clientAddr(r))
	s.finish(f, "", "app created")
	http.Redirect(w, r, "/apps/"+app.ID+"?done=created", http.StatusSeeOther)
}

func (s *Server) appPage(w http.ResponseWriter, r *http.Request) {
	s.renderApp(w, r, http.StatusOK, r.PathValue("id"), page{Tab: "overview"})
}

func (s *Server) appTab(w http.ResponseWriter, r *http.Request, tab string) {
	s.renderApp(w, r, http.StatusOK, r.PathValue("id"), page{Tab: tab})
}

var tabPages = map[string]string{"overview": "app.html", "setup": "app_setup.html", "users": "app_users.html", "sessions": "app_sessions.html", "settings": "app_settings.html"}

// GroupView is a SCIM group with its members' usernames.
type GroupView struct {
	Name    string
	Members []string
}

// TestView is one of an OAuth app's other tests on its Overview.
type TestView struct {
	Name, About, Path string
	NeedsSecret       bool
	Last              *Result
}

func (s *Server) renderApp(w http.ResponseWriter, r *http.Request, status int, id string, p page) {
	v := s.view(id)
	if v == nil {
		s.render(w, r, http.StatusNotFound, "apps.html", page{Nav: "apps", Apps: s.views(), Error: "That app does not exist. It may have been deleted."})
		return
	}
	if p.Tab == "" {
		p.Tab = "overview"
	}
	if !v.Connected() && p.Tab != "users" && p.Tab != "settings" {
		p.Tab = "overview" // the setup steps
	}
	p.Nav, p.App = "apps", v
	p.Results = s.resultsFor(id, 5)
	q := r.URL.Query()
	p.Notice = appNotices[q.Get("done")]
	switch q.Get("done") {
	case "saved":
		if added := q.Get("added"); added != "" {
			p.Notice = "Settings saved. Register the new values below: " + added + "."
		}
	case "imported":
		p.Notice = "Imported " + q.Get("n") + "."
	}
	p.SignInURL = s.base(r) + "/a/" + v.ID
	if v.Logout {
		if v.IsSAML() {
			p.SLOURL = s.sloURL(r, v.App)
		} else {
			p.PostLogoutURL = s.postLogoutURL(r, v.App)
		}
	}
	if v.LoginURL {
		p.LoginURL = s.loginURL(r, v.App)
	}
	if v.RelayStateOn {
		p.DeepLinkURL = s.deepLinkURL(r, v.App)
	}
	if v.IsSAML() {
		p.SP = s.spFor(r, v.App)
		// spFor may have just made the app's keys; show them.
		if live := s.app(v.ID); live != nil {
			s.mu.Lock()
			v.App.signer, v.App.encKey = live.signer, live.encKey
			s.mu.Unlock()
		}
	} else {
		p.Redirect = s.redirectFor(r, v.App)
	}
	if v.Directory {
		s.mu.Lock()
		query := strings.ToLower(strings.TrimSpace(q.Get("q")))
		for _, u := range v.App.Users {
			if query == "" || strings.Contains(strings.ToLower(u.UserName+" "+u.Name()+" "+strings.Join(u.Emails, " ")), query) {
				p.Users = append(p.Users, *u)
			}
		}
		for _, g := range v.App.Groups {
			gv := GroupView{Name: g.Name}
			for _, m := range g.Members {
				if u := userByID(v.App.Users, m); u != nil {
					gv.Members = append(gv.Members, u.UserName)
				}
			}
			p.Groups = append(p.Groups, gv)
		}
		p.ProvLog = append([]ProvEvent(nil), v.App.ProvLog...)
		if t := v.App.SCIMToken; len(t) > 4 {
			p.TokenMask = strings.Repeat("•", 12) + t[len(t)-4:]
		}
		s.mu.Unlock()
		p.Query = q.Get("q")
		p.SCIMURL = s.scimURL(r, v.App)
		p.ConfirmToken = q.Get("rotate") == "1"
	}
	if p.View == "" {
		p.View = q.Get("view")
	}
	switch p.View {
	case "groups", "provisioning", "access":
	default:
		p.View = "accounts"
	}
	if p.View == "access" {
		s.mu.Lock()
		p.Rules = append([]AccessRule(nil), v.App.AccessRules...)
		s.mu.Unlock()
		for _, res := range s.resultsFor(v.ID, 0) {
			if res.IsSignIn() && res.Mode == "" && res.IdentityCount() > 0 {
				s.mu.Lock()
				p.RuleTest = &RuleTest{Result: res, Decision: decide(v.App, res)}
				s.mu.Unlock()
				break
			}
		}
	}
	if v.IsOAuth() {
		p.Tests = s.oauthTests(v.ID)
	}
	if p.Tab == "sessions" {
		p.Active, p.EndedList = s.sessionViews(s.app(v.ID))
	}
	p.Lifetime = int(v.App.lifetime() / time.Minute)
	p.LifetimeChoices, p.IdleChoices = lifetimeChoices, idleChoices
	if v.Logout && !v.IsSAML() && !v.IsOAuth() {
		p.BackchannelURL = s.backchannelURL(r, v.App)
	}
	if p.Form.Protocol == "" {
		p.Form = appForm{Name: v.Name, Protocol: v.Protocol, MetadataURL: v.MetadataURL, MetadataXML: v.MetadataXML,
			ForceAuthn: v.ForceAuthn, Issuer: v.Issuer, ClientID: v.ClientID, Scopes: v.Scopes, ExtraParams: v.ExtraParams}
	}
	s.render(w, r, status, tabPages[p.Tab], p)
}

// oauthTests lists an OAuth app's other tests with the last result of each.
func (s *Server) oauthTests(appID string) []TestView {
	tests := []TestView{
		{Name: "Machine token", About: "Gets a token with the client credentials grant.", Path: "/machine", NeedsSecret: true},
		{Name: "OAuth 2.1 conformance", About: "Probes OAuth 2.1 rules without signing in.", Path: "/conformance"},
		{Name: "Sign-in without PKCE", About: "Asks for a code with no code challenge. The server should refuse.", Path: "/check/" + ModeNoPKCE, NeedsSecret: true},
		{Name: "Wrong PKCE verifier", About: "Redeems a code with a verifier that doesn't match. The server must refuse.", Path: "/check/" + ModeWrongVerifier, NeedsSecret: true},
	}
	for _, res := range s.resultsFor(appID, 0) {
		for i := range tests {
			if tests[i].Last == nil && res.RerunPath() == tests[i].Path {
				tests[i].Last = res
			}
		}
	}
	return tests
}

// appError shows msg on the app's page.
func (s *Server) appError(w http.ResponseWriter, r *http.Request, app *App, msg string) {
	s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Error: capitalize(msg)})
}

func (s *Server) appUpdate(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	patch := parseSettings(r)
	patch.Protocol = app.Protocol
	s.mu.Lock()
	wasConnected := app.Connected()
	mdChanged := patch.MetadataURL != app.MetadataURL || (patch.MetadataURL == "" && patch.MetadataXML != app.MetadataXML)
	issuerChanged := patch.Issuer != app.Issuer
	s.mu.Unlock()
	fail := func(field string, fe FieldError) {
		tab := "settings"
		if !wasConnected {
			tab = "overview"
		}
		s.renderApp(w, r, http.StatusBadRequest, app.ID, page{Form: patch.appForm, Errs: map[string]FieldError{field: fe}, Tab: tab})
	}
	for field, fe := range patch.Errs {
		fail(field, fe)
		return
	}
	f := s.newFlow(app.ProtocolKind(), s.appName(app)+" (settings)")

	// The identity provider connection first: it needs the network, and
	// a failure leaves the app as it was.
	var trial *App
	var provider *oidc.Provider
	_, mdSent := r.Form["metadata_url"]
	clearMetadata := app.IsSAML() && mdSent && mdChanged && patch.MetadataURL == "" && patch.MetadataXML == ""
	switch {
	case app.IsSAML() && mdChanged && (patch.MetadataURL != "" || patch.MetadataXML != ""):
		trial = &App{AppConfig: AppConfig{Name: s.appName(app), Protocol: app.Protocol, MetadataURL: patch.MetadataURL}}
		if patch.MetadataURL == "" {
			trial.MetadataXML = patch.MetadataXML
		}
		if _, err := s.loadIdP(r.Context(), f, trial); err != nil {
			s.finish(f, "", "settings not saved")
			fail(metadataFieldError(patch.MetadataURL, err))
			return
		}
	case !app.IsSAML() && issuerChanged && patch.Issuer != "":
		var err error
		if provider, err = s.discover(r.Context(), f, app, patch.Issuer); err != nil {
			s.finish(f, "", "settings not saved")
			fail("issuer", issuerFieldError(patch.Issuer, err))
			return
		}
	}

	var added []string
	var connected bool
	s.locked(func() {
		switch {
		case trial != nil:
			app.MetadataURL, app.MetadataXML = trial.MetadataURL, trial.MetadataXML
			app.idp, app.idpRaw, app.idpLoadedAt = trial.idp, trial.idpRaw, trial.idpLoadedAt
		case clearMetadata: // both emptied in Settings: back to the setup steps
			app.MetadataURL, app.MetadataXML = "", ""
			app.idp, app.idpRaw, app.idpLoadedAt = nil, nil, time.Time{}
		case provider != nil:
			app.provider, app.providerAt = provider, time.Now()
		case !app.IsSAML() && patch.Issuer == "":
			app.provider, app.providerAt = nil, time.Time{}
		}
		added = patch.apply(app, s.StatePath != "")
		connected = app.Connected()
	})
	if clearMetadata {
		s.event(f, LInfo, "Metadata", 0, "", "Metadata removed; the app is no longer connected")
	}
	s.saveState()
	s.event(f, LInfo, "App", 0, "", "Saved the settings of %q from %s", s.appName(app), clientAddr(r))
	s.finish(f, "", "settings saved")
	target := "/apps/" + app.ID + "/settings?done=saved"
	switch {
	case !wasConnected && connected:
		target = "/apps/" + app.ID + "?done=connected"
	case !connected:
		target = "/apps/" + app.ID
	case len(added) > 0:
		target = "/apps/" + app.ID + "/setup?done=saved&added=" + url.QueryEscape(strings.Join(added, ", "))
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) appSignIn(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	s.signIn(w, r, app, ViaConsole)
}

func (s *Server) signIn(w http.ResponseWriter, r *http.Request, app *App, via string) {
	s.mu.Lock()
	connected := app.Connected()
	s.mu.Unlock()
	if !connected {
		if via == ViaPage {
			s.render(w, r, http.StatusConflict, "signin.html", page{App: s.view(app.ID), Error: "This app isn't set up for sign-in yet. If you were sent here to sign in, tell your administrator."})
			return
		}
		what := "the identity provider's metadata"
		if !app.IsSAML() {
			what = "the issuer URL and client ID"
		}
		s.appError(w, r, app, "Add "+what+" under Connect your identity provider to test sign-in.")
		return
	}
	switch {
	case app.IsSAML():
		s.samlSignIn(w, r, app, via)
	case app.IsOAuth():
		s.oauthSignIn(w, r, app, via, ModeNormal)
	default:
		s.oidcSignIn(w, r, app, via)
	}
}

// landing is where the browser goes once a sign-in has a result: the
// app's welcome screen for people signing in, diagnostics otherwise.
func (s *Server) landing(res *Result, app *App) string {
	if app != nil {
		s.mu.Lock()
		profile := res.Via == ViaPage || (res.Via == ViaIdP && app.LandsOnProfile())
		s.mu.Unlock()
		if profile && s.app(app.ID) != nil {
			return "/a/" + app.ID + "/welcome/" + res.ID
		}
	}
	return "/result/" + res.ID
}

// ---- Sign-in page and welcome screen ----

func (s *Server) signinPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r.PathValue("id"))
	if v == nil {
		http.NotFound(w, r)
		return
	}
	p := page{App: v}
	if !v.Connected() {
		p.Error = "This app isn't set up for sign-in yet. If you were sent here to sign in, tell your administrator."
	}
	if x := s.browserSession(r, s.app(v.ID)); x != nil {
		if x.Active() {
			s.mu.Lock()
			x.LastSeen = time.Now()
			cp := *x
			s.mu.Unlock()
			p.Current = &cp
		} else {
			p.Notice = "Your session ended because " + x.EndedHow + ". Sign in again to continue."
			s.clearSessionCookie(w, r, v.App)
		}
	}
	s.render(w, r, http.StatusOK, "signin.html", p)
}

func (s *Server) signinStart(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil {
		http.NotFound(w, r)
		return
	}
	s.signIn(w, r, app, ViaPage)
}

func (s *Server) welcomePage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r.PathValue("id"))
	res := s.findResult(r.PathValue("rid"))
	if v == nil || res == nil || res.AppID != v.ID {
		http.Redirect(w, r, "/a/"+r.PathValue("id"), http.StatusSeeOther)
		return
	}
	if res.SessionID != "" {
		// The welcome screen belongs to the browser that signed in: the
		// first to open it takes the session's cookie.
		var held string
		if c, err := r.Cookie(sessionCookie(v.ID)); err == nil {
			held = c.Value
		}
		now := time.Now()
		live := s.app(v.ID) // the view is a snapshot; the session is changed on the app itself
		s.mu.Lock()
		var x *Session
		for _, y := range live.Sessions {
			if y.ID == res.SessionID {
				x = y
			}
		}
		claim, other := false, false
		if x != nil {
			checkSessionLocked(live, x, now)
			switch {
			case held == x.ID:
			case !x.Claimed:
				x.Claimed, claim = true, true
			default:
				other = true
			}
			if x.Active() && !other {
				x.LastSeen = now
			}
		}
		s.mu.Unlock()
		switch {
		case x == nil:
		case other:
			http.Redirect(w, r, "/a/"+v.ID, http.StatusSeeOther)
			return
		case !x.Active():
			s.clearSessionCookie(w, r, v.App)
			http.Redirect(w, r, "/a/"+v.ID+"/signed-out?session="+x.ID, http.StatusSeeOther)
			return
		case claim:
			s.setSessionCookie(w, r, v.App, x.ID)
		}
	}
	s.mu.Lock()
	ended := res.Ended
	s.mu.Unlock()
	if ended {
		s.render(w, r, http.StatusOK, "signedout.html", page{App: v, SignedOut: &SignedOut{Local: true, Reason: "This session has ended."}})
		return
	}
	s.render(w, r, http.StatusOK, "welcome.html", page{App: v, Result: res})
}

// appDeleteConfirm asks before deleting: the app's URLs are registered at
// an identity provider and stop working at once.
func (s *Server) appDeleteConfirm(w http.ResponseWriter, r *http.Request) {
	v := s.view(r.PathValue("id"))
	if v == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, http.StatusOK, "app_delete.html", page{Nav: "apps", App: v})
}

func (s *Server) appDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.FormValue("confirm") != "1" {
		http.Redirect(w, r, "/apps/"+id+"/delete", http.StatusSeeOther)
		return
	}
	s.mu.Lock()
	var name string
	s.apps = slices.DeleteFunc(s.apps, func(a *App) bool {
		if a.ID == id {
			name = a.Name
			return true
		}
		return false
	})
	s.mu.Unlock()
	if name == "" {
		http.NotFound(w, r)
		return
	}
	s.saveState()
	f := s.newFlow("App", name+" (deleted)")
	s.event(f, LInfo, "App", 0, "", "Deleted app %q (%s) from %s; its results stay in Activity", name, id, clientAddr(r))
	s.finish(f, "", "app deleted")
	http.Redirect(w, r, "/?deleted="+url.QueryEscape(name), http.StatusSeeOther)
}

// ---- Results ----

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	q := strings.TrimSpace(qv.Get("q"))
	if q == "" {
		q = strings.TrimSpace(qv.Get("ref")) // older links
	}
	p := page{Nav: "history", Apps: s.views(), Query: q, FilterApp: qv.Get("app"), FilterStatus: qv.Get("status")}
	// A reference goes straight to its result.
	if q != "" && len(normalizeRef(q)) == 12 {
		if res := s.findResult(q); res != nil {
			http.Redirect(w, r, "/result/"+res.ID, http.StatusSeeOther)
			return
		}
	}
	needle := strings.ToLower(q)
	for _, res := range s.resultsFor("", 0) {
		switch {
		case p.FilterApp != "" && res.AppID != p.FilterApp:
		case p.FilterStatus != "" && res.Status() != p.FilterStatus:
		case needle != "" && !strings.Contains(strings.ToLower(res.RowTitle()+" "+res.AppName+" "+res.Summary()+" "+res.ID), needle):
		default:
			p.Results = append(p.Results, res)
		}
	}
	s.render(w, r, http.StatusOK, "history.html", p)
}

// save stores res with problems first, links it to its flow, and logs the
// outcome.
func (s *Server) save(res *Result, f *Flow) {
	res.ID = newRef()
	res.Time = time.Now()
	if app := s.app(res.AppID); app != nil && !res.Machine && !res.Conformance {
		s.expectCheck(app, res)
		changed := s.accountCheck(app, res)
		if res.AccountProblem == "" {
			s.accessCheck(app, res)
		}
		if res.AccountProblem == "" && res.AccessProblem == "" {
			s.startSession(app, res)
			changed = changed || res.SessionID != ""
		}
		if changed {
			s.saveState()
		}
	}
	rank := map[check.Status]int{check.Fail: 0, check.Warn: 1}
	slices.SortStableFunc(res.Checks, func(a, b check.Result) int {
		ra, ok := rank[a.Status]
		if !ok {
			ra = 2
		}
		rb, ok := rank[b.Status]
		if !ok {
			rb = 2
		}
		return ra - rb
	})
	// The same fix twice in a row reads as noise.
	seenFix := map[string]bool{}
	for i, c := range res.Checks {
		if c.Fix != "" && (c.Status == check.Fail || c.Status == check.Warn) {
			if seenFix[c.Fix] {
				res.Checks[i].Fix = "Same fix as above."
			}
			seenFix[c.Fix] = true
		}
	}
	markRows(res)
	if s.onSave != nil {
		s.onSave(res)
	}
	outcome := res.Summary()
	lvl := LInfo
	switch res.Status() {
	case "fail":
		lvl = LError
	case "warn":
		lvl = LWarn
	}
	var detail strings.Builder
	for _, r := range res.Checks {
		if r.Status == check.Fail || r.Status == check.Warn {
			fmt.Fprintf(&detail, "%s  %s: %s\n", strings.ToUpper(string(r.Status)), r.Name, r.Detail)
		}
	}
	if f != nil {
		res.FlowID = f.ID
		res.Duration = time.Since(f.Started)
		s.event(f, lvl, "Result", 0, detail.String(), "%s", outcome)
		s.closeFlow(f, res.ID, outcome) // saved with the result, below
	}
	s.mu.Lock()
	s.results = append([]*Result{res}, s.results...)
	if len(s.results) > maxResults {
		s.results = s.results[:maxResults]
	}
	s.mu.Unlock()
	s.saveHistory()
}

// findResult returns a snapshot of a saved result: what is stored may
// still change (a session ending marks it), so readers get a copy.
func (s *Server) findResult(id string) *Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.findResultLocked(id); r != nil {
		return snapshotResult(r)
	}
	return nil
}

func (s *Server) findResultLocked(id string) *Result {
	n := normalizeRef(id)
	for _, x := range s.results {
		if x.ID == id || x.ID == n {
			return x
		}
	}
	return nil
}

func (s *Server) result(w http.ResponseWriter, r *http.Request) {
	res := s.findResult(r.PathValue("id"))
	if res == nil {
		s.render(w, r, http.StatusNotFound, "history.html", page{Nav: "history", Results: s.resultsFor("", 0),
			Error: "That result is no longer available. Activity keeps the last 50 tests."})
		return
	}
	p := page{Nav: "history", Result: res, Flows: s.snapshot(func(f *Flow) bool { return f.ID == res.FlowID })}
	if p.App = s.view(res.AppID); p.App != nil {
		p.Nav = "apps"
	}
	switch r.URL.Query().Get("fixed") {
	case "added":
		p.Notice = "Account added. Test again to sign in with it."
	case "reactivated":
		p.Notice = "Account reactivated. Test again to sign in with it."
	case "expected":
		p.Notice = "Saved. Every sign-in to this app is now checked for these. Change the list in Settings."
	}
	s.render(w, r, http.StatusOK, "result.html", p)
}

func (s *Server) resultLogText(w http.ResponseWriter, r *http.Request) {
	res := s.findResult(r.PathValue("id"))
	if res == nil {
		http.NotFound(w, r)
		return
	}
	s.sendText(w, "ssobench-"+res.ID+".log", s.snapshot(func(f *Flow) bool { return f.ID == res.FlowID }))
}

func (s *Server) logPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "log.html", page{Nav: "log", Flows: s.snapshot(nil)})
}

func (s *Server) logText(w http.ResponseWriter, r *http.Request) {
	s.sendText(w, "ssobench.log", s.snapshot(nil))
}

func (s *Server) sendText(w http.ResponseWriter, filename string, flows []Flow) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	fmt.Fprint(w, Text(flows, s.Version))
}

// ---- Decode ----

func (s *Server) decodePage(w http.ResponseWriter, r *http.Request) {
	p := page{Nav: "decode"}
	if r.Method == http.MethodPost {
		p.Input = r.FormValue("input")
		d, err := decode.Auto(p.Input, time.Now())
		if err != nil {
			p.Error = err.Error()
		}
		p.Decoded = d
	}
	s.render(w, r, http.StatusOK, "decode.html", p)
}

func capitalize(msg string) string {
	if msg == "" {
		return msg
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}

func nameOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// secretSave sets the client secret from the Overview prompt.
func (s *Server) secretSave(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("id"))
	if app == nil || app.IsSAML() {
		http.NotFound(w, r)
		return
	}
	secret := r.FormValue("client_secret")
	s.mu.Lock()
	if secret != "" {
		app.ClientSecret, app.PublicClient = secret, false
	}
	if r.FormValue("public") == "1" {
		app.PublicClient = true
	}
	if r.FormValue("keep_secret") != "" && s.StatePath != "" {
		app.KeepSecret = true
	}
	s.mu.Unlock()
	s.saveState()
	s.logf("Client secret of %q set from %s", s.appName(app), clientAddr(r))
	http.Redirect(w, r, "/apps/"+app.ID+"?done=secret", http.StatusSeeOther)
}
