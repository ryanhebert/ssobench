package web

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
	"github.com/ryanhebert/ssobench/internal/saml"
)

const (
	ProtoSAML  = "saml"
	ProtoOIDC  = "oidc"
	ProtoOAuth = "oauth" // OAuth 2.1 (API access): access tokens, not identity
)

// App is one application registered at an identity provider, such as a
// SAML or OIDC application in the IdP's admin console. Each has its own
// SSOBench URLs, so the IdP can tell them apart and responses are checked
// against the right metadata.
type App struct {
	AppConfig
	// ClientSecret is held in memory only, unless KeepSecret.
	ClientSecret string

	// Runtime state, worked out again after a restart.
	signer       *saml.Signer // from SignKeyPEM
	encKey       *saml.Signer // from EncKeyPEM
	idp          *saml.IdP
	idpRaw       []byte
	idpLoadedAt  time.Time
	idpRefreshAt time.Time      // last reload for an unknown signing certificate
	provider     *oidc.Provider // last discovery, for the Identity provider section
	providerAt   time.Time
}

// AppConfig is an app's settings and data: everything the state file
// keeps. The JSON names are the state file format (version 2); renaming
// a Go field is safe, changing a tag is not.
type AppConfig struct {
	ID       string    `json:"id"` // random and permanent: part of the URLs registered at the IdP
	Name     string    `json:"name"`
	Protocol string    `json:"protocol"`
	Created  time.Time `json:"created"`
	// Legacy apps use the original single-app URLs (/saml/acs and so on),
	// so a registration made before apps existed keeps working.
	Legacy bool `json:"legacy,omitempty"`

	// SAML
	MetadataURL string `json:"metadata_url,omitempty"`
	MetadataXML string `json:"metadata_xml,omitempty"` // only when pasted
	ForceAuthn  bool   `json:"force_authn,omitempty"`
	// SignAuthn signs AuthnRequests. Logout messages are always signed.
	SignAuthn bool `json:"sign_authn,omitempty"`
	// The SP signing key and certificate (PEM), made at first use. The
	// state file is owner-only.
	SignKeyPEM  string `json:"sign_key,omitempty"`
	SignCertPEM string `json:"sign_cert,omitempty"`
	// Request options: the NameID format, a requested authentication
	// context (class refs, compared by AuthnComparison) and IsPassive.
	NameIDFormat    string   `json:"nameid_format,omitempty"`
	AuthnContext    []string `json:"authn_context,omitempty"`
	AuthnComparison string   `json:"authn_comparison,omitempty"`
	IsPassive       bool     `json:"is_passive,omitempty"`
	// EncryptAssertions publishes an encryption key and expects encrypted
	// assertions. The key (PEM) is made at first use.
	EncryptAssertions bool   `json:"encrypt_assertions,omitempty"`
	EncKeyPEM         string `json:"enc_key,omitempty"`
	EncCertPEM        string `json:"enc_cert,omitempty"`

	// OpenID Connect and OAuth 2.1; the secret is App.ClientSecret.
	Issuer      string `json:"issuer,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Scopes      string `json:"scopes,omitempty"`
	ExtraParams string `json:"extra_params,omitempty"`

	// IdPLanding is where IdP-initiated sign-ins land: LandProfile (the
	// default, as a tile is the end-user path) or LandDiagnostics.
	IdPLanding string `json:"idp_landing,omitempty"`

	// Optional features, all off until turned on in the app's settings.
	Logout       bool   `json:"logout,omitempty"`         // SAML single logout, or OIDC RP-initiated logout
	LoginURL     bool   `json:"login_url,omitempty"`      // a URL that starts a sign-in when opened (SP login / initiate login URI)
	IdPSLOURL    string `json:"idp_slo_url,omitempty"`    // SAML: the IdP single logout URL, used instead of the metadata one
	RelayStateOn bool   `json:"relay_state_on,omitempty"` // SAML: give a deep link as default relay state, and check for it

	// OAuth 2.1 apps
	Resource      string `json:"resource,omitempty"`       // the API (RFC 8707 resource) access tokens are for; empty to use the default
	MachineScopes string `json:"machine_scopes,omitempty"` // scopes requested with the client credentials grant
	// OpenID Connect: acr_values and login_hint sent with every sign-in.
	AcrValues string `json:"acr_values,omitempty"`
	LoginHint string `json:"login_hint,omitempty"`

	// KeepSecret saves the client secret in the state file (owner-only),
	// so it survives restarts. Off by default: secrets stay in memory.
	KeepSecret bool `json:"keep_secret,omitempty"`
	// PublicClient: the person said this client has no secret, so do
	// not ask for one.
	PublicClient bool `json:"public_client,omitempty"`

	// User directory: accounts the app keeps, matched at every sign-in.
	Directory bool   `json:"directory,omitempty"`
	MatchKey  string `json:"match_key,omitempty"`  // MatchNameID (default), MatchEmail, MatchUsername or MatchAttr
	MatchAttr string `json:"match_attr,omitempty"` // the attribute or claim name for MatchAttr
	JIT       bool   `json:"jit,omitempty"`        // create unknown accounts at first sign-in
	SCIMToken string `json:"scim_token,omitempty"` // bearer token for this app's SCIM endpoint
	// SCIMPublic is the address the identity provider uses to reach
	// SSOBench's SCIM endpoint, when it differs from the browser's: a
	// reverse proxy or another public name. Empty to use the browser's.
	SCIMPublic string      `json:"scim_public,omitempty"`
	Users      []*User     `json:"users,omitempty"`
	Groups     []*Group    `json:"groups,omitempty"`
	ProvLog    []ProvEvent `json:"provisioning,omitempty"` // SCIM requests, newest first

	// Sessions opened by people signing in, and how long they last.
	Sessions       []*Session `json:"sessions,omitempty"`
	SessionMinutes int        `json:"session_minutes,omitempty"` // maximum lifetime; 0 = the default
	IdleMinutes    int        `json:"idle_minutes,omitempty"`    // idle timeout; 0 = none

	// Access rules: roles, and who may sign in at all.
	AccessRules []AccessRule   `json:"access_rules,omitempty"`
	Expected    []ExpectedAttr `json:"expected,omitempty"` // attributes or claims the application needs
}

// OIDCConfig is the app's OpenID Connect or OAuth 2.1 client settings.
func (a *App) OIDCConfig() oidc.Config {
	return oidc.Config{Issuer: a.Issuer, ClientID: a.ClientID, ClientSecret: a.ClientSecret, Scopes: a.Scopes, ExtraParams: a.ExtraParams}
}

// LandsOnProfile reports whether IdP-initiated sign-ins show the profile.
func (a *App) LandsOnProfile() bool { return a.IdPLanding != LandDiagnostics }

func (a *App) IsSAML() bool { return a.Protocol == ProtoSAML }

// ProtocolKind is the short protocol name used in the log.
func (a *App) ProtocolKind() string {
	switch {
	case a.IsSAML():
		return "SAML"
	case a.IsOAuth():
		return "OAUTH"
	}
	return "OIDC"
}

func (a *App) IsOAuth() bool { return a.Protocol == ProtoOAuth }

func (a *App) ProtocolName() string {
	switch {
	case a.IsSAML():
		return "SAML"
	case a.IsOAuth():
		return "OAuth 2.1"
	}
	return "OpenID Connect"
}

// IdP is the loaded SAML metadata, nil until loaded.
func (a *App) IdP() *saml.IdP           { return a.idp }
func (a *App) IdPLoadedAt() time.Time   { return a.idpLoadedAt }
func (a *App) Signer() *saml.Signer     { return a.signer }
func (a *App) EncKey() *saml.Signer     { return a.encKey }
func (a *App) HasSecret() bool          { return a.ClientSecret != "" }
func (a *App) Provider() *oidc.Provider { return a.provider }
func (a *App) ProviderAt() time.Time    { return a.providerAt }

// Connected reports whether the app knows its identity provider well enough
// to start a sign-in.
func (a *App) Connected() bool {
	if a.IsSAML() {
		return a.idp != nil || a.MetadataURL != ""
	}
	return a.Issuer != "" && a.ClientID != ""
}

// IdPLabel names the identity provider side of the app in one line.
func (a *App) IdPLabel() string {
	switch {
	case a.IsSAML() && a.idp != nil:
		return hostOf(a.idp.EntityID)
	case a.IsSAML() && a.MetadataURL != "":
		return hostOf(a.MetadataURL)
	case a.IsSAML() && a.MetadataXML != "":
		return "pasted metadata"
	case !a.IsSAML() && a.Issuer != "":
		return hostOf(a.Issuer)
	}
	return ""
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

// newAppID returns a random ID for a new app, unique among taken. It is
// unrelated to the app's name: the name can change, the ID cannot, because
// it is part of the URLs registered at the identity provider.
func newAppID(taken func(string) bool) string {
	for {
		b := make([]byte, 10)
		rand.Read(b)
		id := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
		if !taken(id) {
			return id
		}
	}
}

// ---- persistence ----

type savedApp struct {
	AppConfig
	LoadedXML    string    `json:"loaded_metadata,omitempty"` // last loaded, for offline restarts
	LoadedAt     time.Time `json:"loaded_at,omitempty"`
	ClientSecret string    `json:"client_secret,omitempty"` // only when KeepSecret
}

// stateVersion is the state file format this version writes.
const stateVersion = 2

type stateFile struct {
	Version int        `json:"version"`
	Apps    []savedApp `json:"apps"`
	// Console sign-in: a password hash and passkeys (public keys only).
	Console *ConsoleAccess `json:"console,omitempty"`

	// Version 1 (single SAML and OIDC configuration), read for migration.
	SAML *struct {
		MetadataURL string    `json:"metadata_url"`
		MetadataXML string    `json:"metadata_xml"`
		Pasted      bool      `json:"pasted"`
		ForceAuthn  bool      `json:"force_authn"`
		LoadedAt    time.Time `json:"loaded_at"`
	} `json:"saml,omitempty"`
	OIDC *struct {
		Issuer      string `json:"issuer"`
		ClientID    string `json:"client_id"`
		Scopes      string `json:"scopes"`
		ExtraParams string `json:"extra_params"`
	} `json:"oidc,omitempty"`
}

// LoadState reads the apps from the state file. A missing file is not an
// error. A version 1 file becomes legacy apps on the original URLs.
func (s *Server) LoadState() error {
	if s.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("%s: %w", s.StatePath, err)
	}
	if st.Version > stateVersion {
		// Saving would drop what this version doesn't know: don't.
		path := s.StatePath
		s.StatePath = ""
		return fmt.Errorf("%s is from a newer SSOBench (version %d); not loading it, and not saving changes this session", path, st.Version)
	}
	if st.Version < 2 {
		st.Apps = migrateV1(st)
	}
	var apps []*App
	var problems []string
	for _, sa := range st.Apps {
		a := &App{AppConfig: sa.AppConfig}
		if a.Scopes == "" {
			a.Scopes = defaultScopes
		}
		if sa.KeepSecret {
			a.ClientSecret = sa.ClientSecret
		}
		if sa.LoadedXML != "" {
			idp, err := saml.ParseMetadata([]byte(sa.LoadedXML))
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: saved metadata: %v", sa.Name, err))
			} else {
				a.idp, a.idpRaw, a.idpLoadedAt = idp, []byte(sa.LoadedXML), sa.LoadedAt
			}
		}
		apps = append(apps, a)
	}
	s.mu.Lock()
	s.apps = apps
	if st.Console != nil {
		s.access = *st.Console
	}
	s.mu.Unlock()
	if st.Version < 2 && len(apps) > 0 {
		s.saveState()
	}
	if len(problems) > 0 {
		// The apps loaded; only some saved metadata didn't. It is fetched
		// again at the next sign-in.
		s.logf("warning: loaded %d %s, but %s", len(apps), plural(len(apps), "app", "apps"), strings.Join(problems, "; "))
	}
	return nil
}

func migrateV1(st stateFile) []savedApp {
	var out []savedApp
	now := time.Now()
	if v := st.SAML; v != nil && (v.MetadataURL != "" || v.MetadataXML != "") {
		sa := savedApp{AppConfig: AppConfig{ID: "default", Name: "SAML app", Protocol: ProtoSAML, Created: now, Legacy: true,
			MetadataURL: v.MetadataURL, ForceAuthn: v.ForceAuthn}, LoadedXML: v.MetadataXML, LoadedAt: v.LoadedAt}
		if v.Pasted {
			sa.MetadataXML = v.MetadataXML
		}
		out = append(out, sa)
	}
	if v := st.OIDC; v != nil && v.Issuer != "" {
		out = append(out, savedApp{AppConfig: AppConfig{ID: "default-oidc", Name: "OpenID Connect app", Protocol: ProtoOIDC, Created: now, Legacy: true,
			Issuer: v.Issuer, ClientID: v.ClientID, Scopes: v.Scopes, ExtraParams: v.ExtraParams}})
	}
	return out
}

// saveState writes all apps atomically, readable by the owner only.
// Failures are logged, not fatal: the tool works without it.
func (s *Server) saveState() {
	if s.StatePath == "" {
		return
	}
	s.stateSaver.save(s.writeState)
}

// writeState snapshots the apps under the lock, then encodes and writes
// them without it.
func (s *Server) writeState() {
	st := stateFile{Version: stateVersion}
	s.mu.Lock()
	for _, live := range s.apps {
		a := snapshotApp(live)
		sa := savedApp{AppConfig: a.AppConfig, LoadedXML: string(a.idpRaw), LoadedAt: a.idpLoadedAt}
		if a.KeepSecret {
			sa.ClientSecret = a.ClientSecret
		}
		st.Apps = append(st.Apps, sa)
	}
	if !s.access.empty() {
		a := s.access
		a.Passkeys = slices.Clone(a.Passkeys)
		st.Console = &a
	}
	s.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		// Never replace the file with a broken one.
		s.logf("could not save state: %v", err)
		return
	}

	if err := writeOwnerOnly(s.StatePath, b); err != nil {
		s.logf("could not save state to %s: %v", s.StatePath, err)
	}
}

// ---- store ----

func (s *Server) app(id string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// legacyApp is the app answering on the original single-app URLs.
func (s *Server) legacyApp(protocol string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if a.Legacy && a.Protocol == protocol {
			return a
		}
	}
	return nil
}

// appByIssuer finds the SAML app whose IdP has this entity ID.
func (s *Server) appByIssuer(entityID string) *App {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps {
		if a.IsSAML() && a.idp != nil && a.idp.EntityID == entityID {
			return a
		}
	}
	return nil
}

// IdPLogoutURL is where SAML logout messages go: the URL entered for the
// app, else the metadata's SingleLogoutService (Redirect preferred).
// source says which, for display.
func (a *App) IdPLogoutURL() (dest, binding, source string) {
	switch {
	case a.IdPSLOURL != "":
		return a.IdPSLOURL, "HTTP-Redirect", "entered in this app's settings"
	case a.idp != nil && a.idp.SLORedirect != "":
		return a.idp.SLORedirect, "HTTP-Redirect", "from the identity provider's metadata"
	case a.idp != nil && a.idp.SLOPost != "":
		return a.idp.SLOPost, "HTTP-POST", "from the identity provider's metadata"
	}
	return "", "", ""
}

// IdPLogoutURLView is IdPLogoutURL for templates.
func (a *App) IdPLogoutURLView() struct{ URL, Binding, Source string } {
	d, b, src := a.IdPLogoutURL()
	return struct{ URL, Binding, Source string }{d, b, src}
}

// SLOToIdP reports whether signing out goes to the identity provider (and
// so opens in a new tab): single logout on, and a logout URL known.
func (a *App) SLOToIdP() bool {
	if !a.Logout {
		return false
	}
	if a.IsSAML() {
		d, _, _ := a.IdPLogoutURL()
		return d != ""
	}
	return a.provider == nil || a.provider.EndSessionEndpoint != ""
}

// signerFor returns the app's SAML signing key, making it at first use.
func (s *Server) signerFor(app *App) (*saml.Signer, error) {
	return s.keyFor(app, &app.signer, &app.SignKeyPEM, &app.SignCertPEM, newSigningKey)
}

// encKeyFor returns the app's SAML encryption key, making it at first use.
func (s *Server) encKeyFor(app *App) (*saml.Signer, error) {
	return s.keyFor(app, &app.encKey, &app.EncKeyPEM, &app.EncCertPEM, newEncryptionKey)
}

// The key makers, replaceable in tests: an RSA key takes a moment.
var (
	newSigningKey    = saml.NewSigner
	newEncryptionKey = saml.NewEncryptionKey
)

// keyFor loads or makes one of the app's keys, kept in the state file.
func (s *Server) keyFor(app *App, key **saml.Signer, keyPEM, certPEM *string, newKey func(string) (*saml.Signer, []byte, []byte, error)) (*saml.Signer, error) {
	s.mu.Lock()
	sg, kp, cp := *key, *keyPEM, *certPEM
	s.mu.Unlock()
	if sg != nil {
		return sg, nil
	}
	if kp != "" {
		var err error
		if sg, err = saml.LoadSigner([]byte(kp), []byte(cp)); err != nil {
			return nil, fmt.Errorf("saved key: %w", err)
		}
		s.mu.Lock()
		*key = sg
		s.mu.Unlock()
		return sg, nil
	}
	// Generate outside the lock: an RSA key takes a moment.
	sg, k, c, err := newKey("SSOBench " + app.ID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if *key != nil { // made meanwhile by another request
		sg = *key
		s.mu.Unlock()
		return sg, nil
	}
	*key, *keyPEM, *certPEM = sg, string(k), string(c)
	s.mu.Unlock()
	s.saveState()
	return sg, nil
}

// appName reads the app's name, which Settings can change at any time.
func (s *Server) appName(app *App) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return app.Name
}
