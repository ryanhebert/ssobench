package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/ryanhebert/ssobench/internal/scim"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// SCIM 2.0 (RFC 7643/7644) provisioning target, one per app, so the
// identity provider can create, update and deactivate the app's accounts.
// Every request is recorded in the app's provisioning activity.

const (
	scimUser   = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroup  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimList   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimError  = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatch  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	maxProvLog = 100
)

// ProvEvent is one SCIM request, as the app's provisioning activity shows it.
type ProvEvent struct {
	Time     time.Time `json:"time"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Summary  string    `json:"summary"`
	Request  string    `json:"request,omitempty"`
	Response string    `json:"response,omitempty"`
}

func (e ProvEvent) OK() bool { return e.Status < 400 }

// scimURL is the SCIM base URL to give the identity provider.
func (s *Server) scimURL(r *http.Request, app *App) string {
	s.mu.Lock()
	base := app.SCIMPublic
	s.mu.Unlock()
	if base == "" {
		base = s.base(r)
	}
	return base + "/scim/" + app.ID + "/v2"
}

// publicOrigin checks an address entered for SCIM: an http or https
// origin with no path, returned without a trailing slash.
func publicOrigin(v string) (string, bool) {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	if v == "" {
		return "", true
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

func scimJSON(w http.ResponseWriter, status int, v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	w.Write(b)
	return b
}

// scimHandler serves /scim/{app}/v2/{rest...}. The resource handlers run
// under s.mu and return the response; writing it, recording the request in
// the app's provisioning activity and saving happen after.
func (s *Server) scimHandler(w http.ResponseWriter, r *http.Request) {
	app := s.app(r.PathValue("app"))
	rest := strings.Trim(r.PathValue("rest"), "/")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	s.mu.Lock()
	on := app != nil && app.Directory
	token := ""
	if app != nil {
		token = app.SCIMToken
	}
	s.mu.Unlock()
	if !on {
		scimJSON(w, http.StatusNotFound, scim.ErrorBody(404, "", "This app has no user directory. Turn it on in the app's settings in SSOBench."))
		return
	}

	var res scim.Result
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
		res = scim.Fail(http.StatusUnauthorized, "", "Missing or wrong bearer token. Use the SCIM token shown for this app in SSOBench.")
	} else {
		resource, id, _ := strings.Cut(rest, "/")
		base := s.scimURL(r, app)
		s.locked(func() {
			switch resource {
			case "ServiceProviderConfig":
				res = scim.Result{Status: 200, Body: scim.ServiceProviderConfig(), Summary: "read the service provider configuration"}
			case "ResourceTypes":
				res = scim.Result{Status: 200, Body: scim.ResourceTypes(), Summary: "read the resource types"}
			case "Schemas":
				res = scim.Result{Status: 200, Body: map[string]any{"schemas": []string{scim.ListSchema}, "totalResults": 0, "Resources": []any{}}, Summary: "read the schemas"}
			case "Users":
				res = s.scimDirectory(app, func(d *scim.Directory) scim.Result { return scim.Users(r.Method, r.URL.Query(), d, id, body, base) })
				if res.Changed {
					if n := s.endForAccountsLocked(app); n > 0 {
						res.Summary += fmt.Sprintf("; ended %d %s", n, plural(n, "session", "sessions"))
					}
				}
			case "Groups":
				res = s.scimDirectory(app, func(d *scim.Directory) scim.Result { return scim.Groups(r.Method, r.URL.Query(), d, id, body, base) })
			default:
				res = scim.Fail(http.StatusNotFound, "", "Unknown SCIM resource "+resource)
			}
		})
	}

	var out []byte
	if res.Body != nil {
		out = scimJSON(w, res.Status, res.Body)
	} else {
		w.WriteHeader(res.Status)
	}
	ev := ProvEvent{Time: time.Now(), Method: r.Method, Path: "/" + rest, Status: res.Status, Summary: res.Summary,
		Request: capBody(scim.Redact(body)), Response: capBody(string(out))}
	if r.URL.RawQuery != "" {
		if q, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
			ev.Path += "?" + q
		} else {
			ev.Path += "?" + r.URL.RawQuery
		}
	}
	s.mu.Lock()
	app.ProvLog = append([]ProvEvent{ev}, app.ProvLog...)
	if len(app.ProvLog) > maxProvLog {
		app.ProvLog = app.ProvLog[:maxProvLog]
	}
	name := app.Name
	s.mu.Unlock()
	s.logf("SCIM %s: %s %s -> %d %s", name, r.Method, ev.Path, res.Status, res.Summary)
	// A read changes nothing worth a write of the whole state file; its
	// activity entry is saved with the next change.
	if res.Changed || r.Method != http.MethodGet {
		s.saveState()
	}
}

// maxProvBody is how much of a SCIM request or response the activity
// keeps: enough to read, without a full sync filling the state file.
const maxProvBody = 8 << 10

func capBody(b string) string {
	if len(b) <= maxProvBody {
		return b
	}
	cut := maxProvBody
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut] + fmt.Sprintf("\n… %d more bytes not kept", len(b)-cut)
}

// Title is the activity row's heading: what changed, or why it was rejected.
func (e ProvEvent) Title() string {
	if e.OK() {
		return capitalize(e.Summary)
	}
	switch e.Status {
	case 401:
		return "Rejected: wrong bearer token"
	case 404:
		return "Rejected: not found"
	case 409:
		return "Rejected: already exists"
	}
	return fmt.Sprintf("Rejected (%d): %s", e.Status, e.Summary)
}

// scimDirectory runs fn on the app's directory, under the lock, and keeps
// the accounts and groups it leaves.
func (s *Server) scimDirectory(app *App, fn func(*scim.Directory) scim.Result) scim.Result {
	d := &scim.Directory{Users: app.Users, Groups: app.Groups}
	res := fn(d)
	app.Users, app.Groups = d.Users, d.Groups
	return res
}

// Accounts and groups are the SCIM package's types.
type (
	User  = scim.User
	Group = scim.Group
)

var (
	userByID     = scim.UserByID
	userByName   = scim.UserByName
	deleteUser   = scim.DeleteUser
	removeString = scim.RemoveString
	newUserID    = scim.NewUserID
)
