// Package scim is the SCIM 2.0 (RFC 7643/7644) service provider side of
// a user directory: Users and Groups with the filters, patches and
// responses identity providers use. It works on a Directory value and
// does no HTTP itself.
package scim

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Schema and message URNs.
const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	ListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// Directory is an app's accounts and groups.
type Directory struct {
	Users  []*User
	Groups []*Group
}

// Group is a SCIM group in an app's directory.
type Group struct {
	ID      string    `json:"id"`
	Name    string    `json:"displayName"`
	Members []string  `json:"members,omitempty"` // user IDs
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

func ErrorBody(status int, scimType, detail string) map[string]any {
	m := map[string]any{"schemas": []string{errorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		m["scimType"] = scimType
	}
	return m
}

// Result is the answer to a SCIM request: the status, the JSON body, a
// summary for the activity list, and whether the directory changed.
type Result struct {
	Status  int
	Body    any // nil for 204
	Summary string
	Changed bool
}

func Fail(status int, scimType, detail string) Result {
	return Result{status, ErrorBody(status, scimType, detail), detail, false}
}

func ServiceProviderConfig() map[string]any {
	return map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": 200},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "The SCIM token shown for this app in SSOBench"}},
	}
}

func ResourceTypes() map[string]any {
	rt := "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	return map[string]any{"schemas": []string{ListSchema}, "totalResults": 2, "Resources": []map[string]any{
		{"schemas": []string{rt}, "id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		{"schemas": []string{rt}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	}}
}

// Redact pretty-prints a request body for the activity list, hiding
// any password an identity provider sends.
func Redact(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return prettyJSON(b)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if strings.EqualFold(k, "password") || (strings.EqualFold(k, "path") && strings.EqualFold(fmt.Sprint(val), "password")) {
					if _, ok := x["value"]; ok && strings.EqualFold(k, "path") {
						x["value"] = "(hidden)"
					}
					if strings.EqualFold(k, "password") {
						x[k] = "(hidden)"
					}
					continue
				}
				x[k] = walk(val)
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		}
		return v
	}
	out, _ := json.MarshalIndent(walk(v), "", "  ")
	return string(out)
}

// filterEq parses the simple filters identity providers send: attr eq "value".
var filterEq = regexp.MustCompile(`(?i)^\s*([a-zA-Z.]+)\s+eq\s+"([^"]*)"\s*$`)

func Users(method string, query url.Values, d *Directory, id string, body []byte, base string) Result {
	if id == "" {
		switch method {
		case http.MethodGet:
			q := query
			f := q.Get("filter")
			m := filterEq.FindStringSubmatch(f)
			if f != "" && m == nil {
				return Fail(400, "invalidFilter", "Only filters of the form attribute eq \"value\" are supported.")
			}
			var list []*User
			for _, u := range d.Users {
				if f == "" || userMatches(u, m[1], m[2]) {
					list = append(list, u)
				}
			}
			start, _ := strconv.Atoi(q.Get("startIndex"))
			start = max(start, 1)
			count, err := strconv.Atoi(q.Get("count"))
			if err != nil || count < 0 {
				count = 200
			}
			page := []any{}
			for i := start - 1; i < len(list) && len(page) < count; i++ {
				page = append(page, userResource(list[i], d, base))
			}
			summary := fmt.Sprintf("listed %d of %d users", len(page), len(list))
			if f != "" {
				summary = fmt.Sprintf("looked up %s %q: %s", m[1], m[2], map[bool]string{true: "found", false: "not found"}[len(list) > 0])
			}
			return Result{200, map[string]any{"schemas": []string{ListSchema}, "totalResults": len(list),
				"startIndex": start, "itemsPerPage": len(page), "Resources": page}, summary, false}
		case http.MethodPost:
			var in map[string]any
			if json.Unmarshal(body, &in) != nil {
				return Fail(400, "invalidSyntax", "The request body is not JSON.")
			}
			u := &User{ID: NewUserID(), Active: true, Source: "scim", Created: time.Now()}
			applyUser(u, in, true)
			if u.UserName == "" {
				return Fail(400, "invalidValue", "userName is required.")
			}
			if UserByName(d.Users, u.UserName) != nil {
				return Fail(409, "uniqueness", fmt.Sprintf("A user with userName %q already exists.", u.UserName))
			}
			u.Updated = u.Created
			d.Users = append(d.Users, u)
			return Result{201, userResource(u, d, base), "created " + u.UserName + map[bool]string{false: " (inactive)"}[u.Active], true}
		}
		return Fail(405, "", "Method not allowed.")
	}
	u := UserByID(d.Users, id)
	if u == nil {
		return Fail(404, "", "No user with id "+id)
	}
	switch method {
	case http.MethodGet:
		return Result{200, userResource(u, d, base), "read " + u.UserName, false}
	case http.MethodPut:
		var in map[string]any
		if json.Unmarshal(body, &in) != nil {
			return Fail(400, "invalidSyntax", "The request body is not JSON.")
		}
		was := u.Active
		applyUser(u, in, true)
		u.Updated = time.Now()
		return Result{200, userResource(u, d, base), "replaced " + u.UserName + activeChange(was, u.Active), true}
	case http.MethodPatch:
		var in struct {
			Operations []struct {
				Op    string          `json:"op"`
				Path  string          `json:"path"`
				Value json.RawMessage `json:"value"`
			} `json:"Operations"`
		}
		if json.Unmarshal(body, &in) != nil {
			return Fail(400, "invalidSyntax", "The request body is not a PatchOp.")
		}
		was := u.Active
		for _, op := range in.Operations {
			patchUser(u, strings.ToLower(op.Op), op.Path, op.Value)
		}
		u.Updated = time.Now()
		return Result{200, userResource(u, d, base), "updated " + u.UserName + activeChange(was, u.Active), true}
	case http.MethodDelete:
		d.Users = DeleteUser(d.Users, u.ID)
		for _, g := range d.Groups {
			g.Members = RemoveString(g.Members, u.ID)
		}
		return Result{204, nil, "deleted " + u.UserName, true}
	}
	return Fail(405, "", "Method not allowed.")
}

func UserByID(users []*User, id string) *User {
	for _, u := range users {
		if u.ID == id {
			return u
		}
	}
	return nil
}

func UserByName(users []*User, name string) *User {
	for _, u := range users {
		if strings.EqualFold(u.UserName, name) {
			return u
		}
	}
	return nil
}

func activeChange(was, now bool) string {
	switch {
	case was && !now:
		return " (deactivated)"
	case !was && now:
		return " (reactivated)"
	}
	return ""
}

func userMatches(u *User, attr, v string) bool {
	switch strings.ToLower(attr) {
	case "username":
		return strings.EqualFold(u.UserName, v)
	case "externalid":
		return u.ExternalID == v
	case "emails", "emails.value":
		return containsFold(u.Emails, v)
	case "id":
		return u.ID == v
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// applyUser copies SCIM attributes onto u. replace (PUT) clears what is absent.
func applyUser(u *User, in map[string]any, replace bool) {
	str := func(m map[string]any, k string) (string, bool) { v, ok := m[k].(string); return v, ok }
	if v, ok := str(in, "userName"); ok {
		u.UserName = v
	}
	if v, ok := str(in, "externalId"); ok || replace {
		u.ExternalID = v
	}
	if v, ok := str(in, "displayName"); ok || replace {
		u.Display = v
	}
	if n, ok := in["name"].(map[string]any); ok {
		u.GivenName, _ = str(n, "givenName")
		u.FamilyName, _ = str(n, "familyName")
		if u.Display == "" {
			u.Display, _ = str(n, "formatted")
		}
	} else if replace {
		u.GivenName, u.FamilyName = "", ""
	}
	if es, ok := in["emails"].([]any); ok || replace {
		u.Emails = nil
		for _, e := range es {
			m, _ := e.(map[string]any)
			v, _ := str(m, "value")
			if v == "" {
				continue
			}
			if p, _ := m["primary"].(bool); p {
				u.Emails = append([]string{v}, u.Emails...)
			} else {
				u.Emails = append(u.Emails, v)
			}
		}
	}
	if a, ok := in["active"]; ok {
		u.Active = truthy(a)
	} else if replace {
		u.Active = true
	}
}

// truthy accepts true/false and the "True"/"False" strings some identity
// providers send.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// patchUser applies one PATCH operation: with a path, or path-less with an
// object of attributes, as many identity providers send.
func patchUser(u *User, op, path string, raw json.RawMessage) {
	var v any
	json.Unmarshal(raw, &v)
	if path == "" {
		if m, ok := v.(map[string]any); ok {
			for k, val := range m {
				b, _ := json.Marshal(val)
				patchUser(u, op, k, b)
			}
		}
		return
	}
	s, _ := v.(string)
	if op == "remove" {
		s = ""
	}
	switch p := strings.ToLower(path); {
	case p == "active":
		u.Active = op != "remove" && truthy(v)
	case p == "username":
		if s != "" {
			u.UserName = s
		}
	case p == "externalid":
		u.ExternalID = s
	case p == "displayname":
		u.Display = s
	case p == "name.givenname":
		u.GivenName = s
	case p == "name.familyname":
		u.FamilyName = s
	case p == "name":
		m, _ := v.(map[string]any)
		u.GivenName, _ = m["givenName"].(string)
		u.FamilyName, _ = m["familyName"].(string)
	case strings.HasPrefix(p, "emails"):
		switch {
		case op == "remove":
			u.Emails = nil
		case s != "":
			u.Emails = append([]string{s}, RemoveString(u.Emails, s)...)
		default:
			applyUser(u, map[string]any{"emails": v}, false)
		}
	}
}

func userResource(u *User, d *Directory, base string) map[string]any {
	emails := []map[string]any{}
	for i, e := range u.Emails {
		emails = append(emails, map[string]any{"value": e, "type": "work", "primary": i == 0})
	}
	groups := []map[string]string{}
	for _, g := range d.Groups {
		if containsString(g.Members, u.ID) {
			groups = append(groups, map[string]string{"value": g.ID, "display": g.Name})
		}
	}
	return map[string]any{
		"schemas": []string{schemaUser}, "id": u.ID, "externalId": u.ExternalID, "userName": u.UserName,
		"name":        map[string]string{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.Name()},
		"displayName": u.Name(), "emails": emails, "active": u.Active, "groups": groups,
		"meta": map[string]string{"resourceType": "User", "created": u.Created.UTC().Format(time.RFC3339),
			"lastModified": u.Updated.UTC().Format(time.RFC3339), "location": base + "/Users/" + u.ID},
	}
}

var memberPath = regexp.MustCompile(`(?i)^members\[value eq "([^"]+)"\]$`)

func memberIDs(raw any) []string {
	var ids []string
	list, _ := raw.([]any)
	for _, m := range list {
		if mm, ok := m.(map[string]any); ok {
			if v, ok := mm["value"].(string); ok {
				ids = append(ids, v)
			}
		}
	}
	return ids
}

func groupResource(g *Group, d *Directory, base string) map[string]any {
	members := []map[string]string{}
	for _, m := range g.Members {
		disp := ""
		if u := UserByID(d.Users, m); u != nil {
			disp = u.UserName
		}
		members = append(members, map[string]string{"value": m, "display": disp})
	}
	return map[string]any{"schemas": []string{schemaGroup}, "id": g.ID, "displayName": g.Name, "members": members,
		"meta": map[string]string{"resourceType": "Group", "location": base + "/Groups/" + g.ID}}
}

func Groups(method string, query url.Values, d *Directory, id string, body []byte, base string) Result {
	if id == "" {
		switch method {
		case http.MethodGet:
			f := query.Get("filter")
			m := filterEq.FindStringSubmatch(f)
			if f != "" && m == nil {
				return Fail(400, "invalidFilter", "Only filters of the form attribute eq \"value\" are supported.")
			}
			res := []any{}
			for _, g := range d.Groups {
				if f == "" || (strings.EqualFold(m[1], "displayName") && strings.EqualFold(g.Name, m[2])) || (strings.EqualFold(m[1], "id") && g.ID == m[2]) {
					res = append(res, groupResource(g, d, base))
				}
			}
			return Result{200, map[string]any{"schemas": []string{ListSchema}, "totalResults": len(res), "startIndex": 1,
				"itemsPerPage": len(res), "Resources": res}, fmt.Sprintf("listed %d groups", len(res)), false}
		case http.MethodPost:
			var in map[string]any
			if json.Unmarshal(body, &in) != nil {
				return Fail(400, "invalidSyntax", "The request body is not JSON.")
			}
			name, _ := in["displayName"].(string)
			if name == "" {
				return Fail(400, "invalidValue", "displayName is required.")
			}
			g := &Group{ID: NewUserID(), Name: name, Members: memberIDs(in["members"]), Created: time.Now(), Updated: time.Now()}
			d.Groups = append(d.Groups, g)
			return Result{201, groupResource(g, d, base), "created group " + name, true}
		}
		return Fail(405, "", "Method not allowed.")
	}
	var g *Group
	for _, x := range d.Groups {
		if x.ID == id {
			g = x
		}
	}
	if g == nil {
		return Fail(404, "", "No group with id "+id)
	}
	switch method {
	case http.MethodGet:
		return Result{200, groupResource(g, d, base), "read group " + g.Name, false}
	case http.MethodPut:
		var in map[string]any
		if json.Unmarshal(body, &in) != nil {
			return Fail(400, "invalidSyntax", "The request body is not JSON.")
		}
		if name, _ := in["displayName"].(string); name != "" {
			g.Name = name
		}
		g.Members, g.Updated = memberIDs(in["members"]), time.Now()
		return Result{200, groupResource(g, d, base), "replaced group " + g.Name, true}
	case http.MethodPatch:
		var in struct {
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			} `json:"Operations"`
		}
		if json.Unmarshal(body, &in) != nil {
			return Fail(400, "invalidSyntax", "The request body is not a PatchOp.")
		}
		for _, op := range in.Operations {
			o, p := strings.ToLower(op.Op), op.Path
			switch {
			case strings.EqualFold(p, "members") && o == "add":
				for _, m := range memberIDs(op.Value) {
					if !containsString(g.Members, m) {
						g.Members = append(g.Members, m)
					}
				}
			case strings.EqualFold(p, "members") && o == "remove":
				if ids := memberIDs(op.Value); len(ids) > 0 {
					for _, m := range ids {
						g.Members = RemoveString(g.Members, m)
					}
				} else {
					g.Members = nil
				}
			case strings.EqualFold(p, "members") && o == "replace":
				g.Members = memberIDs(op.Value)
			case memberPath.MatchString(p) && o == "remove":
				g.Members = RemoveString(g.Members, memberPath.FindStringSubmatch(p)[1])
			case strings.EqualFold(p, "displayName") || (p == "" && o != "remove"):
				if name, ok := op.Value.(string); ok {
					g.Name = name
				} else if m, ok := op.Value.(map[string]any); ok {
					if name, ok := m["displayName"].(string); ok {
						g.Name = name
					}
					if ms, ok := m["members"]; ok && o == "add" {
						for _, id := range memberIDs(ms) {
							if !containsString(g.Members, id) {
								g.Members = append(g.Members, id)
							}
						}
					}
				}
			}
		}
		g.Updated = time.Now()
		return Result{200, groupResource(g, d, base), fmt.Sprintf("updated group %s (%d members)", g.Name, len(g.Members)), true}
	case http.MethodDelete:
		var keep []*Group
		for _, x := range d.Groups {
			if x.ID != g.ID {
				keep = append(keep, x)
			}
		}
		d.Groups = keep
		return Result{204, nil, "deleted group " + g.Name, true}
	}
	return Fail(405, "", "Method not allowed.")
}

func DeleteUser(users []*User, id string) []*User {
	var out []*User
	for _, u := range users {
		if u.ID != id {
			out = append(out, u)
		}
	}
	return out
}

func RemoveString(list []string, v string) []string {
	var out []string
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// User is an account in an app's user directory, the way a real application
// keeps them: created by SCIM provisioning, by hand, by CSV import, or just
// in time at first sign-in.
type User struct {
	ID         string    `json:"id"`
	UserName   string    `json:"userName"`
	ExternalID string    `json:"externalId,omitempty"`
	Emails     []string  `json:"emails,omitempty"`
	GivenName  string    `json:"givenName,omitempty"`
	FamilyName string    `json:"familyName,omitempty"`
	Display    string    `json:"displayName,omitempty"`
	Groups     []string  `json:"groups,omitempty"`
	Active     bool      `json:"active"`
	Source     string    `json:"source"` // scim, manual, csv, jit
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
	LastSignIn time.Time `json:"lastSignIn,omitempty"`
}

func (u *User) Name() string {
	if u.Display != "" {
		return u.Display
	}
	return strings.TrimSpace(u.GivenName + " " + u.FamilyName)
}

func (u *User) PrimaryEmail() string {
	if len(u.Emails) > 0 {
		return u.Emails[0]
	}
	return ""
}

func NewUserID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func prettyJSON(b []byte) string {
	if len(bytes.TrimSpace(b)) == 0 {
		return ""
	}
	var out bytes.Buffer
	if json.Indent(&out, b, "", "  ") != nil {
		return string(b)
	}
	return out.String()
}
