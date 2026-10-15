package web

import (
	"strings"
	"unicode"
)

// How a sign-in started, which decides where the browser lands afterwards.
const (
	ViaConsole = "console" // the Sign in button in SSOBench: show diagnostics
	ViaPage    = "page"    // the app's own sign-in page: show the profile
	ViaIdP     = "idp"     // started at the identity provider (an app tile)
)

// Where IdP-initiated sign-ins land, per app.
const (
	LandProfile     = "profile"
	LandDiagnostics = "diagnostics"
)

// Profile is who signed in, in the words a person would use: the welcome
// screen shown after signing in through an app's sign-in page.
type Profile struct {
	DisplayName string
	Email       string
	Initials    string
	Fields      []ProfileField
}

type ProfileField struct {
	Label  string
	Values []string
	Tags   bool // show as tags (groups, roles)
}

// profileKeys maps normalized attribute and claim names to friendly labels.
// Normalizing drops case and punctuation, so "given_name", "givenname" and
// "First Name" all match.
var profileKeys = []struct {
	label string
	keys  []string
	tags  bool
}{
	{"Display name", []string{"displayname", "name", "cn", "commonname", "fullname"}, false},
	{"Email", []string{"email", "emailaddress", "mail", "emailaddr"}, false},
	{"Username", []string{"username", "preferredusername", "upn", "samaccountname", "uid", "login", "userprincipalname"}, false},
	{"First name", []string{"firstname", "givenname"}, false},
	{"Last name", []string{"lastname", "surname", "sn", "familyname"}, false},
	{"Phone", []string{"phone", "phonenumber", "telephonenumber", "mobile", "mobilephone"}, false},
	{"Groups", []string{"groups", "group", "memberof"}, true},
	{"Roles", []string{"roles", "role"}, true},
	{"Sign-in methods", []string{"amr", "authenticationmethodsreferences"}, true},
}

// technicalClaims are token plumbing, not facts about the person.
var technicalClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "nonce": true, "athash": true,
	"chash": true, "azp": true, "authtime": true, "sid": true, "jti": true, "acr": true, "sub": true,
	"tid": true, "oid": true, "ver": true, "idp": true, "uti": true, "rh": true, "sessionindex": true,
}

func normKey(k string) string {
	if i := strings.LastIndexAny(k, "/:"); i >= 0 && i < len(k)-1 {
		k = k[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Profile builds the friendly view of res's attributes or claims.
func (res *Result) Profile() Profile {
	var p Profile
	known := map[string]*ProfileField{}
	var other []ProfileField
	for _, sec := range res.Sections(GroupIdentity) {
		for _, row := range sec.Rows {
			key := normKey(row.K)
			if row.Title != "" {
				key = normKey(row.Title)
			}
			if technicalClaims[key] {
				continue
			}
			values := strings.Split(row.V, "\n")
			if key == "amr" || key == "authenticationmethodsreferences" {
				for i, v := range values {
					if w, ok := amrWords[strings.ToLower(strings.TrimSpace(v))]; ok {
						values[i] = w
					}
				}
			}
			matched := false
			for _, pk := range profileKeys {
				for _, k := range pk.keys {
					if key == k {
						if _, dup := known[pk.label]; !dup {
							known[pk.label] = &ProfileField{Label: pk.label, Values: values, Tags: pk.tags}
						}
						matched = true
					}
				}
			}
			if !matched {
				other = append(other, ProfileField{Label: shortLabel(row), Values: values})
			}
		}
	}
	for _, pk := range profileKeys {
		if f, ok := known[pk.label]; ok {
			p.Fields = append(p.Fields, *f)
		}
	}
	p.Fields = append(p.Fields, other...)

	first := func(label string) string {
		if f, ok := known[label]; ok && len(f.Values) > 0 {
			return strings.TrimSpace(f.Values[0])
		}
		return ""
	}
	p.Email = first("Email")
	if p.Email == "" && strings.Contains(res.Subject, "@") {
		p.Email = res.Subject
	}
	p.DisplayName = first("Display name")
	if p.DisplayName == "" {
		p.DisplayName = strings.TrimSpace(first("First name") + " " + first("Last name"))
	}
	if p.DisplayName == "" {
		p.DisplayName = firstNonEmpty(first("Username"), localPart(p.Email), res.Subject, "there")
	}
	p.Initials = initials(p.DisplayName)
	return p
}

// FirstName is the greeting name: the first name if known.
func (p Profile) FirstName() string {
	for _, f := range p.Fields {
		if f.Label == "First name" && len(f.Values) > 0 && f.Values[0] != "" {
			return f.Values[0]
		}
	}
	if fs := strings.Fields(p.DisplayName); len(fs) > 0 && !strings.Contains(fs[0], "@") {
		return fs[0]
	}
	return p.DisplayName
}

func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return ""
}

func initials(name string) string {
	var out []rune
	for _, w := range strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		out = append(out, unicode.ToUpper([]rune(w)[0]))
		if len(out) == 2 {
			break
		}
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// shortLabel is a person-friendly name for an attribute: its friendly name,
// or the last part of a URI-style name.
func shortLabel(row Row) string {
	if row.Title != "" {
		return row.Title
	}
	if i := strings.LastIndexAny(row.K, "/:"); i >= 0 && i < len(row.K)-1 {
		return row.K[i+1:]
	}
	return row.K
}

// amrWords are the RFC 8176 authentication method codes in plain words.
var amrWords = map[string]string{
	"pwd": "Password", "mfa": "Multi-factor", "otp": "One-time code", "hwk": "Security key",
	"swk": "Software key", "sms": "Text message", "tel": "Phone call", "face": "Face recognition",
	"fpt": "Fingerprint", "pin": "PIN", "kba": "Security questions", "user": "User presence",
	"pop": "Proof of possession", "rba": "Risk-based", "wia": "Windows sign-in", "sc": "Smart card",
	"mca": "Multiple channels", "geo": "Location", "iris": "Iris scan", "retina": "Retina scan", "vbm": "Voice",
}
