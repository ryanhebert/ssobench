package web

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ryanhebert/ssobench/internal/oidc"
)

func randomID() string { return oidc.RandomString(9) }

// refAlphabet has no look-alikes (no I, L, O, U, 0 or 1), so a reference
// can be read out over the phone.
const refAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

// newRef returns a 12-character reference for a result.
func newRef() string {
	b := make([]byte, 12)
	rand.Read(b)
	for i := range b {
		b[i] = refAlphabet[int(b[i])%len(refAlphabet)]
	}
	return string(b)
}

// FormatRef groups a reference for reading: ABCD-EFGH-JKMN.
func FormatRef(id string) string {
	if len(id) != 12 {
		return id
	}
	return id[:4] + "-" + id[4:8] + "-" + id[8:]
}

// normalizeRef accepts any case, spaces and dashes. The alphabet has no
// 0, 1, O, I or L, so those can't be misread.
func normalizeRef(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

func queryRows(q url.Values) []Row {
	var rows []Row
	for _, k := range sortedKeys(q) {
		v := strings.Join(q[k], ", ")
		if k == "code" {
			v = shortToken(v) + " (single use, already redeemed)"
		}
		rows = append(rows, Row{K: k, V: v})
	}
	return rows
}

func rowsText(rows []Row) string {
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%-18s %s\n", r.K, r.V)
	}
	return b.String()
}

// prettyURL puts each query parameter of u on its own line.
func prettyURL(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := pu.Query()
	pu.RawQuery = ""
	var b strings.Builder
	b.WriteString(pu.String() + "\n")
	for _, k := range sortedKeys(q) {
		fmt.Fprintf(&b, "  %-22s %s\n", k, strings.Join(q[k], ", "))
	}
	return b.String()
}

func tokenKinds(t *oidc.Tokens) string {
	var k []string
	if t.IDToken != "" {
		k = append(k, "ID token")
	}
	if t.AccessToken != "" {
		k = append(k, "access token")
	}
	if t.RefreshToken != "" {
		k = append(k, "refresh token")
	}
	if len(k) == 0 {
		return "no tokens"
	}
	return strings.Join(k, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

func display(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	// Lists of strings (groups, amr, roles) read best one per line.
	if list, ok := v.([]any); ok {
		var ss []string
		for _, x := range list {
			s, ok := x.(string)
			if !ok {
				ss = nil
				break
			}
			ss = append(ss, s)
		}
		if ss != nil {
			return strings.Join(ss, "\n")
		}
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func indent(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return string(b)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

// redactRefresh shortens the refresh token in the raw token response shown
// on the result page: it is long-lived and has no diagnostic value. ID and
// access tokens stay whole because inspecting them is the point.
func redactRefresh(b []byte) string {
	return mapTokens(b, map[string]bool{"refresh_token": true})
}

// shortenTokens shortens every token, for the log.
func shortenTokens(b []byte) string {
	return mapTokens(b, map[string]bool{"refresh_token": true, "access_token": true, "id_token": true})
}

func mapTokens(b []byte, keys map[string]bool) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return string(b)
	}
	for k := range keys {
		if t, ok := m[k].(string); ok {
			m[k] = shortToken(t)
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return string(out)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// ago is a relative time for people: "just now", "3 min ago", "2 h ago".
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d s ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Round(time.Minute).Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return t.Format("Jan 2, 15:04")
}

// until is a friendly distance to a future time: "in 3 days", "in 5 h".
func until(t time.Time) string {
	d := time.Until(t)
	switch {
	case d < 0:
		return ago(t)
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %d h", int(d.Hours()))
	}
	return fmt.Sprintf("in %d days", int(d.Hours()/24))
}

// humanDur rounds to milliseconds below a second and to seconds above.
func humanDur(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Round(time.Second).Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Round(time.Minute).Minutes()))
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	if m == 0 {
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Diff splits two strings into a shared prefix, the differing middles and a
// shared suffix, so the template can highlight just what differs.
type Diff struct{ Pre, Got, Want, Suf string }

func diffParts(got, want string) Diff {
	g, w := []rune(got), []rune(want)
	p := 0
	for p < len(g) && p < len(w) && g[p] == w[p] {
		p++
	}
	sfx := 0
	for sfx < len(g)-p && sfx < len(w)-p && g[len(g)-1-sfx] == w[len(w)-1-sfx] {
		sfx++
	}
	return Diff{Pre: string(g[:p]), Got: string(g[p : len(g)-sfx]), Want: string(w[p : len(w)-sfx]), Suf: string(g[len(g)-sfx:])}
}

// agoLong is ago with units spelled out, for the pages people signing in see.
func agoLong(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < 2*time.Minute:
		return "a minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Round(time.Minute).Minutes()))
	case d < 2*time.Hour:
		return "an hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return t.Format("January 2, 15:04")
}

// oauthRefusal words a token endpoint error plainly, with the OAuth error
// code, leaving the response body to the log.
func oauthRefusal(what string, raw []byte, err error) string {
	if code := oidc.OAuthError(raw); code != "" {
		return what + " (" + code + ")"
	}
	return what + ": " + err.Error()
}
