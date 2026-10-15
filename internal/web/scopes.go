package web

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ryanhebert/ssobench/internal/check"
)

// scopeClaims are the claims each standard OpenID Connect scope asks for
// (OpenID Connect Core, section 5.4).
var scopeClaims = map[string][]string{
	"openid": {"sub"},
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile",
		"picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// ScopeRow is one requested scope: whether it was granted, and which of
// its claims arrived in the ID token or from UserInfo.
type ScopeRow struct {
	Scope    string   `json:"scope"`
	Granted  string   `json:"granted"` // "yes", "no", or "" when the token response doesn't say
	Claims   []string `json:"claims,omitempty"`
	Of       int      `json:"of,omitempty"`   // how many claims the scope defines; 0 for other scopes
	Note     string   `json:"note,omitempty"` // for scopes that are not about claims
	Standard bool     `json:"standard,omitempty"`
}

// inspectScopes compares the scopes asked for with those granted (the
// token response's scope, when present) and the claims received.
func inspectScopes(requested, granted string, claims map[string]bool, refreshToken bool) ([]ScopeRow, []check.Result) {
	var rows []ScopeRow
	var rs []check.Result
	grantedList := strings.Fields(granted)
	var empty, refused []string
	for _, sc := range strings.Fields(requested) {
		row := ScopeRow{Scope: sc}
		switch {
		case granted == "":
		case slices.Contains(grantedList, sc):
			row.Granted = "yes"
		default:
			row.Granted = "no"
			refused = append(refused, sc)
		}
		if want, ok := scopeClaims[sc]; ok {
			row.Standard, row.Of = true, len(want)
			for _, c := range want {
				if claims[c] {
					row.Claims = append(row.Claims, c)
				}
			}
			if len(row.Claims) == 0 && row.Granted != "no" {
				empty = append(empty, sc)
			}
		} else if sc == "offline_access" {
			row.Note = map[bool]string{true: "A refresh token was issued", false: "No refresh token was issued"}[refreshToken]
		} else if claims[sc] {
			row.Claims = []string{sc}
		}
		rows = append(rows, row)
	}
	if len(refused) > 0 {
		rs = append(rs, check.Note("Scopes", "not granted: "+strings.Join(refused, ", ")+" (the token response lists the scopes it granted)"))
	}
	if len(empty) > 0 {
		rs = append(rs, check.Meh("Scope claims", fmt.Sprintf("no claims arrived for %s", strings.Join(empty, ", ")),
			"The provider accepted the scope but sent none of its claims in the ID token or from UserInfo. Check the claims it releases to this app."))
	}
	for _, sc := range strings.Fields(granted) {
		if !slices.Contains(strings.Fields(requested), sc) {
			rs = append(rs, check.Note("Scopes", "granted without being asked for: "+sc))
		}
	}
	return rows, rs
}

// claimNames collects the claim names in maps.
func claimNames(maps ...map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, m := range maps {
		for k := range m {
			out[k] = true
		}
	}
	return out
}
