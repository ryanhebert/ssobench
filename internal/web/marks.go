package web

import (
	"strings"

	"github.com/ryanhebert/ssobench/internal/check"
)

// checkRows maps a check name to the rows (keys) it is about, so a failing
// check also marks the value in the data: aud in the claims, Audience in
// the conditions.
var checkRows = map[string][]string{
	"Audience (aud)":                {"aud"},
	"Issuer (iss)":                  {"iss"},
	"Lifetime (nbf/exp)":            {"exp", "nbf"},
	"Issued at (iat)":               {"iat"},
	"Nonce":                         {"nonce"},
	"Authorized party (azp)":        {"azp"},
	"Access token hash (at_hash)":   {"at_hash"},
	"Audience":                      {"Audience"},
	"Destination":                   {"Destination"},
	"Recipient":                     {"Confirmation recipient"},
	"Issuer":                        {"Assertion issuer"},
	"Conditions lifetime":           {"Not before", "Not on or after"},
	"Subject confirmation lifetime": {"Confirmation not on or after"},
	"InResponseTo":                  {"InResponseTo"},
	"NameID":                        {"NameID"},
}

func markRows(res *Result) {
	status := map[string]check.Status{}
	for _, c := range res.Checks {
		if c.Status != check.Fail && c.Status != check.Warn {
			continue
		}
		keys := checkRows[c.Name]
		if len(keys) == 2 && (c.Name == "Lifetime (nbf/exp)" || c.Name == "Conditions lifetime") {
			// A window check fails on one bound: mark that row only.
			// Lifetime rows are listed {upper, lower} for OIDC, {lower, upper} for SAML.
			lower, upper := keys[1], keys[0]
			if c.Name == "Conditions lifetime" {
				lower, upper = keys[0], keys[1]
			}
			switch {
			case strings.HasPrefix(c.Detail, "expired"):
				keys = []string{upper}
			case strings.HasPrefix(c.Detail, "not valid until"):
				keys = []string{lower}
			}
		}
		for _, k := range keys {
			if status[k] != check.Fail {
				status[k] = c.Status
			}
		}
	}
	for i := range res.All {
		for j := range res.All[i].Rows {
			if st, ok := status[res.All[i].Rows[j].K]; ok {
				res.All[i].Rows[j].Status = string(st)
			}
		}
	}
}
