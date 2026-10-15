package decode

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ryanhebert/ssobench/internal/saml"
)

func TestSummaryRowsKeepLongAndMultibyteNames(t *testing.T) {
	r := &saml.Response{Issuer: "https://idp.example"}
	r.Assertions = []saml.Assertion{{Attributes: []saml.Attribute{
		{Name: "a-very-long-attribute-name-indeed", Values: []string{"x"}},
		{Name: "prénom-utilisateur-complet", Values: []string{"Zoë", "Ana"}},
	}}}
	rows := SummaryRows(r)
	want := map[string]string{"Issuer": "https://idp.example", "a-very-long-attribute-name-indeed": "x", "prénom-utilisateur-complet": "Zoë, Ana"}
	for _, row := range rows {
		if w, ok := want[row[0]]; ok && w == row[1] {
			delete(want, row[0])
		}
	}
	if len(want) > 0 {
		t.Errorf("missing or garbled rows %v in %q", want, rows)
	}
}

func TestAuto(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	now := time.Unix(1700000000, 0)
	jwt := enc(`{"alg":"RS256","kid":"k1"}`) + "." + enc(`{"sub":"u1","exp":1700000600}`) + ".c2ln"
	r, err := Auto(jwt, now)
	if err != nil || r.Kind != "JWT" || len(r.Parts) != 4 || !strings.Contains(r.Parts[2].Body, "exp") || !strings.Contains(r.Parts[3].Body, `kid "k1"`) {
		t.Fatalf("JWT: %v %+v", err, r)
	}
	resp := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`
	r, err = Auto(base64.StdEncoding.EncodeToString([]byte(resp)), now)
	if err != nil || r.Kind != "SAML" || !strings.Contains(r.Parts[0].Body+r.Parts[len(r.Parts)-1].Body, "https://idp.example") {
		t.Fatalf("SAML: %v %+v", err, r)
	}
	if _, err := Auto("  ", now); err == nil {
		t.Error("empty input decoded")
	}
}
