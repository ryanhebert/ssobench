package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// SP describes this tool acting as a service provider.
type SP struct {
	EntityID string
	ACSURL   string
	SLOURL   string // single logout endpoint; empty for none
	// SigningCert is the SP's signing certificate (base64 DER) for the
	// metadata; SignRequests sets AuthnRequestsSigned.
	SigningCert  string
	SignRequests bool
	// EncryptionCert (base64 DER) asks the IdP to encrypt assertions.
	EncryptionCert string
	// NameIDFormat is the format the SP asks for; empty for unspecified.
	NameIDFormat string
}

// NameID formats.
const (
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// AuthnOptions are what an AuthnRequest asks of the identity provider.
type AuthnOptions struct {
	ForceAuthn bool
	IsPassive  bool
	// NameIDFormat goes in NameIDPolicy; empty asks for none in particular.
	NameIDFormat string
	// AuthnContext lists AuthnContextClassRef values for
	// RequestedAuthnContext, compared by Comparison (exact when empty).
	AuthnContext []string
	Comparison   string
}

// NewRequestID returns an XML ID (must not start with a digit).
func NewRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

func esc(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// AuthnRequest builds an AuthnRequest (signed later, if at all) asking for
// a POST-binding response.
func AuthnRequest(sp SP, id, destination string, o AuthnOptions, now time.Time) []byte {
	attrs := ""
	if o.ForceAuthn {
		attrs += ` ForceAuthn="true"`
	}
	if o.IsPassive {
		attrs += ` IsPassive="true"`
	}
	format := ""
	if o.NameIDFormat != "" {
		format = fmt.Sprintf(` Format="%s"`, esc(o.NameIDFormat))
	}
	ctx := ""
	if len(o.AuthnContext) > 0 {
		cmp := ""
		if o.Comparison != "" && o.Comparison != "exact" {
			cmp = fmt.Sprintf(` Comparison="%s"`, esc(o.Comparison))
		}
		ctx = fmt.Sprintf(`<samlp:RequestedAuthnContext%s>`, cmp)
		for _, ref := range o.AuthnContext {
			ctx += fmt.Sprintf(`<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>`, esc(ref))
		}
		ctx += `</samlp:RequestedAuthnContext>`
	}
	return []byte(fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="%s"%s><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy%s AllowCreate="true"/>%s</samlp:AuthnRequest>`,
		esc(id), now.UTC().Format(time.RFC3339), esc(destination), esc(sp.ACSURL), BindingPOST, attrs, esc(sp.EntityID), format, ctx))
}

// RedirectURL encodes req for the HTTP-Redirect binding (raw DEFLATE, then
// base64, then URL-encoding).
func RedirectURL(destination string, req []byte, relayState string) (string, error) {
	return EncodeRedirect(destination, "SAMLRequest", req, relayState)
}

// EncodeRedirect encodes a SAML message as the param ("SAMLRequest" or
// "SAMLResponse") of an HTTP-Redirect binding URL.
func EncodeRedirect(destination, param string, msg []byte, relayState string) (string, error) {
	req := msg
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(req)
	w.Close()
	u, err := url.Parse(destination)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Metadata returns SP metadata for pasting into the IdP, with the signing
// certificate when there is one, and the encryption certificate when
// assertions should be encrypted.
func Metadata(sp SP) []byte {
	slo := ""
	if sp.SLOURL != "" {
		slo = fmt.Sprintf(`
    <md:SingleLogoutService Binding="%s" Location="%s"/>
    <md:SingleLogoutService Binding="%s" Location="%s"/>`, BindingRedirect, esc(sp.SLOURL), BindingPOST, esc(sp.SLOURL))
	}
	key := ""
	if sp.SigningCert != "" {
		key = fmt.Sprintf(`
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>`, sp.SigningCert)
	}
	if sp.EncryptionCert != "" {
		key += fmt.Sprintf(`
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      <md:EncryptionMethod Algorithm="%s"/>
      <md:EncryptionMethod Algorithm="%s"/>
      <md:EncryptionMethod Algorithm="%s"/>
      <md:EncryptionMethod Algorithm="%s"/>
    </md:KeyDescriptor>`, sp.EncryptionCert, EncAES256GCM, EncAES128GCM, KeyRSAOAEP11, KeyRSAOAEP)
	}
	nameIDFormat := sp.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = NameIDUnspecified
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="%t" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">%s%s
    <md:NameIDFormat>%s</md:NameIDFormat>
    <md:AssertionConsumerService Binding="%s" Location="%s" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`, esc(sp.EntityID), sp.SignRequests, key, slo, esc(nameIDFormat), BindingPOST, esc(sp.ACSURL)))
}

// DecodeMessage turns a SAMLRequest/SAMLResponse value into XML. It accepts
// raw XML, base64 (POST binding), base64+DEFLATE (Redirect binding), and
// URL-encoded variants of those, including a whole redirect URL.
func DecodeMessage(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<") {
		return []byte(s), nil
	}
	if u, err := url.Parse(s); err == nil && u.Scheme != "" {
		q := u.Query()
		for _, k := range []string{"SAMLResponse", "SAMLRequest"} {
			if v := q.Get(k); v != "" {
				return DecodeMessage(v)
			}
		}
	}
	for _, k := range []string{"SAMLResponse=", "SAMLRequest="} {
		if i := strings.Index(s, k); i >= 0 {
			s = s[i+len(k):]
			if j := strings.IndexByte(s, '&'); j >= 0 {
				s = s[:j]
			}
		}
	}
	if strings.Contains(s, "%") {
		if u, err := url.QueryUnescape(s); err == nil {
			s = u
		}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("not XML, and not valid base64")
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("<")) {
		return raw, nil
	}
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 8<<20))
	if err == nil && bytes.HasPrefix(bytes.TrimSpace(inflated), []byte("<")) {
		return inflated, nil
	}
	return nil, errors.New("base64 decoded, but the result is neither XML nor DEFLATE-compressed XML")
}

// Pretty re-indents XML without disturbing namespace prefixes. On parse
// failure it returns the input unchanged.
func Pretty(b []byte) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		return string(b)
	}
	doc.Indent(2)
	s, err := doc.WriteToString()
	if err != nil {
		return string(b)
	}
	return s
}
