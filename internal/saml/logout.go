package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// LogoutRequest builds an unsigned SP-initiated LogoutRequest.
func LogoutRequest(sp SP, id, destination, nameID, nameIDFormat, sessionIndex string, now time.Time) []byte {
	format, session := "", ""
	if nameIDFormat != "" {
		format = fmt.Sprintf(` Format="%s"`, esc(nameIDFormat))
	}
	if sessionIndex != "" {
		session = fmt.Sprintf(`<samlp:SessionIndex>%s</samlp:SessionIndex>`, esc(sessionIndex))
	}
	return []byte(fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID%s>%s</saml:NameID>%s</samlp:LogoutRequest>`,
		esc(id), now.UTC().Format(time.RFC3339), esc(destination), esc(sp.EntityID), format, esc(nameID), session))
}

// LogoutResponse builds an unsigned LogoutResponse with status Success.
func LogoutResponse(sp SP, id, inResponseTo, destination string, now time.Time) []byte {
	return []byte(fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`,
		esc(id), now.UTC().Format(time.RFC3339), esc(destination), esc(inResponseTo), esc(sp.EntityID), statusSuccess))
}

// LogoutMessage is a parsed LogoutRequest or LogoutResponse.
type LogoutMessage struct {
	XMLName      xml.Name
	ID           string     `xml:"ID,attr"`
	InResponseTo string     `xml:"InResponseTo,attr"`
	Destination  string     `xml:"Destination,attr"`
	Issuer       string     `xml:"Issuer"`
	NameID       NameID     `xml:"NameID"`
	SessionIndex []string   `xml:"SessionIndex"`
	Status       StatusCode `xml:"Status>StatusCode"`
	StatusMsg    string     `xml:"Status>StatusMessage"`
	Signed       bool       `xml:"-"` // an enveloped XML signature is present
}

func (m *LogoutMessage) IsRequest() bool { return m.XMLName.Local == "LogoutRequest" }

// StatusText is the status in short form, e.g. "Success" or "Responder / PartialLogout".
func (m *LogoutMessage) StatusText() string {
	s := short(m.Status.Value)
	if m.Status.Sub != nil {
		s += " / " + short(m.Status.Sub.Value)
	}
	return s
}

func (m *LogoutMessage) Success() bool { return m.Status.Value == statusSuccess }

func ParseLogout(b []byte) (*LogoutMessage, error) {
	var m LogoutMessage
	if err := xml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	switch m.XMLName.Local {
	case "LogoutRequest", "LogoutResponse":
	default:
		return nil, fmt.Errorf("expected a LogoutRequest or LogoutResponse, got %s", m.XMLName.Local)
	}
	m.Signed = strings.Contains(string(b), "SignatureValue")
	return &m, nil
}

// VerifyRedirectSignature checks the detached signature of an HTTP-Redirect
// binding message. rawQuery must be the query string exactly as received:
// the signature covers the URL-encoded values, not the decoded ones.
// present is false when the message carries no signature.
func VerifyRedirectSignature(rawQuery string, certs []*x509.Certificate) (present bool, err error) {
	values := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature":
			// A repeated parameter lets the signature cover one copy while
			// the receiver reads another.
			if _, dup := values[k]; dup {
				return true, fmt.Errorf("the %s parameter appears more than once", k)
			}
		}
		values[k] = v
	}
	_, hasReq := values["SAMLRequest"]
	_, hasResp := values["SAMLResponse"]
	sigB64, sigAlg := values["Signature"], values["SigAlg"]
	if hasReq && hasResp {
		return true, errors.New("the message has both SAMLRequest and SAMLResponse")
	}
	if sigB64 == "" {
		return false, nil
	}
	msgKey := "SAMLRequest"
	if _, ok := values["SAMLResponse"]; ok {
		msgKey = "SAMLResponse"
	}
	signed := msgKey + "=" + values[msgKey]
	if rs, ok := values["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + sigAlg

	alg, err := url.QueryUnescape(sigAlg)
	if err != nil {
		return true, err
	}
	rawSig, err := url.QueryUnescape(sigB64)
	if err != nil {
		return true, err
	}
	sig, err := base64.StdEncoding.DecodeString(rawSig)
	if err != nil {
		return true, errors.New("signature is not valid base64")
	}
	var h crypto.Hash
	switch {
	case strings.HasSuffix(alg, "sha1"):
		h = crypto.SHA1
	case strings.HasSuffix(alg, "sha256"):
		h = crypto.SHA256
	case strings.HasSuffix(alg, "sha384"):
		h = crypto.SHA384
	case strings.HasSuffix(alg, "sha512"):
		h = crypto.SHA512
	default:
		return true, fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	hw := h.New()
	hw.Write([]byte(signed))
	digest := hw.Sum(nil)
	for _, c := range certs {
		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if rsa.VerifyPKCS1v15(pub, h, digest, sig) == nil {
				return true, nil
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, digest, sig) {
				return true, nil
			}
		}
	}
	return true, errors.New("signature does not verify with any certificate in the IdP metadata")
}

// VerifyEmbeddedSignature checks an enveloped XML signature on the root of a
// POST-binding message (a LogoutRequest or LogoutResponse).
func VerifyEmbeddedSignature(raw []byte, certs []*x509.Certificate) (present bool, err error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return false, err
	}
	if doc.Root() == nil {
		return false, errors.New("the message has no root element")
	}
	s := verify(doc.Root(), certs)
	if !s.Present {
		return false, nil
	}
	if !s.Valid {
		return true, s.Err
	}
	return true, nil
}
