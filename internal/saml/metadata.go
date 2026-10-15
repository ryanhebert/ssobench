// Package saml is a minimal SAML 2.0 service provider: it sends unsigned
// AuthnRequests, receives POST-binding responses, verifies XML signatures
// with goxmldsig, and explains every check it runs.
package saml

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
)

const (
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

var HTTPClient = &http.Client{Timeout: 15 * time.Second}

// IdP is what we need from the identity provider's metadata.
type IdP struct {
	EntityID    string
	SSORedirect string
	SSOPost     string
	SLORedirect string // SingleLogoutService locations, if the IdP has them
	SLOPost     string
	Certs       []*x509.Certificate
}

func FetchMetadata(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// ParseMetadata reads the first IdP EntityDescriptor, also inside an
// EntitiesDescriptor aggregate.
func ParseMetadata(b []byte) (*IdP, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil {
		return nil, fmt.Errorf("metadata is not valid XML: %w", err)
	}
	if doc.Root() == nil {
		return nil, errors.New("metadata is empty")
	}
	for _, ed := range descendants(doc.Root(), "EntityDescriptor", true) {
		sso := child(ed, "IDPSSODescriptor")
		if sso == nil {
			continue
		}
		idp := &IdP{EntityID: ed.SelectAttrValue("entityID", "")}
		for _, s := range children(sso, "SingleSignOnService") {
			switch s.SelectAttrValue("Binding", "") {
			case BindingRedirect:
				idp.SSORedirect = s.SelectAttrValue("Location", "")
			case BindingPOST:
				idp.SSOPost = s.SelectAttrValue("Location", "")
			}
		}
		for _, s := range children(sso, "SingleLogoutService") {
			switch s.SelectAttrValue("Binding", "") {
			case BindingRedirect:
				idp.SLORedirect = s.SelectAttrValue("Location", "")
			case BindingPOST:
				idp.SLOPost = s.SelectAttrValue("Location", "")
			}
		}
		for _, kd := range children(sso, "KeyDescriptor") {
			if use := kd.SelectAttrValue("use", ""); use != "" && use != "signing" {
				continue
			}
			for _, xc := range descendants(kd, "X509Certificate", false) {
				c, err := ParseCertB64(xc.Text())
				if err != nil {
					return nil, fmt.Errorf("signing certificate in metadata: %w", err)
				}
				idp.Certs = append(idp.Certs, c)
			}
		}
		if idp.SSORedirect == "" && idp.SSOPost == "" {
			return nil, errors.New("IDPSSODescriptor has no HTTP-Redirect or HTTP-POST SingleSignOnService")
		}
		if len(idp.Certs) == 0 {
			return nil, errors.New("IDPSSODescriptor has no signing certificate")
		}
		return idp, nil
	}
	return nil, errors.New("no EntityDescriptor with an IDPSSODescriptor found (is this SP metadata?)")
}

func ParseCertB64(s string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// Thumbprints formats a certificate as subject plus SHA-1 (what Windows and
// AD FS display) and SHA-256 fingerprints.
func Thumbprints(c *x509.Certificate) string {
	s1 := sha1.Sum(c.Raw)
	s256 := sha256.Sum256(c.Raw)
	fp := fmt.Sprintf("SHA-1 %s, SHA-256 %s…", strings.ToUpper(hex.EncodeToString(s1[:])), strings.ToUpper(hex.EncodeToString(s256[:8])))
	if subj := c.Subject.String(); subj != "" {
		return subj + ", " + fp
	}
	return fp
}

// The helpers below match on local names so any namespace prefix works.

func children(e *etree.Element, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range e.ChildElements() {
		if c.Tag == tag {
			out = append(out, c)
		}
	}
	return out
}

func child(e *etree.Element, tag string) *etree.Element {
	if cs := children(e, tag); len(cs) > 0 {
		return cs[0]
	}
	return nil
}

func descendants(e *etree.Element, tag string, self bool) []*etree.Element {
	var out []*etree.Element
	if self && e.Tag == tag {
		out = append(out, e)
	}
	for _, c := range e.ChildElements() {
		out = append(out, descendants(c, tag, true)...)
	}
	return out
}
