package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ryanhebert/ssobench/internal/check"
)

type Response struct {
	XMLName      xml.Name
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
	Destination  string `xml:"Destination,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Issuer       string `xml:"Issuer"`
	Status       struct {
		Code    StatusCode `xml:"StatusCode"`
		Message string     `xml:"StatusMessage"`
	} `xml:"Status"`
	Assertions []Assertion `xml:"Assertion"`
}

type StatusCode struct {
	Value string      `xml:"Value,attr"`
	Sub   *StatusCode `xml:"StatusCode"`
}

type Assertion struct {
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Issuer       string `xml:"Issuer"`
	Subject      struct {
		NameID        NameID                `xml:"NameID"`
		Confirmations []SubjectConfirmation `xml:"SubjectConfirmation"`
	} `xml:"Subject"`
	Conditions *struct {
		NotBefore        string    `xml:"NotBefore,attr"`
		NotOnOrAfter     string    `xml:"NotOnOrAfter,attr"`
		Audiences        []string  `xml:"AudienceRestriction>Audience"`
		OneTimeUse       *struct{} `xml:"OneTimeUse"`
		ProxyRestriction *struct {
			Count     string   `xml:"Count,attr"`
			Audiences []string `xml:"Audience"`
		} `xml:"ProxyRestriction"`
	} `xml:"Conditions"`
	AuthnStatements []struct {
		AuthnInstant        string   `xml:"AuthnInstant,attr"`
		SessionIndex        string   `xml:"SessionIndex,attr"`
		SessionNotOnOrAfter string   `xml:"SessionNotOnOrAfter,attr"`
		ClassRef            string   `xml:"AuthnContext>AuthnContextClassRef"`
		DeclRef             string   `xml:"AuthnContext>AuthnContextDeclRef"`
		Authorities         []string `xml:"AuthnContext>AuthenticatingAuthority"`
		Locality            *struct {
			Address string `xml:"Address,attr"`
			DNSName string `xml:"DNSName,attr"`
		} `xml:"SubjectLocality"`
	} `xml:"AuthnStatement"`
	Attributes []Attribute `xml:"AttributeStatement>Attribute"`
}

type NameID struct {
	Format          string `xml:"Format,attr"`
	NameQualifier   string `xml:"NameQualifier,attr"`
	SPNameQualifier string `xml:"SPNameQualifier,attr"`
	Value           string `xml:",chardata"`
}

type SubjectConfirmation struct {
	Method string `xml:"Method,attr"`
	Data   struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
		Recipient    string `xml:"Recipient,attr"`
		InResponseTo string `xml:"InResponseTo,attr"`
		Address      string `xml:"Address,attr"`
	} `xml:"SubjectConfirmationData"`
}

type Attribute struct {
	Name         string   `xml:"Name,attr"`
	FriendlyName string   `xml:"FriendlyName,attr"`
	NameFormat   string   `xml:"NameFormat,attr"`
	Values       []string `xml:"AttributeValue"`
}

const statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// Expect is what the service provider knows when a response arrives.
type Expect struct {
	SP SP
	// Alt is the same service provider reached at another address: the one
	// the response arrived at, when the sign-in started elsewhere. Its
	// entity ID and ACS URL are accepted too.
	Alt *SP
	IdP *IdP
	// RequestKnown reports whether id is an AuthnRequest we sent.
	RequestKnown func(id string) bool
	// AssertionSeen records id and reports whether it was seen before.
	AssertionSeen func(id string) bool
	// DecryptKey decrypts encrypted assertions; nil when the app has no
	// encryption key. WantEncrypted fails an unencrypted assertion.
	DecryptKey    *rsa.PrivateKey
	WantEncrypted bool
	Now           time.Time
	Skew          time.Duration
}

type Report struct {
	Response  *Response
	Assertion *Assertion // the assertion the checks ran on
	Verified  bool       // Assertion came out of a valid signature
	Checks    []check.Result
	// SigLog describes each signature verification attempt, for the log.
	SigLog []string
	// UnknownSigner is set when a signature names a certificate that is not
	// in the metadata: usually the IdP rotated its signing certificate.
	UnknownSigner bool
	// Encrypted describes the assertion's encryption, when it had one;
	// DecryptedXML is the assertion after decryption.
	Encrypted    *EncInfo
	DecryptedXML string
	// DecryptProblem is why decryption failed, for the operator's terminal
	// only: pages show ErrUndecryptable (see encrypt.go).
	DecryptProblem string
}

// ParseResponse decodes a Response without verifying anything.
func ParseResponse(b []byte) (*Response, error) {
	var r Response
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.XMLName.Local != "Response" {
		return nil, fmt.Errorf("this is a SAML %s, not a Response", r.XMLName.Local)
	}
	return &r, nil
}

// Inspect verifies and checks a SAML Response. Only signed content is
// trusted for the checks; when nothing verifies, the checks still run on the
// unverified content so the remaining problems are visible too.
func Inspect(raw []byte, e Expect) (*Report, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("response is not valid XML: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" {
		return nil, errors.New("XML root is not a SAML Response")
	}
	resp, err := ParseResponse(raw)
	if err != nil {
		return nil, err
	}
	rep := &Report{Response: resp}
	add := func(r check.Result) { rep.Checks = append(rep.Checks, r) }
	now := e.Now

	// Status first: a failed login has no assertion to check.
	code := resp.Status.Code
	if code.Value == statusSuccess {
		add(check.OK("Status", "Success"))
	} else {
		detail := short(code.Value)
		if code.Sub != nil {
			detail += " / " + short(code.Sub.Value)
		}
		if resp.Status.Message != "" {
			detail += ": " + resp.Status.Message
		}
		fix := "The identity provider refused the login. Check the identity provider's event log for the reason."
		if code.Sub != nil {
			if f, ok := statusFixes[short(code.Sub.Value)]; ok {
				fix = f
			}
		}
		add(check.Bad("Status", detail, fix))
	}

	assertEls := children(root, "Assertion")
	if encEls := children(root, "EncryptedAssertion"); len(encEls) > 0 {
		if el := decryptInto(rep, encEls[0], e.DecryptKey, add); el != nil {
			var a Assertion
			if err := unmarshalEl(el, &a); err == nil {
				assertEls = append(assertEls, el)
				resp.Assertions = append(resp.Assertions, a)
			}
		}
		if len(encEls) > 1 {
			add(check.Bad("Assertion count", fmt.Sprintf("%d encrypted assertions; only the first is checked", len(encEls)),
				"Multiple assertions are unusual and a common shape of signature-wrapping attacks."))
		}
	} else if e.WantEncrypted && len(assertEls) > 0 {
		add(check.Bad("Assertion encryption", "the assertion arrived unencrypted",
			"Turn on assertion encryption for this app at the identity provider, with this app's encryption certificate from Set up."))
	}
	if len(assertEls) == 0 {
		if code.Value == statusSuccess {
			add(check.Bad("Assertion", "the response contains no readable assertion", "The identity provider sent Success without an assertion."))
		}
		return rep, nil
	}
	if len(assertEls) > 1 {
		add(check.Bad("Assertion count", fmt.Sprintf("%d assertions; only the first is checked", len(assertEls)),
			"Multiple assertions are unusual and a common shape of signature-wrapping attacks."))
	}

	respSig := verify(root, e.IdP.Certs)
	asrtSig := verify(assertEls[0], e.IdP.Certs)
	for _, x := range []struct {
		where string
		s     sigInfo
	}{{"Response", respSig}, {"Assertion", asrtSig}} {
		if !x.s.Present {
			rep.SigLog = append(rep.SigLog, x.where+": no signature")
			continue
		}
		head := fmt.Sprintf("%s: signature %s, digest %s", x.where, short(x.s.SigAlg), short(x.s.DigestAlg))
		if x.s.KeyInfoCert != nil {
			head += "; embedded certificate " + Thumbprints(x.s.KeyInfoCert)
		}
		rep.SigLog = append(rep.SigLog, head)
		for _, a := range x.s.Attempts {
			rep.SigLog = append(rep.SigLog, "  "+a)
		}
	}
	addSig := func(where string, s sigInfo) {
		switch {
		case !s.Present:
			add(check.Note(where+" signature", "not signed"))
		case s.Valid:
			add(check.OK(where+" signature", "valid, signed by "+certName(s.Cert)))
		default:
			add(sigFailure(where, s, e.IdP.Certs))
		}
	}
	addSig("Response", respSig)
	addSig("Assertion", asrtSig)
	for _, x := range []sigInfo{respSig, asrtSig} {
		if x.Present && !x.Valid && x.KeyInfoCert != nil && !slices.ContainsFunc(e.IdP.Certs, x.KeyInfoCert.Equal) {
			rep.UnknownSigner = true
		}
	}

	// Pick the content the checks are allowed to trust.
	trusted := &resp.Assertions[0]
	switch {
	case asrtSig.Valid:
		var a Assertion
		if err := unmarshalEl(asrtSig.Validated, &a); err == nil {
			trusted, rep.Verified = &a, true
		}
	case respSig.Valid:
		var r Response
		if err := unmarshalEl(respSig.Validated, &r); err == nil && len(r.Assertions) > 0 {
			trusted, rep.Verified = &r.Assertions[0], true
		} else if enc := children(respSig.Validated, "EncryptedAssertion"); len(enc) > 0 && e.DecryptKey != nil {
			// The signature covers the encrypted assertion: decrypt the
			// signed copy, not the one in the document.
			if el, _, err := DecryptAssertion(enc[0], e.DecryptKey); err == nil {
				var a Assertion
				if unmarshalEl(el, &a) == nil {
					trusted, rep.Verified = &a, true
				}
			}
		}
	}
	rep.Assertion = trusted
	if !rep.Verified {
		add(check.Bad("Trust", "no valid signature covers the assertion; the checks below use unverified data",
			"An SP must reject this response. Fix the signature problem above first."))
	}

	for _, s := range []sigInfo{respSig, asrtSig} {
		if s.Present && (strings.Contains(s.SigAlg, "sha1") || strings.Contains(s.DigestAlg, "sha1")) {
			add(check.Meh("Algorithms", fmt.Sprintf("SHA-1 in use (signature %s, digest %s)", short(s.SigAlg), short(s.DigestAlg)),
				"SHA-1 is deprecated and rejected by many SPs. Switch the relying party to SHA-256 at the identity provider."))
			break
		}
	}
	signer := asrtSig.Cert
	if signer == nil {
		signer = respSig.Cert
	}
	if signer != nil {
		switch {
		case now.After(signer.NotAfter):
			add(check.Meh("Signing certificate", "expired "+check.When(signer.NotAfter, now),
				"The signature itself is valid, but many SPs reject expired certificates. Renew the identity provider's token-signing certificate and update SP metadata."))
		case signer.NotAfter.Sub(now) < 30*24*time.Hour:
			add(check.Meh("Signing certificate", "expires "+check.When(signer.NotAfter, now),
				"Plan the certificate rollover and update every SP that pins this certificate."))
		default:
			add(check.OK("Signing certificate", "valid until "+signer.NotAfter.UTC().Format("Jan 2, 2006")))
		}
	}

	if trusted.Issuer == e.IdP.EntityID {
		add(check.OK("Issuer", trusted.Issuer))
	} else {
		add(check.Bad("Issuer", "the assertion comes from a different identity provider than the metadata",
			"The assertion came from a different identity provider than the metadata you loaded"+nearMiss(trusted.Issuer, e.IdP.EntityID)+".").Mismatch(trusted.Issuer, e.IdP.EntityID))
	}

	switch {
	case resp.Destination == "" && respSig.Present:
		add(check.Bad("Destination", "not set on a signed response",
			"A signed response must say where it is going (SAML bindings, section 3.5.5.2), so it can't be posted to another service provider. Configure the identity provider to include Destination."))
	case resp.Destination == "":
		add(check.Note("Destination", "not set (allowed because the response itself is unsigned)"))
	case resp.Destination == e.SP.ACSURL:
		add(check.OK("Destination", resp.Destination))
	case e.Alt != nil && resp.Destination == e.Alt.ACSURL:
		add(check.OK("Destination", resp.Destination+" (the address the response arrived at)"))
	default:
		add(check.Bad("Destination", "the response was addressed to a different ACS URL",
			"Set the ACS URL at the identity provider to exactly this app's ACS URL"+nearMiss(resp.Destination, e.SP.ACSURL)+".").Mismatch(resp.Destination, e.SP.ACSURL))
	}

	switch {
	case resp.InResponseTo == "":
		add(check.Meh("InResponseTo", "empty: IdP-initiated login",
			"Fine for testing, but IdP-initiated SSO cannot be tied to a request and is easier to replay."))
	case e.RequestKnown != nil && e.RequestKnown(resp.InResponseTo):
		add(check.OK("InResponseTo", "matches a request this SP sent"))
	default:
		add(check.Bad("InResponseTo", fmt.Sprintf("%q is not a request this SP sent", resp.InResponseTo),
			"The request expired, this tool was restarted, or the login was started from another SP."))
	}

	if c := trusted.Conditions; c == nil {
		add(check.Meh("Conditions", "no Conditions element", "Without Conditions there is no audience or lifetime restriction."))
	} else {
		if len(c.Audiences) == 0 {
			add(check.Meh("Audience", "no audience restriction, so any service provider would accept this assertion",
				"Configure the identity provider to restrict the assertion to this app's entity ID ("+e.SP.EntityID+")."))
		} else if slices.Contains(c.Audiences, e.SP.EntityID) {
			add(check.OK("Audience", e.SP.EntityID))
		} else if e.Alt != nil && slices.Contains(c.Audiences, e.Alt.EntityID) {
			add(check.OK("Audience", e.Alt.EntityID+" (SSOBench at the address the response arrived at)"))
		} else {
			hint := ""
			for _, a := range c.Audiences {
				hint += nearMiss(a, e.SP.EntityID)
			}
			add(check.Bad("Audience", "the assertion is for a different service provider",
				"Set the entity ID (audience) at the identity provider to exactly this app's entity ID"+hint+".").Mismatch(strings.Join(c.Audiences, "\n"), e.SP.EntityID))
		}
		add(check.Window("Conditions lifetime", parseTime(c.NotBefore), parseTime(c.NotOnOrAfter), now, e.Skew))
	}
	if t := parseTime(trusted.IssueInstant); !t.IsZero() {
		skew := t.Sub(now).Round(time.Second)
		switch {
		case skew > e.Skew:
			add(check.Bad("Clock skew", fmt.Sprintf("assertion issued %s ahead of this machine", check.Human(skew)),
				"Sync this machine and the identity provider with NTP."))
		case -skew > 5*time.Minute:
			add(check.Meh("Issue instant", "issued "+check.When(t, now),
				"Assertions are normally used seconds after they are issued. An old one means clock skew, or a response that was saved and posted again."))
		default:
			add(check.OK("Issue instant", check.When(t, now)))
		}
	}

	bearer := false
	for _, sc := range trusted.Subject.Confirmations {
		if sc.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			continue
		}
		bearer = true
		d := sc.Data
		if d.Recipient != e.SP.ACSURL && (e.Alt == nil || d.Recipient != e.Alt.ACSURL) {
			add(check.Bad("Recipient", "the subject confirmation names a different ACS URL",
				"Set the ACS URL at the identity provider to exactly this app's ACS URL"+nearMiss(d.Recipient, e.SP.ACSURL)+".").Mismatch(d.Recipient, e.SP.ACSURL))
		} else {
			add(check.OK("Recipient", d.Recipient))
		}
		add(check.Window("Subject confirmation lifetime", parseTime(d.NotBefore), parseTime(d.NotOnOrAfter), now, e.Skew))
		if d.NotBefore != "" {
			add(check.Meh("Subject confirmation NotBefore", "set, which the Web SSO profile forbids for bearer confirmations",
				"Some service providers reject the assertion. Remove NotBefore from SubjectConfirmationData at the identity provider; the Conditions element already limits when the assertion is valid."))
		}
		if d.Address != "" {
			add(check.Note("Subject address", d.Address+" (the address the identity provider saw; behind NAT or a proxy it differs from the one SSOBench sees)"))
		}
		if d.InResponseTo != resp.InResponseTo {
			add(check.Bad("Subject InResponseTo", fmt.Sprintf("%q differs from the response's %q", d.InResponseTo, resp.InResponseTo),
				"The assertion was issued for a different request."))
		}
		break
	}
	if !bearer {
		add(check.Bad("Subject confirmation", "no bearer SubjectConfirmation", "Web SSO requires a bearer subject confirmation."))
	}

	if trusted.Subject.NameID.Value == "" {
		add(check.Meh("NameID", "empty", "Most SPs key users on NameID. Configure a NameID claim rule at the identity provider."))
	} else {
		add(check.OK("NameID", trusted.Subject.NameID.Value+" ("+short(trusted.Subject.NameID.Format)+")"))
	}

	if e.AssertionSeen != nil && trusted.ID != "" && e.AssertionSeen(trusted.ID) {
		add(check.Bad("Replay", "this assertion ID was already used", "A browser refresh or back button reposted the response, or it is being replayed."))
	}
	return rep, nil
}

var statusFixes = map[string]string{
	"InvalidNameIDPolicy": "The identity provider cannot produce the NameID format requested. Add a NameID claim rule at the identity provider.",
	"RequestDenied":       "The identity provider denied the request. Check access-control policy for this relying party.",
	"AuthnFailed":         "The user failed authentication at the identity provider.",
	"NoPassive":           "Passive login was requested but the user has no session at the identity provider.",
	"RequestUnsupported":  "The identity provider does not support something in the request. Check its log.",
	"UnknownPrincipal":    "The identity provider does not know this user.",
}

type sigInfo struct {
	Present     bool
	Valid       bool
	Err         error
	Cert        *x509.Certificate // metadata cert that verified the signature
	KeyInfoCert *x509.Certificate // cert embedded in the signature, if any
	SigAlg      string
	DigestAlg   string
	Validated   *etree.Element
	Attempts    []string
}

// verify validates el's enveloped signature against each metadata cert in
// turn. Certificate validity dates are checked separately, so the clock is
// pinned inside each cert's lifetime: an expired cert is a warning about the
// IdP, not a reason to hide whether the signature itself is good.
func verify(el *etree.Element, certs []*x509.Certificate) sigInfo {
	sig := child(el, "Signature")
	if sig == nil {
		return sigInfo{}
	}
	s := sigInfo{Present: true}
	if m := descendants(sig, "SignatureMethod", false); len(m) > 0 {
		s.SigAlg = m[0].SelectAttrValue("Algorithm", "")
	}
	if m := descendants(sig, "DigestMethod", false); len(m) > 0 {
		s.DigestAlg = m[0].SelectAttrValue("Algorithm", "")
	}
	if xc := descendants(sig, "X509Certificate", false); len(xc) > 0 {
		s.KeyInfoCert, _ = ParseCertB64(xc[0].Text())
	}
	detached := detach(el)
	for _, c := range certs {
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{c}})
		ctx.Clock = dsig.NewFakeClockAt(c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) / 2))
		v, err := ctx.Validate(detached)
		if err == nil {
			s.Valid, s.Cert, s.Validated, s.Err = true, c, v, nil
			s.Attempts = append(s.Attempts, "verified with metadata certificate "+certName(c))
			return s
		}
		s.Err = err
		s.Attempts = append(s.Attempts, fmt.Sprintf("metadata certificate %s: %v", certName(c), err))
	}
	return s
}

func sigFailure(where string, s sigInfo, certs []*x509.Certificate) check.Result {
	if s.KeyInfoCert != nil && !slices.ContainsFunc(certs, s.KeyInfoCert.Equal) {
		var have []string
		for _, c := range certs {
			have = append(have, Thumbprints(c))
		}
		return check.Bad(where+" signature",
			fmt.Sprintf("signed with a certificate that is not in the metadata: %s. Metadata has: %s",
				Thumbprints(s.KeyInfoCert), strings.Join(have, "; ")),
			"The identity provider rolled over its token-signing certificate. Reload the identity provider's metadata (or update the pinned certificate).")
	}
	return check.Bad(where+" signature", "invalid: "+s.Err.Error(),
		"The signed content was modified after signing (a proxy or the identity provider re-encoding it), or the wrong certificate is configured.")
}

// detach copies el and re-declares every namespace it inherits from its
// ancestors, so it can be canonicalized on its own. Extra declarations are
// harmless: exclusive C14N drops the ones that are not used.
func detach(el *etree.Element) *etree.Element {
	cp := el.Copy()
	declared := map[string]bool{}
	nsKey := func(a etree.Attr) (string, bool) {
		switch {
		case a.Space == "xmlns":
			return a.Key, true
		case a.Space == "" && a.Key == "xmlns":
			return "", true
		}
		return "", false
	}
	for _, a := range cp.Attr {
		if k, ok := nsKey(a); ok {
			declared[k] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			if k, ok := nsKey(a); ok && !declared[k] {
				cp.CreateAttr(a.FullKey(), a.Value)
				declared[k] = true
			}
		}
	}
	return cp
}

func unmarshalEl(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	b, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(b, v)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	return t
}

// ParseTime is the exported form, for display.
func ParseTime(s string) time.Time { return parseTime(s) }

// short drops a URN or URL prefix: "urn:...:status:Success" -> "Success".
func short(s string) string {
	if i := strings.LastIndexAny(s, ":#"); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}

// Short is the exported form, for display.
func Short(s string) string { return short(s) }

// nearMiss explains the classic near-identical identifier mismatches.
func nearMiss(got, want string) string {
	switch {
	case got == want:
		return ""
	case strings.TrimRight(got, "/") == strings.TrimRight(want, "/"):
		return " (they differ only by a trailing slash)"
	case strings.EqualFold(got, want):
		return " (they differ only by upper/lower case)"
	case strings.Replace(got, "https://", "http://", 1) == strings.Replace(want, "https://", "http://", 1):
		return " (they differ only by http vs https)"
	}
	return ""
}

// certName is the subject, or the SHA-1 thumbprint when the subject is empty.
func certName(c *x509.Certificate) string {
	if s := c.Subject.String(); s != "" {
		return s
	}
	t := Thumbprints(c)
	return t[strings.Index(t, "SHA-1"):strings.Index(t, ", SHA-256")]
}

// decryptInto decrypts an encrypted assertion for rep, reporting how it
// was encrypted, or why it could not be read.
func decryptInto(rep *Report, enc *etree.Element, key *rsa.PrivateKey, add func(check.Result)) *etree.Element {
	if key == nil {
		add(check.Bad("Assertion encryption", "the assertion is encrypted, but this app has no encryption key",
			"Turn on Encrypted assertions in the app's Settings, and give the identity provider the encryption certificate from Set up. Or turn encryption off at the identity provider."))
		return nil
	}
	el, info, err := DecryptAssertion(enc, key)
	if err != nil {
		rep.DecryptProblem = DecryptFailure(err)
		add(check.Bad("Assertion decryption", err.Error(),
			"Encrypt for this app's encryption certificate, under Set up, with AES-GCM or AES-CBC and RSA-OAEP."))
		return nil
	}
	rep.Encrypted = &info
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	doc.Indent(2)
	rep.DecryptedXML, _ = doc.WriteToString()
	if why := info.Legacy(); why != "" {
		add(check.Meh("Assertion encryption", info.String(),
			"Decrypted, but "+why+". Choose AES-GCM with RSA-OAEP at the identity provider."))
	} else {
		add(check.OK("Assertion encryption", info.String()))
	}
	return el
}
