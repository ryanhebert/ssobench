package saml

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// XML signature wrapping (XSW): the response keeps a validly signed
// assertion for alice somewhere, and adds an unsigned or altered one for
// mallory where a careless SP reads. SSOBench must never accept mallory's,
// and must fail the sign-in. The shapes follow Somorovsky et al., "On
// Breaking SAML" (2012).
func TestSignatureWrapping(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	c := cert(t, ks)

	// evil is a copy of the signed assertion naming mallory, without its
	// signature unless keepSig.
	evil := func(signed *etree.Element, id string, keepSig bool) *etree.Element {
		e := signed.Copy()
		if !keepSig {
			for _, s := range children(e, "Signature") {
				e.RemoveChild(s)
			}
		}
		for _, n := range descendants(e, "NameID", true) {
			n.SetText("mallory@example.com")
		}
		e.CreateAttr("ID", id)
		return e
	}
	extensions := func(root *etree.Element) *etree.Element {
		x := etree.NewElement("samlp:Extensions")
		root.InsertChildAt(1, x) // after Issuer
		return x
	}

	for _, v := range []struct {
		name  string
		wrap  func(root, signed *etree.Element)
		count bool // only the assertion count gives it away
	}{
		{"unsigned assertion before the signed one, same ID", func(root, signed *etree.Element) {
			root.InsertChildAt(signed.Index(), evil(signed, "_a1", false))
		}, false},
		{"unsigned assertion before the signed one, new ID", func(root, signed *etree.Element) {
			root.InsertChildAt(signed.Index(), evil(signed, "_evil", false))
		}, false},
		{"signed assertion nested inside the evil one", func(root, signed *etree.Element) {
			e := evil(signed, "_evil", false)
			root.RemoveChild(signed)
			e.AddChild(signed)
			root.AddChild(e)
		}, false},
		{"evil assertion carries the original signature, original moved to Extensions", func(root, signed *etree.Element) {
			e := evil(signed, "_a1", true)
			root.RemoveChild(signed)
			extensions(root).AddChild(signed)
			root.AddChild(e)
		}, false},
		{"original moved to Extensions, unsigned evil in its place", func(root, signed *etree.Element) {
			e := evil(signed, "_a1", false)
			root.RemoveChild(signed)
			extensions(root).AddChild(signed)
			root.AddChild(e)
		}, false},
		{"evil assertion carries the signature, original nested in its signature Object", func(root, signed *etree.Element) {
			e := evil(signed, "_a1", true)
			obj := etree.NewElement("ds:Object")
			children(e, "Signature")[0].AddChild(obj)
			root.RemoveChild(signed)
			obj.AddChild(signed)
			root.AddChild(e)
		}, false},
		{"unsigned assertion after the signed one", func(root, signed *etree.Element) {
			root.AddChild(evil(signed, "_evil", false))
		}, true},
	} {
		t.Run(v.name, func(t *testing.T) {
			doc := etree.NewDocument()
			if err := doc.ReadFromBytes(build(t, ks, sp.EntityID, false)); err != nil {
				t.Fatal(err)
			}
			root := doc.Root()
			v.wrap(root, children(root, "Assertion")[0])
			raw, _ := doc.WriteToBytes()

			rep := inspectWith(t, raw, Expect{}, c)
			if rep.Verified && rep.Assertion.Subject.NameID.Value == "mallory@example.com" {
				t.Fatal("accepted the wrapped assertion for mallory as verified")
			}
			f := failures(rep.Checks)
			if len(f) == 0 {
				t.Fatal("no failure: the sign-in would pass")
			}
			if v.count && !strings.Contains(strings.Join(f, "\n"), "Assertion count") {
				t.Errorf("expected the assertion count to be flagged: %v", f)
			}
		})
	}
}

// A comment inside a signed value does not change the signature (exclusive
// C14N drops comments), so a reader that stops at the first text node sees
// alice@example.com where the IdP signed alice@example.com.evil.com
// (CVE-2017-11427 and relatives). SSOBench must read the whole value.
func TestCommentInSignedValue(t *testing.T) {
	ks := dsig.RandomKeyStoreForTest()
	ad := etree.NewDocument()
	xml := strings.Replace(assertionXML(sp.EntityID),
		">alice@example.com</saml:NameID>", ">alice@example.com<!---->.evil.com</saml:NameID>", 1)
	if err := ad.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(ad.Root())
	if err != nil {
		t.Fatal(err)
	}
	rd := etree.NewDocument()
	rd.ReadFromString(fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="_req1"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`,
		now.Format(time.RFC3339), sp.ACSURL, idpID))
	rd.Root().AddChild(signed)
	raw, _ := rd.WriteToBytes()

	rep := inspectWith(t, raw, Expect{}, cert(t, ks))
	if !rep.Verified {
		t.Fatalf("not verified: %v", failures(rep.Checks))
	}
	if got := rep.Assertion.Subject.NameID.Value; got != "alice@example.com.evil.com" {
		t.Fatalf("NameID read as %q, want the whole signed value alice@example.com.evil.com", got)
	}
}
