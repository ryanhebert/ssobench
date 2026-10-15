package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// XML Encryption algorithm identifiers.
const (
	EncAES128CBC  = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES192CBC  = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	EncAES256CBC  = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	Enc3DESCBC    = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	EncAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES192GCM  = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	EncAES256GCM  = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	KeyRSAOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyRSAOAEP11  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	KeyRSA15      = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	xmlencNS      = "http://www.w3.org/2001/04/xmlenc#"
	xmlenc11NS    = "http://www.w3.org/2009/xmlenc11#"
	mgf1Prefix    = "http://www.w3.org/2009/xmlenc11#mgf1"
	digestSHA1    = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestSHA256  = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384  = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512  = "http://www.w3.org/2001/04/xmlenc#sha512"
	dsigNamespace = "http://www.w3.org/2000/09/xmldsig#"
)

// EncInfo describes how an assertion was encrypted.
type EncInfo struct {
	DataAlg   string // block cipher, such as AES-256-GCM
	KeyAlg    string // key transport, such as RSA-OAEP
	KeyDigest string // OAEP digest and mask function, such as SHA-256
}

// String is the algorithms in words.
func (e EncInfo) String() string {
	s := e.DataAlg + ", key wrapped with " + e.KeyAlg
	if e.KeyDigest != "" {
		s += " (" + e.KeyDigest + ")"
	}
	return s
}

// Legacy reports why the algorithms are weak, or "".
func (e EncInfo) Legacy() string {
	var why []string
	switch {
	case e.DataAlg == "Triple DES":
		why = append(why, "Triple DES is obsolete")
	case strings.HasSuffix(e.DataAlg, "-CBC"):
		why = append(why, "AES-CBC is open to padding-oracle attacks on XML encryption")
	}
	if e.KeyAlg == "RSA PKCS#1 v1.5" {
		why = append(why, "RSA PKCS#1 v1.5 key transport is open to Bleichenbacher attacks")
	}
	return strings.Join(why, "; ")
}

var dataAlgs = map[string]struct {
	name  string
	key   int
	block bool // CBC; otherwise GCM
	des   bool
}{
	EncAES128CBC: {"AES-128-CBC", 16, true, false},
	EncAES192CBC: {"AES-192-CBC", 24, true, false},
	EncAES256CBC: {"AES-256-CBC", 32, true, false},
	Enc3DESCBC:   {"Triple DES", 24, true, true},
	EncAES128GCM: {"AES-128-GCM", 16, false, false},
	EncAES192GCM: {"AES-192-GCM", 24, false, false},
	EncAES256GCM: {"AES-256-GCM", 32, false, false},
}

var digests = map[string]struct {
	name string
	h    crypto.Hash
}{
	digestSHA1: {"SHA-1", crypto.SHA1}, digestSHA256: {"SHA-256", crypto.SHA256},
	digestSHA384: {"SHA-384", crypto.SHA384}, digestSHA512: {"SHA-512", crypto.SHA512},
}

var mgfs = map[string]crypto.Hash{
	"sha1": crypto.SHA1, "sha224": crypto.SHA224, "sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512,
}

func algOf(el *etree.Element) string {
	if m := child(el, "EncryptionMethod"); m != nil {
		return m.SelectAttrValue("Algorithm", "")
	}
	return ""
}

func cipherValue(el *etree.Element) ([]byte, error) {
	cd := child(el, "CipherData")
	if cd == nil || child(cd, "CipherValue") == nil {
		return nil, errors.New("no CipherValue (CipherReference is not supported)")
	}
	v := strings.Join(strings.Fields(child(cd, "CipherValue").Text()), "")
	return base64.StdEncoding.DecodeString(v)
}

// DecryptAssertion decrypts an EncryptedAssertion element with key and
// returns the assertion as a standalone element, carrying the namespace
// declarations it relied on from the response.
func DecryptAssertion(enc *etree.Element, key *rsa.PrivateKey) (*etree.Element, EncInfo, error) {
	var info EncInfo
	ed := child(enc, "EncryptedData")
	if ed == nil {
		return nil, info, errors.New("no EncryptedData")
	}
	dataAlg := algOf(ed)
	da, ok := dataAlgs[dataAlg]
	if !ok {
		return nil, info, fmt.Errorf("unsupported data encryption algorithm %q", dataAlg)
	}
	info.DataAlg = da.name

	// The encrypted key sits in the data's KeyInfo, or beside it.
	var ek *etree.Element
	if ki := child(ed, "KeyInfo"); ki != nil {
		if found := descendants(ki, "EncryptedKey", false); len(found) > 0 {
			ek = found[0]
		}
	}
	if ek == nil {
		if found := descendants(enc, "EncryptedKey", false); len(found) > 0 {
			ek = found[0]
		}
	}
	if ek == nil {
		return nil, info, errors.New("no EncryptedKey: the key may be agreed another way, which is not supported")
	}
	wrapped, err := cipherValue(ek)
	if err != nil {
		return nil, info, fmt.Errorf("encrypted key: %w", err)
	}
	var cek []byte
	switch keyAlg := algOf(ek); keyAlg {
	case KeyRSAOAEP, KeyRSAOAEP11:
		info.KeyAlg = "RSA-OAEP"
		h := crypto.SHA1
		dname := "SHA-1"
		if m := child(ek, "EncryptionMethod"); m != nil {
			if dm := child(m, "DigestMethod"); dm != nil {
				d, ok := digests[dm.SelectAttrValue("Algorithm", "")]
				if !ok {
					return nil, info, fmt.Errorf("unsupported OAEP digest %q", dm.SelectAttrValue("Algorithm", ""))
				}
				h, dname = d.h, d.name
			}
		}
		mgf := crypto.SHA1
		if keyAlg == KeyRSAOAEP11 {
			if m := child(ek, "EncryptionMethod"); m != nil {
				if mg := child(m, "MGF"); mg != nil {
					a := strings.TrimPrefix(mg.SelectAttrValue("Algorithm", ""), mgf1Prefix)
					if mgf, ok = mgfs[a]; !ok {
						return nil, info, fmt.Errorf("unsupported OAEP mask function %q", mg.SelectAttrValue("Algorithm", ""))
					}
				}
			}
		}
		info.KeyDigest = dname
		if mgf != h {
			info.KeyDigest += ", MGF1 with " + strings.ReplaceAll(mgf.String(), "SHA", "SHA-")
		}
		cek, err = key.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: h, MGFHash: mgf})
	case KeyRSA15:
		info.KeyAlg = "RSA PKCS#1 v1.5"
		cek, err = rsa.DecryptPKCS1v15(rand.Reader, key, wrapped)
	default:
		return nil, info, fmt.Errorf("unsupported key transport algorithm %q", keyAlg)
	}
	if err != nil {
		return nil, info, errors.New("the key could not be decrypted: the assertion was probably encrypted for another certificate")
	}
	if len(cek) != da.key {
		return nil, info, fmt.Errorf("the decrypted key is %d bytes, but %s needs %d", len(cek), da.name, da.key)
	}
	ct, err := cipherValue(ed)
	if err != nil {
		return nil, info, err
	}
	plain, err := decryptData(da.block, da.des, cek, ct)
	if err != nil {
		return nil, info, fmt.Errorf("%s: %w", da.name, err)
	}
	el, err := parseFragment(plain, enc)
	return el, info, err
}

func decryptData(cbc, tripleDES bool, key, ct []byte) ([]byte, error) {
	var block cipher.Block
	var err error
	if tripleDES {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	if !cbc {
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(ct) < gcm.NonceSize()+gcm.Overhead() {
			return nil, errors.New("ciphertext too short")
		}
		out, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
		if err != nil {
			return nil, errors.New("authentication tag does not match")
		}
		return out, nil
	}
	bs := block.BlockSize()
	if len(ct) < 2*bs || len(ct)%bs != 0 {
		return nil, errors.New("ciphertext is not whole blocks")
	}
	out := make([]byte, len(ct)-bs)
	cipher.NewCBCDecrypter(block, ct[:bs]).CryptBlocks(out, ct[bs:])
	// XML Encryption padding: the last byte is the pad length.
	n := int(out[len(out)-1])
	if n < 1 || n > bs {
		return nil, errors.New("bad padding")
	}
	return out[:len(out)-n], nil
}

// parseFragment reads decrypted XML, which may use prefixes declared on
// the response around it, into a standalone element.
func parseFragment(plain []byte, ctx *etree.Element) (*etree.Element, error) {
	ns := map[string]string{}
	for e := ctx; e != nil; e = e.Parent() {
		for _, a := range e.Attr {
			key := ""
			switch {
			case a.Space == "xmlns":
				key = "xmlns:" + a.Key
			case a.Space == "" && a.Key == "xmlns":
				key = "xmlns"
			default:
				continue
			}
			if _, inner := ns[key]; !inner {
				ns[key] = a.Value
			}
		}
	}
	var b bytes.Buffer
	b.WriteString("<w")
	for k, v := range ns {
		fmt.Fprintf(&b, ` %s="%s"`, k, esc(v))
	}
	b.WriteString(">")
	b.Write(bytes.TrimPrefix(bytes.TrimSpace(plain), []byte("\xef\xbb\xbf")))
	b.WriteString("</w>")
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b.Bytes()); err != nil {
		return nil, fmt.Errorf("the decrypted content is not XML: %w", err)
	}
	els := doc.Root().ChildElements()
	if len(els) != 1 || els[0].Tag != "Assertion" {
		return nil, errors.New("the decrypted content is not a single Assertion")
	}
	el := els[0]
	for k, v := range ns {
		if el.SelectAttr(k) == nil {
			el.CreateAttr(k, v)
		}
	}
	out := etree.NewDocument()
	out.SetRoot(el.Copy())
	return out.Root(), nil
}

// EncryptAssertion encrypts assertion XML for cert, as an identity provider
// would, with the given data and key transport algorithms. It returns the
// EncryptedAssertion element as XML. Used by tests and test identity
// providers.
func EncryptAssertion(assertion []byte, pub *rsa.PublicKey, dataAlg, keyAlg string) ([]byte, error) {
	da, ok := dataAlgs[dataAlg]
	if !ok {
		return nil, fmt.Errorf("unsupported data algorithm %q", dataAlg)
	}
	cek := make([]byte, da.key)
	rand.Read(cek)
	var block cipher.Block
	var err error
	if da.des {
		block, err = des.NewTripleDESCipher(cek)
	} else {
		block, err = aes.NewCipher(cek)
	}
	if err != nil {
		return nil, err
	}
	var ct []byte
	if da.block {
		bs := block.BlockSize()
		n := bs - len(assertion)%bs
		padded := append(append([]byte{}, assertion...), bytes.Repeat([]byte{byte(n)}, n)...)
		ct = make([]byte, bs+len(padded))
		rand.Read(ct[:bs])
		cipher.NewCBCEncrypter(block, ct[:bs]).CryptBlocks(ct[bs:], padded)
	} else {
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		ct = gcm.Seal(nonce, nonce, assertion, nil)
	}
	var wrapped []byte
	method := fmt.Sprintf(`<xenc:EncryptionMethod Algorithm="%s"/>`, keyAlg)
	switch keyAlg {
	case KeyRSAOAEP:
		wrapped, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, cek, nil)
		method = fmt.Sprintf(`<xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/></xenc:EncryptionMethod>`, keyAlg, digestSHA1)
	case KeyRSAOAEP11:
		wrapped, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
		method = fmt.Sprintf(`<xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/><xenc11:MGF xmlns:xenc11="%s" Algorithm="%ssha256"/></xenc:EncryptionMethod>`, keyAlg, digestSHA256, xmlenc11NS, mgf1Prefix)
	case KeyRSA15:
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", keyAlg)
	}
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	return []byte(fmt.Sprintf(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><xenc:EncryptedData xmlns:xenc="%s" xmlns:ds="%s" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo><xenc:EncryptedKey>%s<xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`,
		xmlencNS, dsigNamespace, dataAlg, method, b64(wrapped), b64(ct))), nil
}
