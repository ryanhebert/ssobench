package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SigAlgRSASHA256 is the signature algorithm SSOBench signs with.
const SigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// Signer is a service provider's signing key and its self-signed
// certificate, published in the SP metadata.
type Signer struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// NewSigner creates a 2048-bit RSA signing key and a ten-year self-signed
// certificate for it, returned as PEM for storage.
func NewSigner(commonName string) (*Signer, []byte, []byte, error) {
	return newKeyPair(commonName, x509.KeyUsageDigitalSignature)
}

// NewEncryptionKey is NewSigner for a key that identity providers encrypt
// assertions to.
func NewEncryptionKey(commonName string) (*Signer, []byte, []byte, error) {
	return newKeyPair(commonName, x509.KeyUsageKeyEncipherment|x509.KeyUsageDataEncipherment)
}

func newKeyPair(commonName string, usage x509.KeyUsage) (*Signer, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &Signer{Key: key, Cert: cert}, keyPEM, certPEM, nil
}

// LoadSigner reads a signer stored as PEM.
func LoadSigner(keyPEM, certPEM []byte) (*Signer, error) {
	kb, _ := pem.Decode(keyPEM)
	cb, _ := pem.Decode(certPEM)
	if kb == nil || cb == nil {
		return nil, errors.New("signing key or certificate is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	return &Signer{Key: key, Cert: cert}, nil
}

// CertBase64 is the certificate as it appears in metadata.
func (s *Signer) CertBase64() string { return base64.StdEncoding.EncodeToString(s.Cert.Raw) }

// CertPEM is the certificate for download.
func (s *Signer) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
}

// EncodeRedirectSigned encodes msg for the HTTP-Redirect binding and signs
// it: the signature covers "param=...&RelayState=...&SigAlg=..." exactly as
// it appears in the URL (SAML bindings, section 3.4.4.1).
func EncodeRedirectSigned(destination, param string, msg []byte, relayState string, s *Signer) (string, error) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write(msg)
	w.Close()
	signed := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		signed += "&RelayState=" + url.QueryEscape(relayState)
	}
	signed += "&SigAlg=" + url.QueryEscape(SigAlgRSASHA256)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	sep := "?"
	if strings.Contains(destination, "?") {
		sep = "&"
	}
	return destination + sep + signed + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), nil
}

// SignEnveloped signs a SAML protocol message for the HTTP-POST binding,
// placing the signature right after the Issuer as the schema requires.
func (s *Signer) SignEnveloped(msg []byte) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(msg); err != nil {
		return nil, err
	}
	ks := dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{s.Cert.Raw}, PrivateKey: s.Key})
	ctx := dsig.NewDefaultSigningContext(ks)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	root := doc.Root()
	sig, err := ctx.ConstructSignature(root, true)
	if err != nil {
		return nil, err
	}
	if iss := child(root, "Issuer"); iss != nil {
		root.InsertChildAt(iss.Index()+1, sig)
	} else {
		root.AddChild(sig)
	}
	signed := root
	doc.SetRoot(signed)
	return doc.WriteToBytes()
}
