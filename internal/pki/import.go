package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ParseCertChainPEM decodes every certificate in a PEM blob, in file order.
// pfSense and most other authorities hand out chains exactly this way.
func ParseCertChainPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in chain: %w", err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		// Fall back to raw DER, which is what a .cer export often contains.
		if cert, err := x509.ParseCertificate(data); err == nil {
			return []*x509.Certificate{cert}, nil
		}
		return nil, errors.New("no certificates found; expected PEM CERTIFICATE blocks or DER")
	}
	return out, nil
}

// ValidateCACertificate checks that a certificate is usable as a signing CA.
func ValidateCACertificate(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("no certificate supplied")
	}
	if !cert.IsCA {
		return errors.New("this certificate is not a CA: its basic constraints say CA:FALSE. " +
			"Import the CA certificate, not an end-entity certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("this CA certificate does not carry the keyCertSign usage, " +
			"so it cannot sign certificates")
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("this CA certificate expired on %s", cert.NotAfter.Format("2006-01-02"))
	}
	return nil
}

// IsSelfSigned reports whether a certificate signed itself, i.e. it is a root.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// VerifyIssuedBy checks that child was signed by parent.
func VerifyIssuedBy(child, parent *x509.Certificate) error {
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("%q was not signed by %q: %w",
			DNString(child.Subject), DNString(parent.Subject), err)
	}
	return nil
}

// MatchKeyToCertificate confirms a private key belongs to a certificate and
// returns a friendly error when it does not.
func MatchKeyToCertificate(key crypto.PrivateKey, cert *x509.Certificate) error {
	if err := KeyMatchesCert(key, cert); err != nil {
		return fmt.Errorf("the private key does not belong to this certificate: %w", err)
	}
	return nil
}

// PathLenOf reports the path length constraint of a CA certificate, returning
// -1 when it is unconstrained.
func PathLenOf(cert *x509.Certificate) int {
	if !cert.BasicConstraintsValid {
		return -1
	}
	if cert.MaxPathLenZero {
		return 0
	}
	if cert.MaxPathLen <= 0 {
		return -1
	}
	return cert.MaxPathLen
}

// SubordinateCSRParams describes a request for an external authority to sign.
type SubordinateCSRParams struct {
	Subject Subject
	KeyType KeyType
}

// CreateSubordinateCSR generates a CA key pair and a certificate signing
// request for it. The request is what you hand to pfSense (or any other
// authority); the key never leaves this server.
//
// The CSR carries a basicConstraints CA:TRUE extension request, which is what
// most authorities look at when deciding to issue an intermediate.
func CreateSubordinateCSR(p SubordinateCSRParams) (*CSRResult, error) {
	if err := p.Subject.Validate(); err != nil {
		return nil, err
	}
	kt := p.KeyType
	if kt == "" {
		kt = KeyRSA4096
	}
	key, err := GenerateKey(kt)
	if err != nil {
		return nil, fmt.Errorf("generate subordinate CA key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("generated key does not implement crypto.Signer")
	}

	// Request basicConstraints CA:TRUE and the CA key usages, so an authority
	// that honours extension requests issues an intermediate rather than a
	// leaf. Authorities that ignore them (pfSense asks you to pick a type in
	// its UI) are unaffected.
	exts, err := caExtensionRequests()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:            p.Subject.PKIX(),
		SignatureAlgorithm: signatureAlgorithmFor(key),
		ExtraExtensions:    exts,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("create subordinate CA CSR: %w", err)
	}
	keyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &CSRResult{
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		PrivateKeyPEM: keyPEM,
		PrivateKey:    key,
		KeyType:       kt,
	}, nil
}

// ASN.1 object identifiers for the extensions a CA request carries.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// caExtensionRequests builds critical basicConstraints (CA:TRUE) and keyUsage
// (keyCertSign + cRLSign) extensions for a subordinate CA request.
func caExtensionRequests() ([]pkix.Extension, error) {
	bcValue, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: true})
	if err != nil {
		return nil, fmt.Errorf("encode basicConstraints: %w", err)
	}
	// keyCertSign is bit 5 and cRLSign is bit 6, counted from the most
	// significant bit, so the single value byte is 0b0000_0110 over 7 bits.
	kuValue, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7})
	if err != nil {
		return nil, fmt.Errorf("encode keyUsage: %w", err)
	}
	return []pkix.Extension{
		{Id: oidBasicConstraints, Critical: true, Value: bcValue},
		{Id: oidKeyUsage, Critical: true, Value: kuValue},
	}, nil
}
