package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CertInfo is a display-friendly summary of an X.509 certificate.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	CommonName         string    `json:"common_name"`
	Serial             string    `json:"serial"`
	SANs               []string  `json:"sans"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsCA               bool      `json:"is_ca"`
	KeyType            string    `json:"key_type"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyUsage           []string  `json:"key_usage"`
	ExtKeyUsage        []string  `json:"ext_key_usage"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	SubjectKeyID       string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string    `json:"authority_key_id,omitempty"`
	CRLDistPoints      []string  `json:"crl_distribution_points,omitempty"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	DaysRemaining      int       `json:"days_remaining"`
}

// Describe summarises a parsed certificate.
func Describe(c *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:            DNString(c.Subject),
		Issuer:             DNString(c.Issuer),
		CommonName:         c.Subject.CommonName,
		Serial:             SerialHex(c.SerialNumber),
		SANs:               sanStringsFrom(c.DNSNames, c.IPAddresses, c.EmailAddresses, c.URIs),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		IsCA:               c.IsCA,
		KeyType:            string(KeyTypeOf(c.PublicKey)),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		KeyUsage:           keyUsageNames(c.KeyUsage),
		ExtKeyUsage:        extKeyUsageNames(c.ExtKeyUsage),
		FingerprintSHA256:  FingerprintSHA256(c.Raw),
		SubjectKeyID:       hexColons(c.SubjectKeyId),
		AuthorityKeyID:     hexColons(c.AuthorityKeyId),
		CRLDistPoints:      c.CRLDistributionPoints,
		OCSPServers:        c.OCSPServer,
		DaysRemaining:      int(time.Until(c.NotAfter).Hours() / 24),
	}
}

func keyUsageNames(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var out []string
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageNames(us []x509.ExtKeyUsage) []string {
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	}
	var out []string
	for _, u := range us {
		if n, ok := m[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("ext(%d)", u))
		}
	}
	return out
}

func hexColons(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

// BuildPKCS12 packages a leaf certificate, its key and the CA chain into a
// password-protected .p12 file for browsers and mobile devices.
func BuildPKCS12(key crypto.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, password string) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("a private key is required to build a PKCS#12 bundle")
	}
	return pkcs12.Modern.Encode(key, leaf, chain, password)
}

// VerifyChain checks that leaf chains up to root through the given intermediates.
func VerifyChain(leaf *x509.Certificate, intermediates, roots []*x509.Certificate) error {
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	inter := x509.NewCertPool()
	for _, i := range intermediates {
		inter.AddCert(i)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func normalise(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "_", "").Replace(strings.TrimSpace(s)))
}
