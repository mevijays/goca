package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Profile selects the key usage / extended key usage set of an issued
// certificate.
type Profile string

// Supported issuance profiles.
const (
	ProfileServer    Profile = "server"
	ProfileClient    Profile = "client"
	ProfileServerCli Profile = "server-client"
	ProfileCodeSign  Profile = "code-signing"
	ProfileEmail     Profile = "email"
	ProfileIntermCA  Profile = "intermediate-ca"
)

// Profiles lists selectable end-entity profiles in menu order.
var Profiles = []Profile{ProfileServer, ProfileClient, ProfileServerCli, ProfileCodeSign, ProfileEmail}

// ProfileDescriptions powers the help text in the web UI and CLI.
var ProfileDescriptions = map[Profile]string{
	ProfileServer:    "TLS server authentication (websites, APIs, load balancers)",
	ProfileClient:    "TLS client authentication (mutual TLS, VPN, device identity)",
	ProfileServerCli: "Both server and client authentication",
	ProfileCodeSign:  "Code signing",
	ProfileEmail:     "S/MIME email protection",
	ProfileIntermCA:  "Subordinate certificate authority",
}

// ParseProfile normalises profile input.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(s))); p {
	case "":
		return ProfileServer, nil
	case ProfileServer, ProfileClient, ProfileServerCli, ProfileCodeSign, ProfileEmail, ProfileIntermCA:
		return p, nil
	case "both", "server+client", "serverclient":
		return ProfileServerCli, nil
	default:
		return "", fmt.Errorf("unknown profile %q", s)
	}
}

func (p Profile) usages() (x509.KeyUsage, []x509.ExtKeyUsage) {
	switch p {
	case ProfileClient:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case ProfileServerCli:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case ProfileCodeSign:
		return x509.KeyUsageDigitalSignature,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	case ProfileEmail:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
	default: // ProfileServer
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

// CreateCAParams describes a CA to be created.
type CAParams struct {
	Subject Subject
	KeyType KeyType
	Days    int
	// PathLen limits how many further CAs may appear below this one.
	// -1 means unconstrained.
	PathLen int
	// Parent is nil for a self-signed root, otherwise the signing CA.
	Parent    *x509.Certificate
	ParentKey crypto.PrivateKey

	CRLDistPoints []string
	OCSPServers   []string
	// PermittedDNSDomains applies a name constraint (optional).
	PermittedDNSDomains []string
}

// CAResult holds a freshly created CA.
type CAResult struct {
	Certificate   *x509.Certificate
	CertPEM       []byte
	PrivateKey    crypto.PrivateKey
	PrivateKeyPEM []byte
	KeyType       KeyType
	SerialHex     string
	Fingerprint   string
}

// CreateCA builds a self-signed root or a subordinate CA certificate.
func CreateCA(p CAParams) (*CAResult, error) {
	if err := p.Subject.Validate(); err != nil {
		return nil, err
	}
	if p.Days <= 0 {
		p.Days = 3650
	}
	kt := p.KeyType
	if kt == "" {
		kt = KeyRSA4096
	}
	key, err := GenerateKey(kt)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	pub, err := PublicKeyOf(key)
	if err != nil {
		return nil, err
	}
	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               p.Subject.PKIX(),
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, p.Days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		CRLDistributionPoints: p.CRLDistPoints,
		OCSPServer:            p.OCSPServers,
	}
	if p.PathLen >= 0 {
		tmpl.MaxPathLen = p.PathLen
		tmpl.MaxPathLenZero = p.PathLen == 0
	}
	if len(p.PermittedDNSDomains) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = p.PermittedDNSDomains
	}
	if ski, err := subjectKeyID(pub); err == nil {
		tmpl.SubjectKeyId = ski
	}

	issuer := tmpl
	issuerKey := key
	if p.Parent != nil {
		if p.ParentKey == nil {
			return nil, errors.New("parent CA private key is required to sign an intermediate")
		}
		issuer = p.Parent
		issuerKey = p.ParentKey
		if tmpl.NotAfter.After(p.Parent.NotAfter) {
			return nil, fmt.Errorf("requested validity (%s) outruns the parent CA, which expires %s",
				tmpl.NotAfter.Format("2006-01-02"), p.Parent.NotAfter.Format("2006-01-02"))
		}
	}
	tmpl.SignatureAlgorithm = signatureAlgorithmFor(issuerKey)

	signer, ok := issuerKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("issuer key does not implement crypto.Signer")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	return &CAResult{
		Certificate:   cert,
		CertPEM:       EncodeCertPEM(der),
		PrivateKey:    key,
		PrivateKeyPEM: keyPEM,
		KeyType:       kt,
		SerialHex:     SerialHex(serial),
		Fingerprint:   FingerprintSHA256(der),
	}, nil
}

// SignParams describes an issuance from an existing CSR.
type SignParams struct {
	CSR       *x509.CertificateRequest
	Issuer    *x509.Certificate
	IssuerKey crypto.PrivateKey
	Profile   Profile
	Days      int
	// SANOverride replaces the SANs carried in the CSR when non-empty.
	SANOverride *SANSet
	// SubjectOverride replaces the CSR subject when non-nil.
	SubjectOverride *Subject

	CRLDistPoints []string
	OCSPServers   []string
	// PathLen is only used for the intermediate-ca profile.
	PathLen int
}

// SignResult holds an issued certificate.
type SignResult struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	SerialHex   string
	Fingerprint string
}

// Sign issues a certificate for a CSR using the given CA.
func Sign(p SignParams) (*SignResult, error) {
	if p.CSR == nil {
		return nil, errors.New("no CSR supplied")
	}
	if p.Issuer == nil || p.IssuerKey == nil {
		return nil, errors.New("issuer certificate and key are required")
	}
	if !p.Issuer.IsCA {
		return nil, errors.New("issuer certificate is not a CA")
	}
	if time.Now().After(p.Issuer.NotAfter) {
		return nil, fmt.Errorf("issuing CA expired on %s", p.Issuer.NotAfter.Format("2006-01-02"))
	}
	if p.Days <= 0 {
		p.Days = 397
	}
	profile := p.Profile
	if profile == "" {
		profile = ProfileServer
	}

	subject := p.CSR.Subject
	if p.SubjectOverride != nil {
		subject = p.SubjectOverride.PKIX()
	}
	sans := SANSet{
		DNS:    p.CSR.DNSNames,
		IPs:    p.CSR.IPAddresses,
		Emails: p.CSR.EmailAddresses,
		URIs:   p.CSR.URIs,
	}
	if p.SANOverride != nil {
		sans = *p.SANOverride
	}
	// A server certificate with no SANs is rejected by every modern client;
	// promote the CN when it looks like a hostname or IP.
	if sans.Empty() && subject.CommonName != "" &&
		(profile == ProfileServer || profile == ProfileServerCli) {
		promoted, err := ParseSANs([]string{subject.CommonName})
		if err == nil {
			sans = promoted
		}
	}

	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	notAfter := now.AddDate(0, 0, p.Days)
	if notAfter.After(p.Issuer.NotAfter) {
		return nil, fmt.Errorf("requested validity ends %s but the issuing CA expires %s; "+
			"choose a shorter lifetime", notAfter.Format("2006-01-02"), p.Issuer.NotAfter.Format("2006-01-02"))
	}

	ku, eku := profile.usages()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		DNSNames:              sans.DNS,
		IPAddresses:           sans.IPs,
		EmailAddresses:        sans.Emails,
		URIs:                  sans.URIs,
		CRLDistributionPoints: p.CRLDistPoints,
		OCSPServer:            p.OCSPServers,
		SignatureAlgorithm:    signatureAlgorithmFor(p.IssuerKey),
	}
	if profile == ProfileIntermCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = nil
		tmpl.MaxPathLen = p.PathLen
		tmpl.MaxPathLenZero = p.PathLen == 0
	}
	if ski, err := subjectKeyID(p.CSR.PublicKey); err == nil {
		tmpl.SubjectKeyId = ski
	}

	signer, ok := p.IssuerKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("issuer key does not implement crypto.Signer")
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.Issuer, p.CSR.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &SignResult{
		Certificate: cert,
		CertPEM:     EncodeCertPEM(der),
		SerialHex:   SerialHex(serial),
		Fingerprint: FingerprintSHA256(der),
	}, nil
}

// NewSerial returns a cryptographically random positive 128-bit serial.
func NewSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	// Avoid a zero serial, which some parsers reject.
	return n.Add(n, big.NewInt(1)), nil
}

// SerialHex renders a serial as uppercase hex, zero padded to a byte boundary.
func SerialHex(n *big.Int) string {
	s := strings.ToUpper(n.Text(16))
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

// SerialFromHex parses a hex serial, tolerating colons and 0x prefixes.
func SerialFromHex(s string) (*big.Int, bool) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	s = strings.ReplaceAll(s, ":", "")
	n, ok := new(big.Int).SetString(s, 16)
	return n, ok
}

// FingerprintSHA256 renders a colon-separated SHA-256 fingerprint of DER bytes.
func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	hexs := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexs); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexs[i : i+2])
	}
	return b.String()
}

// subjectKeyID computes the RFC 5280 method-1 key identifier: SHA-1 over the
// BIT STRING contents of the SubjectPublicKeyInfo (not the whole structure).
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}
