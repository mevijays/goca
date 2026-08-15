package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// externalCA stands in for an authority goca does not control - a pfSense CA,
// a corporate root - so the import paths are exercised against a real issuer
// rather than something goca produced itself.
type externalCA struct {
	cert    *x509.Certificate
	key     crypto.PrivateKey
	certPEM string
}

func newExternalCA(t *testing.T, cn string) *externalCA {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyECP256)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := pki.PublicKeyOf(key)
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"External"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &externalCA{cert: cert, key: key, certPEM: string(pki.EncodeCertPEM(der))}
}

// signCSR issues an intermediate CA certificate for a request, the way pfSense
// does when you choose "Sign an intermediate Certificate Authority".
func (e *externalCA) signCSR(t *testing.T, csrPEM string, days int) string {
	t.Helper()
	csr, err := pki.ParseCSR([]byte(csrPEM))
	if err != nil {
		t.Fatalf("external CA could not parse the CSR: %v", err)
	}
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.cert, csr.PublicKey, e.key.(crypto.Signer))
	if err != nil {
		t.Fatalf("external CA could not sign: %v", err)
	}
	return string(pki.EncodeCertPEM(der))
}

// signLeaf issues an end-entity certificate, used to prove a leaf is refused
// where a CA is required.
func (e *externalCA) signLeaf(t *testing.T, cn string) string {
	t.Helper()
	key, _ := pki.GenerateKey(pki.KeyECP256)
	pub, _ := pki.PublicKeyOf(key)
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, 30),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, e.cert, pub, e.key.(crypto.Signer))
	return string(pki.EncodeCertPEM(der))
}

//
// ---------- flow 1: CSR here, signed there, imported back ----------
//

func TestSubordinateFlowEndToEnd(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	// Step 1: goca generates the key and the request.
	req, err := svc.CreateSubordinateCSR(ctx, SubordinateCSRInput{
		Name:    "Lab Issuing CA",
		Subject: pki.Subject{CommonName: "Lab Issuing CA", Organization: "Home Lab"},
		KeyType: "ec-p256",
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("CreateSubordinateCSR: %v", err)
	}
	if req.CA.Status != store.StatusPending {
		t.Errorf("a fresh request should be pending, got %q", req.CA.Status)
	}
	if !strings.Contains(req.CSRPEM, "CERTIFICATE REQUEST") {
		t.Fatal("no CSR was produced")
	}
	// The request must ask to be a CA, or an authority that honours extension
	// requests would issue a leaf.
	csr, err := pki.ParseCSR([]byte(req.CSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !csrRequestsCA(csr) {
		t.Error("the CSR does not carry a basicConstraints CA:TRUE extension request")
	}

	// A pending authority must not be usable.
	if _, err := svc.Issue(ctx, IssueInput{
		CARef: req.CA.Slug, Subject: pki.Subject{CommonName: "too.early"},
		KeyType: "ec-p256", Days: 10, Actor: "tester"}); err == nil {
		t.Error("a pending authority issued a certificate")
	}

	// Step 2: the external authority signs it.
	signed := ext.signCSR(t, req.CSRPEM, 1825)

	// Step 3: import the result together with the external root.
	completed, err := svc.CompleteSubordinate(ctx, CompleteSubordinateInput{
		CARef:    req.CA.Slug,
		CertPEM:  signed,
		ChainPEM: ext.certPEM,
		Actor:    "tester",
	})
	if err != nil {
		t.Fatalf("CompleteSubordinate: %v", err)
	}
	if completed.Status != store.StatusActive {
		t.Errorf("status after import is %q, want active", completed.Status)
	}
	if !completed.External {
		t.Error("the authority should be marked as externally issued")
	}
	if completed.ParentID == nil {
		t.Fatal("the external root was not linked as the issuer")
	}
	if !svc.ChainComplete(ctx, completed) {
		t.Error("the chain should reach a self-signed root")
	}

	// It can now issue, and what it issues must verify to the external root.
	res, err := svc.Issue(ctx, IssueInput{
		CARef:   completed.Slug,
		Subject: pki.Subject{CommonName: "web.lab.lan"},
		SANs:    []string{"web.lab.lan"},
		KeyType: "ec-p256",
		Days:    90,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("Issue from the imported authority: %v", err)
	}
	leaf, _ := pki.ParseCertPEM([]byte(res.Certificate.CertPEM))
	interCert, _ := pki.ParseCertPEM([]byte(completed.CertPEM))
	if err := pki.VerifyChain(leaf,
		[]*x509.Certificate{interCert}, []*x509.Certificate{ext.cert}); err != nil {
		t.Fatalf("the issued certificate does not chain to the external root: %v", err)
	}
}

// csrRequestsCA reports whether a request carries basicConstraints CA:TRUE.
func csrRequestsCA(csr *x509.CertificateRequest) bool {
	for _, e := range csr.Extensions {
		if e.Id.String() == "2.5.29.19" {
			return true
		}
	}
	for _, e := range csr.ExtraExtensions {
		if e.Id.String() == "2.5.29.19" {
			return true
		}
	}
	return false
}

func TestCompleteSubordinateRejectsForeignCertificate(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	a, err := svc.CreateSubordinateCSR(ctx, SubordinateCSRInput{
		Name: "A", Subject: pki.Subject{CommonName: "A"}, KeyType: "ec-p256", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateSubordinateCSR(ctx, SubordinateCSRInput{
		Name: "B", Subject: pki.Subject{CommonName: "B"}, KeyType: "ec-p256", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	// A certificate issued for B must never activate A.
	signedForB := ext.signCSR(t, b.CSRPEM, 365)
	_, err = svc.CompleteSubordinate(ctx, CompleteSubordinateInput{
		CARef: a.CA.Slug, CertPEM: signedForB, Actor: "t"})
	if err == nil {
		t.Fatal("a certificate for a different request was accepted")
	}
	if !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestCompleteSubordinateRejectsNonCA(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	req, _ := svc.CreateSubordinateCSR(ctx, SubordinateCSRInput{
		Name: "Sub", Subject: pki.Subject{CommonName: "Sub"}, KeyType: "ec-p256", Actor: "t"})

	_, err := svc.CompleteSubordinate(ctx, CompleteSubordinateInput{
		CARef: req.CA.Slug, CertPEM: ext.signLeaf(t, "not-a-ca"), Actor: "t"})
	if err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("expected a CA:FALSE rejection, got %v", err)
	}
}

//
// ---------- flow 2 & 3: importing an existing authority ----------
//

func TestImportCAWithKeyCanIssue(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	// An intermediate created entirely outside goca, exported as a pair.
	interKey, _ := pki.GenerateKey(pki.KeyECP256)
	interPEM, interKeyPEM := signIntermediate(t, ext, interKey, "External Issuing CA")

	c, err := svc.ImportCA(ctx, ImportCAInput{
		Name:     "External Issuing CA",
		CertPEM:  interPEM,
		KeyPEM:   interKeyPEM,
		ChainPEM: ext.certPEM,
		Actor:    "tester",
	})
	if err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if !c.HasKey() || !c.CanIssue() {
		t.Fatal("an imported CA with its key should be able to issue")
	}
	if c.ParentID == nil {
		t.Error("the supplied chain was not linked")
	}

	res, err := svc.Issue(ctx, IssueInput{
		CARef: c.Slug, Subject: pki.Subject{CommonName: "app.test"},
		KeyType: "ec-p256", Days: 30, Actor: "tester"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf, _ := pki.ParseCertPEM([]byte(res.Certificate.CertPEM))
	inter, _ := pki.ParseCertPEM([]byte(c.CertPEM))
	if err := pki.VerifyChain(leaf, []*x509.Certificate{inter}, []*x509.Certificate{ext.cert}); err != nil {
		t.Errorf("chain does not verify: %v", err)
	}
}

// signIntermediate builds an intermediate CA signed by ext, returning both PEMs.
func signIntermediate(t *testing.T, ext *externalCA, key crypto.PrivateKey, cn string) (certPEM, keyPEM string) {
	t.Helper()
	pub, _ := pki.PublicKeyOf(key)
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ext.cert, pub, ext.key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := pki.EncodePrivateKeyPEM(key)
	return string(pki.EncodeCertPEM(der)), string(kp)
}

func TestImportTrustAnchorCannotIssue(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	c, err := svc.ImportCA(ctx, ImportCAInput{
		Name: "External Root CA", CertPEM: ext.certPEM, Actor: "tester"})
	if err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if c.HasKey() {
		t.Fatal("no key was supplied, yet one is reported")
	}
	if c.CanIssue() {
		t.Fatal("a trust anchor must not be issuable")
	}
	if c.IsDefault {
		t.Error("a key-less anchor must never become the default issuer")
	}

	_, err = svc.Issue(ctx, IssueInput{
		CARef: c.Slug, Subject: pki.Subject{CommonName: "x.test"},
		KeyType: "ec-p256", Days: 10, Actor: "tester"})
	if err == nil {
		t.Fatal("a trust anchor issued a certificate")
	}
	if !strings.Contains(err.Error(), "trust anchor") {
		t.Errorf("unhelpful error: %v", err)
	}

	// Nor can it sign a CRL.
	if _, _, err := svc.GenerateCRL(ctx, c.ID, "tester"); err == nil {
		t.Error("a trust anchor produced a CRL")
	}
}

func TestImportRejectsDuplicate(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	if _, err := svc.ImportCA(ctx, ImportCAInput{CertPEM: ext.certPEM, Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ImportCA(ctx, ImportCAInput{CertPEM: ext.certPEM, Actor: "t"})
	if err == nil || !strings.Contains(err.Error(), "already present") {
		t.Fatalf("expected a duplicate rejection, got %v", err)
	}
}

func TestImportRejectsMismatchedKey(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	wrongKey, _ := pki.GenerateKey(pki.KeyECP256)
	wrongPEM, _ := pki.EncodePrivateKeyPEM(wrongKey)

	_, err := svc.ImportCA(ctx, ImportCAInput{
		CertPEM: ext.certPEM, KeyPEM: string(wrongPEM), Actor: "t"})
	if err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("expected a key mismatch rejection, got %v", err)
	}
}

func TestImportChainOfMultipleCertificates(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	interKey, _ := pki.GenerateKey(pki.KeyECP256)
	interPEM, interKeyPEM := signIntermediate(t, ext, interKey, "External Issuing CA")

	// One file holding the intermediate followed by its root, which is how
	// most authorities hand out a chain.
	c, err := svc.ImportCA(ctx, ImportCAInput{
		Name:    "Issuing",
		CertPEM: interPEM + ext.certPEM,
		KeyPEM:  interKeyPEM,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("ImportCA with a combined chain: %v", err)
	}
	if c.ParentID == nil {
		t.Error("the root inside the combined file was not imported and linked")
	}
	if !svc.ChainComplete(ctx, c) {
		t.Error("chain should be complete")
	}
	all, _ := svc.ListCAs(ctx)
	if len(all) != 2 {
		t.Errorf("expected the intermediate and its root, got %d authorities", len(all))
	}
}

func TestImportedChainProducesCompleteBundle(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ext := newExternalCA(t, "External Root CA")

	interKey, _ := pki.GenerateKey(pki.KeyECP256)
	interPEM, interKeyPEM := signIntermediate(t, ext, interKey, "External Issuing CA")
	c, err := svc.ImportCA(ctx, ImportCAInput{
		CertPEM: interPEM, KeyPEM: interKeyPEM, ChainPEM: ext.certPEM, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Issue(ctx, IssueInput{
		CARef: c.Slug, Subject: pki.Subject{CommonName: "bundle.test"},
		KeyType: "ec-p256", Days: 30, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	full, err := svc.CertChainPEM(ctx, res.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := pki.ParseCertChainPEM(full)
	if err != nil {
		t.Fatal(err)
	}
	// leaf + intermediate + external root
	if len(certs) != 3 {
		t.Fatalf("full chain has %d certificates, want 3 (leaf, intermediate, root)", len(certs))
	}
	if !pki.IsSelfSigned(certs[2]) {
		t.Error("the chain does not end at a self-signed root")
	}
}

func TestPendingCADoesNotBecomeDefault(t *testing.T) {
	svc, st, _ := newTestService(t)
	ctx := context.Background()

	// The very first authority is a pending request; it must not take the
	// default slot, or issuance would fail confusingly.
	if _, err := svc.CreateSubordinateCSR(ctx, SubordinateCSRInput{
		Name: "Pending", Subject: pki.Subject{CommonName: "Pending"}, KeyType: "ec-p256", Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DefaultCA(ctx); err == nil {
		t.Error("a pending authority was returned as the default issuer")
	}

	// A real CA created afterwards should take it.
	root := mustRootCA(t, svc)
	def, err := st.DefaultCA(ctx)
	if err != nil {
		t.Fatalf("DefaultCA: %v", err)
	}
	if def.ID != root.ID {
		t.Errorf("default is %q, want %q", def.Name, root.Name)
	}
}

func TestParseCertChainPEMHandlesDER(t *testing.T) {
	ext := newExternalCA(t, "DER Root")
	// Raw DER, as a .cer export often contains.
	certs, err := pki.ParseCertChainPEM(ext.cert.Raw)
	if err != nil {
		t.Fatalf("ParseCertChainPEM(DER): %v", err)
	}
	if len(certs) != 1 || certs[0].Subject.CommonName != "DER Root" {
		t.Error("DER input was not parsed correctly")
	}
}

func TestBigIntSerialRoundTrip(t *testing.T) {
	// Serials from external authorities can be large; the hex round trip used
	// when building CRLs must survive them.
	n := new(big.Int).Lsh(big.NewInt(1), 120)
	hex := pki.SerialHex(n)
	back, ok := pki.SerialFromHex(hex)
	if !ok || back.Cmp(n) != 0 {
		t.Errorf("serial round trip failed: %s -> %v", hex, back)
	}
}
