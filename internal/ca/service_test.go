package ca

import (
	"context"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// newTestService builds a service backed by a throwaway database.
func newTestService(t *testing.T) (*Service, *store.Store, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "test.db")
	cfg.Server.BaseURL = "http://ca.test"
	if err := cfg.GenerateSecrets(); err != nil {
		t.Fatalf("GenerateSecrets: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc, err := New(cfg, st)
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	return svc, st, cfg
}

func mustRootCA(t *testing.T, svc *Service) *store.CA {
	t.Helper()
	c, err := svc.CreateCA(context.Background(), CreateCAInput{
		Name:    "Test Root CA",
		Subject: pki.Subject{CommonName: "Test Root CA", Organization: "Testing"},
		KeyType: "ec-p256",
		Days:    3650,
		PathLen: 1,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return c
}

func TestCreateCAStoresEncryptedKey(t *testing.T) {
	svc, st, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	if !root.IsRoot || !root.IsDefault {
		t.Errorf("first CA should be a default root, got root=%t default=%t", root.IsRoot, root.IsDefault)
	}
	raw, err := st.GetCA(ctx, root.ID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if strings.Contains(raw.KeyEnc, "PRIVATE KEY") {
		t.Fatal("the CA private key is stored in cleartext")
	}
	keyPEM, err := svc.CAKeyPEM(ctx, raw)
	if err != nil {
		t.Fatalf("CAKeyPEM: %v", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Error("decrypted CA key is not PEM")
	}
}

func TestIntermediateChainVerifies(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	inter, err := svc.CreateCA(ctx, CreateCAInput{
		Name:      "Test Issuing CA",
		Subject:   pki.Subject{CommonName: "Test Issuing CA"},
		KeyType:   "ec-p256",
		Days:      1825,
		ParentRef: root.Slug,
		PathLen:   0,
		Actor:     "tester",
	})
	if err != nil {
		t.Fatalf("CreateCA intermediate: %v", err)
	}
	if inter.IsRoot {
		t.Error("intermediate is marked as a root")
	}

	res, err := svc.Issue(ctx, IssueInput{
		CARef:   inter.Slug,
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: "leaf.test"},
		SANs:    []string{"leaf.test", "10.0.0.1"},
		KeyType: "ec-p256",
		Profile: "server",
		Days:    90,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The full chain must verify against the root alone.
	full, err := svc.CertChainPEM(ctx, res.Certificate)
	if err != nil {
		t.Fatalf("CertChainPEM: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(full) {
		t.Fatal("full chain is not parseable PEM")
	}
	leaf, err := pki.ParseCertPEM([]byte(res.Certificate.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := pki.ParseCertPEM([]byte(inter.CertPEM))
	rootCert, _ := pki.ParseCertPEM([]byte(root.CertPEM))
	if err := pki.VerifyChain(leaf, []*x509.Certificate{interCert}, []*x509.Certificate{rootCert}); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}
}

func TestIssueFromSuppliedCSRKeepsSubject(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	gen, err := svc.GenerateCSR(ctx, GenerateCSRInput{
		Subject: pki.Subject{CommonName: "byo.test", Organization: "Bring Your Own"},
		SANs:    []string{"byo.test"},
		KeyType: "rsa-2048",
	})
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}

	res, err := svc.Issue(ctx, IssueInput{
		Mode:   ModeCSR,
		CSRPEM: gen.CSRPEM,
		KeyPEM: gen.PrivateKeyPEM,
		Days:   30,
		Actor:  "tester",
	})
	if err != nil {
		t.Fatalf("Issue from CSR: %v", err)
	}
	if res.Certificate.CommonName != "byo.test" {
		t.Errorf("subject from the CSR was lost: %q", res.Certificate.CommonName)
	}
	if !res.Certificate.HasKey {
		t.Error("the supplied key should have been stored")
	}

	// The stored key must come back byte-identical so the pair still works.
	stored, err := svc.CertKeyPEM(ctx, res.Certificate)
	if err != nil {
		t.Fatalf("CertKeyPEM: %v", err)
	}
	if strings.TrimSpace(string(stored)) != strings.TrimSpace(gen.PrivateKeyPEM) {
		t.Error("the stored private key differs from the one supplied")
	}
}

func TestIssueRejectsMismatchedKey(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	a, _ := svc.GenerateCSR(ctx, GenerateCSRInput{
		Subject: pki.Subject{CommonName: "a.test"}, KeyType: "ec-p256"})
	b, _ := svc.GenerateCSR(ctx, GenerateCSRInput{
		Subject: pki.Subject{CommonName: "b.test"}, KeyType: "ec-p256"})

	_, err := svc.Issue(ctx, IssueInput{
		Mode: ModeCSR, CSRPEM: a.CSRPEM, KeyPEM: b.PrivateKeyPEM, Days: 30, Actor: "tester"})
	if err == nil {
		t.Fatal("expected an error when the key does not match the CSR")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoStoreKeyLeavesNothingBehind(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	no := false
	res, err := svc.Issue(ctx, IssueInput{
		Mode:     ModeGenerate,
		Subject:  pki.Subject{CommonName: "ephemeral.test"},
		KeyType:  "ec-p256",
		Days:     30,
		StoreKey: &no,
		Actor:    "tester",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res.PrivateKeyPEM == "" {
		t.Fatal("the caller must still receive the key it can never fetch again")
	}
	if res.Certificate.HasKey {
		t.Error("the key should not have been stored")
	}
	if _, err := svc.CertKeyPEM(ctx, res.Certificate); err == nil {
		t.Error("expected an error retrieving a key that was never stored")
	}
}

func TestRevokeAppearsOnCRL(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	res, err := svc.Issue(ctx, IssueInput{
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: "doomed.test"},
		KeyType: "ec-p256",
		Days:    30,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := svc.Revoke(ctx, res.Certificate.ID, pki.ReasonKeyCompromise, "tester"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	der, _, err := svc.GenerateCRL(ctx, root.ID, "tester")
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 revoked entry, got %d", len(crl.RevokedCertificateEntries))
	}
	got := pki.SerialHex(crl.RevokedCertificateEntries[0].SerialNumber)
	if got != res.Certificate.SerialHex {
		t.Errorf("CRL lists serial %s, want %s", got, res.Certificate.SerialHex)
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != pki.ReasonKeyCompromise {
		t.Error("the revocation reason was not carried onto the CRL")
	}

	rootCert, _ := pki.ParseCertPEM([]byte(root.CertPEM))
	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("CRL is not signed by its CA: %v", err)
	}
}

func TestSearchFindsBySANAndSerial(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	res, err := svc.Issue(ctx, IssueInput{
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: "findme.test"},
		SANs:    []string{"findme.test", "alias.test", "10.9.9.9"},
		KeyType: "ec-p256",
		Days:    30,
		Actor:   "alice",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	for _, q := range []string{"findme", "alias.test", "10.9.9.9", "alice", res.Certificate.SerialHex} {
		got, total, err := svc.Search(ctx, store.CertFilter{Query: q})
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if total != 1 || len(got) != 1 {
			t.Errorf("Search(%q) returned %d results, want 1", q, total)
		}
	}

	// And it can be fetched historically by serial, which is how the CLI and
	// API let users re-download long after issuance.
	found, err := svc.FindCertificate(ctx, res.Certificate.SerialHex)
	if err != nil {
		t.Fatalf("FindCertificate by serial: %v", err)
	}
	if found.ID != res.Certificate.ID {
		t.Error("serial lookup returned the wrong certificate")
	}
}

func TestIssueRejectsValidityBeyondCA(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.CreateCA(ctx, CreateCAInput{
		Name:    "Short CA",
		Subject: pki.Subject{CommonName: "Short CA"},
		KeyType: "ec-p256",
		Days:    10,
		Actor:   "tester",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	_, err := svc.Issue(ctx, IssueInput{
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: "toolong.test"},
		KeyType: "ec-p256",
		Days:    365,
		Actor:   "tester",
	})
	if err == nil {
		t.Fatal("expected an error when the leaf outlives its CA")
	}
}

func TestDisabledCARefusesIssuance(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	if err := svc.SetCAStatus(ctx, root.ID, store.StatusDisabled, "tester"); err != nil {
		t.Fatalf("SetCAStatus: %v", err)
	}
	_, err := svc.Issue(ctx, IssueInput{
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: "nope.test"},
		KeyType: "ec-p256",
		Days:    30,
		Actor:   "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-CA error, got %v", err)
	}
}

func TestDeleteCACascadesToCertificates(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	if _, err := svc.Issue(ctx, IssueInput{
		Mode: ModeGenerate, Subject: pki.Subject{CommonName: "child.test"},
		KeyType: "ec-p256", Days: 30, Actor: "tester"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := svc.DeleteCA(ctx, root.ID, "tester"); err != nil {
		t.Fatalf("DeleteCA: %v", err)
	}
	_, total, err := svc.Search(ctx, store.CertFilter{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 0 {
		t.Errorf("deleting the CA left %d certificates behind", total)
	}
}

func TestPKCS12BundleIsReadable(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	res, err := svc.Issue(ctx, IssueInput{
		Mode: ModeGenerate, Subject: pki.Subject{CommonName: "bundle.test"},
		KeyType: "rsa-2048", Days: 30, Actor: "tester"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	p12, err := svc.CertBundleP12(ctx, res.Certificate, "hunter2")
	if err != nil {
		t.Fatalf("CertBundleP12: %v", err)
	}
	if len(p12) == 0 {
		t.Fatal("empty PKCS#12 bundle")
	}
}

func TestSlugifyIsStableAndSafe(t *testing.T) {
	// Anything outside [a-z0-9] collapses to a separator, so the result is
	// always safe in a URL path and as a file name.
	cases := map[string]string{
		"Acme Root CA":     "acme-root-ca",
		"  Ünïcode / CA  ": "n-code-ca",
		"already-a-slug":   "already-a-slug",
		"!!!":              "ca",
		"":                 "ca",
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditTrailRecordsIssuance(t *testing.T) {
	svc, st, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)
	if _, err := svc.Issue(ctx, IssueInput{
		Mode: ModeGenerate, Subject: pki.Subject{CommonName: "audited.test"},
		KeyType: "ec-p256", Days: 30, Actor: "alice"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	entries, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "cert.issue" && e.Actor == "alice" && e.Target == "audited.test" {
			found = true
			if time.Since(e.TS) > time.Minute {
				t.Error("audit timestamp looks wrong")
			}
		}
	}
	if !found {
		t.Error("issuance was not recorded in the audit log")
	}
}
