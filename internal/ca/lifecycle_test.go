package ca

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// issueTestCert is a shorthand for the lifecycle tests.
func issueTestCert(t *testing.T, svc *Service, cn string, days int) *store.Certificate {
	t.Helper()
	res, err := svc.Issue(context.Background(), IssueInput{
		Mode:    ModeGenerate,
		Subject: pki.Subject{CommonName: cn, Organization: "Testing"},
		SANs:    []string{cn},
		KeyType: "ec-p256",
		Days:    days,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("Issue(%s): %v", cn, err)
	}
	return res.Certificate
}

//
// ---------- renewal ----------
//

func TestRenewKeepsIdentityAndRotatesKey(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	old := issueTestCert(t, svc, "rotate.test", 90)
	oldKey, err := svc.CertKeyPEM(ctx, old)
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.Renew(ctx, old.ID, RenewInput{Actor: "tester"})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	newCert := res.Certificate

	if newCert.CommonName != old.CommonName {
		t.Errorf("common name changed: %q -> %q", old.CommonName, newCert.CommonName)
	}
	if strings.Join(newCert.SANs(), ",") != strings.Join(old.SANs(), ",") {
		t.Errorf("SANs changed: %v -> %v", old.SANs(), newCert.SANs())
	}
	if newCert.Profile != old.Profile {
		t.Errorf("profile changed: %q -> %q", old.Profile, newCert.Profile)
	}
	if newCert.SerialHex == old.SerialHex {
		t.Error("the replacement reused the old serial")
	}
	if newCert.RenewedFrom == nil || *newCert.RenewedFrom != old.ID {
		t.Error("the replacement is not linked to its predecessor")
	}

	// A fresh key is the default: rotation should retire the old key too.
	newKey, err := svc.CertKeyPEM(ctx, newCert)
	if err != nil {
		t.Fatal(err)
	}
	if string(newKey) == string(oldKey) {
		t.Error("the key was reused even though a new one was expected")
	}

	// Validity should carry over the original span.
	got := int(newCert.NotAfter.Sub(newCert.NotBefore).Hours() / 24)
	if got < 88 || got > 91 {
		t.Errorf("replacement spans %d days, want about 90", got)
	}

	// The old certificate stays valid until explicitly retired.
	reloaded, err := svc.GetCertificate(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != store.StatusActive {
		t.Errorf("the predecessor was retired without being asked: %s", reloaded.Status)
	}
}

func TestRenewSameKeyReusesTheKey(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	old := issueTestCert(t, svc, "pinned.test", 60)
	oldKey, _ := svc.CertKeyPEM(ctx, old)

	res, err := svc.Renew(ctx, old.ID, RenewInput{SameKey: true, Actor: "tester"})
	if err != nil {
		t.Fatalf("Renew --same-key: %v", err)
	}
	newKey, err := svc.CertKeyPEM(ctx, res.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(newKey)) != strings.TrimSpace(string(oldKey)) {
		t.Fatal("--same-key did not reuse the private key")
	}
	// And the new certificate must actually belong to that key.
	cert, _ := pki.ParseCertPEM([]byte(res.Certificate.CertPEM))
	key, _ := pki.ParsePrivateKeyPEM(newKey)
	if err := pki.KeyMatchesCert(key, cert); err != nil {
		t.Errorf("the replacement does not match the reused key: %v", err)
	}
}

func TestRenewWithRevokeOldSupersedes(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	old := issueTestCert(t, svc, "replaceme.test", 60)
	res, err := svc.Renew(ctx, old.ID, RenewInput{RevokeOld: true, Actor: "tester"})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !res.RevokedOld {
		t.Fatal("the predecessor was not revoked")
	}
	reloaded, _ := svc.GetCertificate(ctx, old.ID)
	if reloaded.Status != store.StatusRevoked {
		t.Fatalf("predecessor status is %q", reloaded.Status)
	}
	if reloaded.RevokeCode != pki.ReasonSuperseded {
		t.Errorf("reason is %s, want superseded", pki.ReasonName(reloaded.RevokeCode))
	}

	// And it lands on the CRL, with the replacement absent from it.
	der, _, err := svc.GenerateCRL(ctx, root.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("CRL has %d entries, want 1", len(crl.RevokedCertificateEntries))
	}
	if pki.SerialHex(crl.RevokedCertificateEntries[0].SerialNumber) != old.SerialHex {
		t.Error("the wrong certificate is on the CRL")
	}
}

func TestRenewalHistoryWalksTheChain(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	first := issueTestCert(t, svc, "chain.test", 30)
	second, err := svc.Renew(ctx, first.ID, RenewInput{Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	third, err := svc.Renew(ctx, second.Certificate.ID, RenewInput{Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}

	// The history should be identical viewed from any point in the chain.
	for _, from := range []*store.Certificate{first, second.Certificate, third.Certificate} {
		hist, err := svc.RenewalHistory(ctx, from)
		if err != nil {
			t.Fatal(err)
		}
		if len(hist) != 3 {
			t.Fatalf("history from %d has %d entries, want 3", from.ID, len(hist))
		}
		if hist[0].ID != first.ID || hist[2].ID != third.Certificate.ID {
			t.Errorf("history is out of order: %d, %d, %d", hist[0].ID, hist[1].ID, hist[2].ID)
		}
	}
}

func TestRenewExpiringBatch(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	issueTestCert(t, svc, "soon-a.test", 10)
	issueTestCert(t, svc, "soon-b.test", 20)
	issueTestCert(t, svc, "later.test", 300)

	results, errs := svc.RenewExpiring(ctx, 30, RenewInput{Actor: "tester"})
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(results) != 2 {
		t.Fatalf("renewed %d certificates, want the 2 expiring within 30 days", len(results))
	}
	names := map[string]bool{}
	for _, r := range results {
		names[r.Certificate.CommonName] = true
	}
	if !names["soon-a.test"] || !names["soon-b.test"] {
		t.Errorf("wrong certificates renewed: %v", names)
	}
	if names["later.test"] {
		t.Error("a certificate outside the window was renewed")
	}
}

func TestRenewFromDisabledCAFallsBackToDefault(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	first := mustRootCA(t, svc)
	cert := issueTestCert(t, svc, "moving.test", 30)

	// A second authority, then the original is disabled.
	second, err := svc.CreateCA(ctx, CreateCAInput{
		Name: "Second CA", Subject: pki.Subject{CommonName: "Second CA"},
		KeyType: "ec-p256", Days: 3650, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDefaultCA(ctx, second.ID, "t"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCAStatus(ctx, first.ID, store.StatusDisabled, "t"); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Renew(ctx, cert.ID, RenewInput{Actor: "t"})
	if err != nil {
		t.Fatalf("Renew after the issuer was disabled: %v", err)
	}
	if res.Certificate.CAID != second.ID {
		t.Errorf("the replacement was issued by CA %d, want the new default %d",
			res.Certificate.CAID, second.ID)
	}
}

//
// ---------- hold / release ----------
//

func TestHoldAndRelease(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)
	cert := issueTestCert(t, svc, "suspect.test", 90)

	if err := svc.Hold(ctx, cert.ID, "tester"); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	held, _ := svc.GetCertificate(ctx, cert.ID)
	if !held.OnHold() {
		t.Fatal("the certificate is not marked as on hold")
	}

	// A hold appears on the CRL like any revocation.
	der, _, _ := svc.GenerateCRL(ctx, root.ID, "t")
	crl, _ := x509.ParseRevocationList(der)
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatal("the held certificate is not on the CRL")
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != pki.ReasonCertificateHold {
		t.Error("the CRL entry does not carry certificateHold")
	}

	// Releasing takes it back off.
	if err := svc.Release(ctx, cert.ID, "tester"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	back, _ := svc.GetCertificate(ctx, cert.ID)
	if back.Status != store.StatusActive || back.RevokedAt != nil {
		t.Fatalf("the certificate was not reinstated: status=%s", back.Status)
	}
	der, _, _ = svc.GenerateCRL(ctx, root.ID, "t")
	crl, _ = x509.ParseRevocationList(der)
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Error("the released certificate is still on the CRL")
	}
}

func TestPermanentRevocationCannotBeReleased(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)
	cert := issueTestCert(t, svc, "gone.test", 90)

	if err := svc.Revoke(ctx, cert.ID, pki.ReasonKeyCompromise, "t"); err != nil {
		t.Fatal(err)
	}
	err := svc.Release(ctx, cert.ID, "t")
	if err == nil {
		t.Fatal("a key-compromise revocation was reversed")
	}
	if !strings.Contains(err.Error(), "on hold") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestHoldRejectsAlreadyRevoked(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)
	cert := issueTestCert(t, svc, "already.test", 90)

	if err := svc.Revoke(ctx, cert.ID, pki.ReasonSuperseded, "t"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Hold(ctx, cert.ID, "t"); err == nil {
		t.Fatal("a permanently revoked certificate was put on hold")
	}
}

//
// ---------- bulk revocation ----------
//

func TestBulkRevokeByFilter(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	issueTestCert(t, svc, "a.doomed.test", 90)
	issueTestCert(t, svc, "b.doomed.test", 90)
	keep := issueTestCert(t, svc, "keeper.test", 90)

	res, err := svc.BulkRevoke(ctx, BulkRevokeInput{
		Filter: &store.CertFilter{Query: "doomed"},
		Reason: pki.ReasonCessationOfOperation,
		Actor:  "tester",
	})
	if err != nil {
		t.Fatalf("BulkRevoke: %v", err)
	}
	if len(res.Revoked) != 2 {
		t.Fatalf("revoked %d certificates, want 2", len(res.Revoked))
	}
	survivor, _ := svc.GetCertificate(ctx, keep.ID)
	if survivor.Status != store.StatusActive {
		t.Error("a certificate outside the filter was revoked")
	}

	// Re-running is a no-op rather than an error.
	again, err := svc.BulkRevoke(ctx, BulkRevokeInput{
		Filter: &store.CertFilter{Query: "doomed"}, Reason: pki.ReasonUnspecified, Actor: "t"})
	if err != nil {
		t.Fatalf("second BulkRevoke: %v", err)
	}
	if len(again.Revoked) != 0 || len(again.Skipped) != 2 {
		t.Errorf("re-run revoked %d and skipped %d, want 0 and 2",
			len(again.Revoked), len(again.Skipped))
	}
}

func TestBulkRevokeRefusesEmptySelection(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	mustRootCA(t, svc)

	_, err := svc.BulkRevoke(ctx, BulkRevokeInput{
		Filter: &store.CertFilter{Query: "nothing-matches-this"}, Actor: "t"})
	if err == nil {
		t.Fatal("an empty selection was accepted")
	}
}

//
// ---------- CA retirement ----------
//

func TestRevokeCACascades(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	inter, err := svc.CreateCA(ctx, CreateCAInput{
		Name: "Doomed Issuing CA", Subject: pki.Subject{CommonName: "Doomed Issuing CA"},
		KeyType: "ec-p256", Days: 1000, ParentRef: root.Slug, Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, cn := range []string{"one.test", "two.test"} {
		if _, err := svc.Issue(ctx, IssueInput{
			CARef: inter.Slug, Subject: pki.Subject{CommonName: cn},
			KeyType: "ec-p256", Days: 30, Actor: "t"}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := svc.RevokeCA(ctx, inter.ID, pki.ReasonCessationOfOperation, true, "tester")
	if err != nil {
		t.Fatalf("RevokeCA: %v", err)
	}
	if res.Certificates != 2 {
		t.Errorf("revoked %d certificates, want 2", res.Certificates)
	}
	if !res.RevokedInParent {
		t.Error("the CA was not added to its parent's CRL")
	}

	// Issuance must stop.
	reloaded, _ := svc.GetCA(ctx, inter.ID)
	if reloaded.Status != store.StatusDisabled {
		t.Errorf("the CA is %q, want disabled", reloaded.Status)
	}
	if _, err := svc.Issue(ctx, IssueInput{
		CARef: inter.Slug, Subject: pki.Subject{CommonName: "late.test"},
		KeyType: "ec-p256", Days: 10, Actor: "t"}); err == nil {
		t.Error("a retired authority issued a certificate")
	}

	// The parent's CRL must now list the retired CA's own serial.
	der, _, err := svc.GenerateCRL(ctx, root.ID, "t")
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if pki.SerialHex(e.SerialNumber) == inter.SerialHex {
			found = true
		}
	}
	if !found {
		t.Error("the retired authority's serial is missing from the parent CRL")
	}
}

func TestRevokeRootWarnsItCannotBeRevoked(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	root := mustRootCA(t, svc)

	res, err := svc.RevokeCA(ctx, root.ID, pki.ReasonCessationOfOperation, false, "t")
	if err != nil {
		t.Fatalf("RevokeCA: %v", err)
	}
	if res.RevokedInParent {
		t.Error("a self-signed root cannot be revoked by anything")
	}
	if len(res.Warnings) == 0 {
		t.Error("retiring a root should warn that trust stores must be updated")
	}
}
