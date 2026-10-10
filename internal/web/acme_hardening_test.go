package web

// Protocol-conformance hardening, driven through golang.org/x/crypto/acme
// like the rest of the ACME tests.

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/mevijays/goca/internal/acme"
	"github.com/mevijays/goca/internal/store"
)

func TestACMEHonoursRequestedNotAfter(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	c := registerACME(t, srv, createTestEAB(t, h, acme.CreateEABInput{Name: "d", Actor: "t"}))
	ctx := context.Background()

	// cert-manager sends notAfter when the issuer enables duration support;
	// it used to be ignored, issuing at the authority default (397 days).
	want := time.Now().Add(90 * 24 * time.Hour)
	o, err := c.AuthorizeOrder(ctx, xacme.DomainIDs("short.internal"), xacme.WithOrderNotAfter(want))
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := generateTestCSR(t, "short.internal")
	chain, _, err := c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(chain[0])
	// Whole days, rounded up: within a day after the request, never before.
	if d := leaf.NotAfter.Sub(want); d < -time.Minute || d > 25*time.Hour {
		t.Fatalf("NotAfter = %s, want ~%s (got %.1f days of validity)", leaf.NotAfter, want,
			math.Round(leaf.NotAfter.Sub(time.Now()).Hours()/24*10)/10)
	}
}

func TestACMERejectsLifetimeItCannotHonour(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	c := registerACME(t, srv, createTestEAB(t, h, acme.CreateEABInput{Name: "d", Days: 30, Actor: "t"}))
	ctx := context.Background()

	_, err := c.AuthorizeOrder(ctx, xacme.DomainIDs("long.internal"), xacme.WithOrderNotAfter(time.Now().Add(60*24*time.Hour)))
	wantACMEProblem(t, err, "malformed") // beyond the credential's 30 days

	_, err = c.AuthorizeOrder(ctx, xacme.DomainIDs("later.internal"), xacme.WithOrderNotBefore(time.Now().Add(24*time.Hour)))
	wantACMEProblem(t, err, "malformed") // notBefore is not supported

	// No requested lifetime: the credential's own validity, as before.
	if _, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{DNSNames: []string{"plain.internal"}}, "plain.internal"); err != nil {
		t.Fatalf("an order without notAfter was refused: %v", err)
	}
}

func TestACMEDeactivatedKeyCannotReRegister(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "d", Actor: "t"})
	c := registerACME(t, srv, eab)
	ctx := context.Background()
	if err := c.DeactivateReg(ctx); err != nil {
		t.Fatal(err)
	}
	// Same key registering again used to get the deactivated account back
	// with a 200.
	_, err := c.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: mustHMAC(t, eab)},
	}, xacme.AcceptTOS)
	wantACMEProblem(t, err, "unauthorized")
}

func TestACMEFinalizeRefusesExpiredOrder(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	c := registerACME(t, srv, createTestEAB(t, h, acme.CreateEABInput{Name: "e", Actor: "t"}))
	accts, err := acme.New(h.svc).ListAccounts(context.Background())
	if err != nil || len(accts) != 1 {
		t.Fatalf("accounts: %d %v", len(accts), err)
	}
	// An order that expired an hour ago, still marked ready.
	o, err := h.svc.Store().CreateAcmeOrder(context.Background(), &store.AcmeOrder{
		AccountID: accts[0].ID, Status: store.AcmeStatusReady,
		Identifiers: []store.AcmeIdentifier{{Type: "dns", Value: "stale.internal"}},
		ExpiresAt:   time.Now().Add(-time.Hour), CreatedAt: time.Now().Add(-25 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := generateTestCSR(t, "stale.internal")
	_, _, err = c.CreateOrderCert(context.Background(), fmt.Sprintf("%s/acme/order/%d/finalize", srv.URL, o.ID), csr, true)
	wantACMEProblem(t, err, "orderNotReady")
}

// A sequential second finalize was already refused before the atomic claim
// existed; this guards that the claim keeps it that way. The race the claim
// actually fixes - two finalizes at once both passing the status check - is
// proven at the store level (TestClaimAcmeOrderForFinalizeIsExclusive, on
// SQLite and PostgreSQL), where the concurrency can be controlled.
func TestACMEFinalizeTwiceIssuesOnce(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	c := registerACME(t, srv, createTestEAB(t, h, acme.CreateEABInput{Name: "f", Actor: "t"}))
	ctx := context.Background()
	o, err := c.AuthorizeOrder(ctx, xacme.DomainIDs("once.internal"))
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := generateTestCSR(t, "once.internal")
	if _, _, err := c.CreateOrderCert(ctx, o.FinalizeURL, csr, true); err != nil {
		t.Fatal(err)
	}
	_, _, err = c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	wantACMEProblem(t, err, "orderNotReady")
}

func TestACMEContactsAreValidated(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "c", Actor: "t"})
	for contact, problem := range map[string]string{
		"https://evil.example/":            "unsupportedContact",
		"mailto:a@x.internal?subject=hi":   "invalidContact",
		"mailto:a@x.internal,b@x.internal": "invalidContact",
		"mailto:no-at-sign":                "invalidContact",
	} {
		t.Run(contact, func(t *testing.T) {
			c := newUnregisteredClient(t, srv)
			_, err := c.Register(context.Background(), &xacme.Account{
				Contact:                []string{contact},
				ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: mustHMAC(t, eab)},
			}, xacme.AcceptTOS)
			wantACMEProblem(t, err, problem)
		})
	}
	c := newUnregisteredClient(t, srv)
	if _, err := c.Register(context.Background(), &xacme.Account{
		Contact:                []string{"mailto:ops@lab.internal"},
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: mustHMAC(t, eab)},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("a plain mailto: contact was refused: %v", err)
	}
}
