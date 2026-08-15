package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/mevijays/goca/internal/acme"
	"github.com/mevijays/goca/internal/store"
)

// These tests drive goca's ACME server with golang.org/x/crypto/acme, an
// independent RFC 8555 client implementation goca has no influence over -
// the strongest confidence available short of running actual cert-manager,
// and it exercises the exact code paths a real ACME client does: directory
// discovery, EAB-signed registration, nonce handling, order/authorization
// polling, CSR finalization and certificate download.

// acmeTestClient wires an x/crypto/acme.Client at an httptest server backed
// by the harness, with a freshly generated account key.
func acmeTestClient(t *testing.T, h *harness) (*xacme.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)

	// internal/acme builds every directory/Location/Link URL from the
	// configured base URL, same as CRL and public-CA URLs elsewhere in goca.
	// The harness's default ("http://ca.test") isn't dialable, so point it at
	// the httptest server actually listening for this test.
	h.svc.Config().Server.BaseURL = srv.URL

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &xacme.Client{
		Key:          key,
		DirectoryURL: srv.URL + "/acme/directory",
		HTTPClient:   srv.Client(),
	}, srv
}

// createTestEAB is a shortcut around the Go-level EAB admin API (what the
// CLI/portal/REST API all call) so tests don't need real HTTP for setup.
func createTestEAB(t *testing.T, h *harness, in acme.CreateEABInput) *acme.CreateEABResult {
	t.Helper()
	svc := acme.New(h.svc)
	res, err := svc.CreateEAB(context.Background(), in)
	if err != nil {
		t.Fatalf("CreateEAB: %v", err)
	}
	return res
}

func generateTestCSR(t *testing.T, names ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{}, DNSNames: names}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func TestACMEEndToEndWithRealClient(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{
		Name:           "cluster-a",
		AllowedDomains: []string{"*.svc.cluster-a.internal"},
		Profile:        "server",
		Days:           30,
		Actor:          "test",
	})
	hmacKey, err := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	client, _ := acmeTestClient(t, h)
	ctx := context.Background()

	// 1. Directory discovery.
	dir, err := client.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !dir.ExternalAccountRequired {
		t.Error("directory does not advertise externalAccountRequired")
	}

	// 2. Register with EAB.
	account, err := client.Register(ctx, &xacme.Account{
		Contact: []string{"mailto:ops@cluster-a.internal"},
		ExternalAccountBinding: &xacme.ExternalAccountBinding{
			KID: eab.Cred.KeyID,
			Key: hmacKey,
		},
	}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if account.Status != xacme.StatusValid {
		t.Fatalf("account status is %q, want valid", account.Status)
	}

	// Re-registering with the same key must be idempotent (§7.3.1): the
	// server responds 200 rather than 201, which the x/crypto client
	// surfaces as ErrAccountAlreadyExists - its documented signal for "this
	// was not a fresh registration", not a failure - while still caching the
	// same account URL as KID.
	// A fresh Client value with the same account key (not a struct copy,
	// which would copy the library's internal mutex).
	client2 := &xacme.Client{Key: client.Key, DirectoryURL: client.DirectoryURL, HTTPClient: client.HTTPClient}
	_, err = client2.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS)
	if err != xacme.ErrAccountAlreadyExists {
		t.Fatalf("repeat Register: got %v, want ErrAccountAlreadyExists", err)
	}
	if string(client2.KID) != account.URI {
		t.Errorf("repeat registration resolved a different account URL: %s vs %s", client2.KID, account.URI)
	}
	accounts, err := acme.New(h.svc).ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 1 {
		t.Fatalf("expected exactly 1 account after a repeat registration, got %d", len(accounts))
	}

	// 3. Order, with authorizations pre-valid: WaitOrder must return
	// immediately at "ready" with no challenge ever needing a response.
	domain := "app.svc.cluster-a.internal"
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ready, err := client.WaitOrder(waitCtx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if ready.Status != xacme.StatusReady {
		t.Fatalf("order status is %q, want ready", ready.Status)
	}
	for _, authzURL := range ready.AuthzURLs {
		az, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		if az.Status != xacme.StatusValid {
			t.Errorf("authorization %s is %q, want valid (EAB-only mode never leaves anything pending)",
				authzURL, az.Status)
		}
	}

	// 4. Finalize with a CSR the client built itself - its key never
	// reaches the server.
	csrDER, csrKey := generateTestCSR(t, domain)
	der, certURL, err := client.CreateOrderCert(ctx, ready.FinalizeURL, csrDER, true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	if len(der) < 2 {
		t.Fatalf("expected a leaf plus at least one issuer, got %d certificates", len(der))
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
		t.Errorf("leaf SANs are %v, want [%s]", leaf.DNSNames, domain)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(&csrKey.PublicKey) {
		t.Error("the issued certificate's key does not match the client's CSR key")
	}

	// Chain verifies against goca's own root, using only what the ACME
	// response handed back - no goca-internal API involved.
	pool := x509.NewCertPool()
	for _, c := range der[1:] {
		issuer, err := x509.ParseCertificate(c)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(issuer)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued certificate does not verify against the chain ACME returned: %v", err)
	}

	// The certificate is an ordinary goca certificate from here on.
	certs, total, err := h.svc.Search(ctx, store.CertFilter{Query: domain})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected the ACME-issued certificate to show up in a normal search, got %d", total)
	}
	if certs[0].RequestedBy != "acme:cluster-a" {
		t.Errorf("requested_by is %q, want acme:cluster-a", certs[0].RequestedBy)
	}
	if certs[0].HasKey {
		t.Error("goca must never have the client's private key for an ACME-issued certificate")
	}

	// 5. Fetch again directly to make sure the cert URL alone also works.
	refetched, err := client.FetchCert(ctx, certURL, true)
	if err != nil {
		t.Fatalf("FetchCert: %v", err)
	}
	if len(refetched) < 1 || string(refetched[0]) != string(der[0]) {
		t.Error("re-fetching the certificate by its URL returned something different")
	}

	// 6. Revoke through ACME, with the account key (not the cert's key).
	if err := client.RevokeCert(ctx, nil, der[0], xacme.CRLReasonSuperseded); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	revoked, err := h.svc.FindCertificate(ctx, certs[0].SerialHex)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != store.StatusRevoked {
		t.Errorf("certificate status is %q after ACME revocation, want revoked", revoked.Status)
	}

	// Revoking again must be rejected as alreadyRevoked, which the client
	// treats as success (idempotent), so assert at the store level instead.
	if err := client.RevokeCert(ctx, nil, der[0], xacme.CRLReasonSuperseded); err != nil {
		t.Errorf("re-revoking an already-revoked certificate should be treated as success, got: %v", err)
	}
}

func TestACMERejectsDomainOutsideEABScope(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{
		Name: "scoped", AllowedDomains: []string{"*.allowed.internal"}, Actor: "test",
	})
	hmacKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)
	client, _ := acmeTestClient(t, h)
	ctx := context.Background()

	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("not-allowed.other.internal"))
	if err == nil {
		t.Fatal("an order for a domain outside the EAB's scope was accepted")
	}
	acmeErr, ok := err.(*xacme.Error)
	if !ok {
		t.Fatalf("expected an *acme.Error, got %T: %v", err, err)
	}
	if !strings.Contains(acmeErr.ProblemType, "rejectedIdentifier") {
		t.Errorf("problem type is %q, want rejectedIdentifier", acmeErr.ProblemType)
	}
}

func TestACMERejectsBadEABSignature(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "real", Actor: "test"})
	_ = eab

	client, _ := acmeTestClient(t, h)
	ctx := context.Background()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 32) // not the credential's real HMAC key
	_, err := client.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: wrongKey},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("registration with a forged EAB signature was accepted")
	}
}

func TestACMERejectsUnknownEABKeyID(t *testing.T) {
	h := newHarness(t)
	client, _ := acmeTestClient(t, h)
	ctx := context.Background()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}

	_, err := client.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{
			KID: "does-not-exist", Key: make([]byte, 32),
		},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("registration with an unknown EAB keyID was accepted")
	}
}

func TestACMEDisabledEABCannotBootstrap(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "temp", Actor: "test"})
	hmacKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)

	svc := acme.New(h.svc)
	if err := svc.SetEABDisabled(context.Background(), eab.Cred.ID, true, "test"); err != nil {
		t.Fatal(err)
	}

	client, _ := acmeTestClient(t, h)
	ctx := context.Background()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := client.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("a disabled EAB credential bootstrapped a new account")
	}
}

func TestACMEMaxAccountsEnforced(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "single-use", MaxAccounts: 1, Actor: "test"})
	hmacKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)
	ctx := context.Background()

	client1, _ := acmeTestClient(t, h)
	if _, err := client1.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client1.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	client2, _ := acmeTestClient(t, h) // a different account key
	if _, err := client2.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := client2.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS)
	if err == nil {
		t.Fatal("a second account was bootstrapped past max_accounts=1")
	}
}

func TestACMEWildcardIdentifier(t *testing.T) {
	h := newHarness(t)
	eab := createTestEAB(t, h, acme.CreateEABInput{
		Name: "wild", AllowedDomains: []string{"*.svc.cluster-a.internal"}, Actor: "test",
	})
	hmacKey, _ := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)
	client, _ := acmeTestClient(t, h)
	ctx := context.Background()
	if _, err := client.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: hmacKey},
	}, xacme.AcceptTOS); err != nil {
		t.Fatal(err)
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("*.svc.cluster-a.internal"))
	if err != nil {
		t.Fatalf("AuthorizeOrder for a wildcard identifier: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ready, err := client.WaitOrder(waitCtx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	csrDER, _ := generateTestCSR(t, "*.svc.cluster-a.internal")
	der, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, csrDER, false)
	if err != nil {
		t.Fatalf("CreateOrderCert for a wildcard: %v", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "*.svc.cluster-a.internal" {
		t.Errorf("wildcard SAN was not preserved: %v", leaf.DNSNames)
	}
}
