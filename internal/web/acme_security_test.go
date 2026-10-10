package web

// Regression tests for the ACME and issuance security review. Each one
// started life as a probe that demonstrated the hole against the real code;
// these assert the fixed behaviour, through the same real ACME client
// (golang.org/x/crypto/acme) the rest of acme_test.go uses.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/mevijays/goca/internal/acme"
)

// acmeServer starts one httptest server for a test and points goca's base
// URL at it. Every client in a test must share it: acmeTestClient starts a
// new server (and rewrites the base URL) per call, so a second call leaves
// the first client sending url headers for a server goca no longer
// considers its own - an "unauthorized" that has nothing to do with what a
// multi-account test is trying to assert.
func acmeServer(t *testing.T, h *harness) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	h.svc.Config().Server.BaseURL = srv.URL
	return srv
}

// mustHMAC decodes a freshly created credential's HMAC key.
func mustHMAC(t *testing.T, eab *acme.CreateEABResult) []byte {
	t.Helper()
	k, err := base64.RawURLEncoding.DecodeString(eab.HMACKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newUnregisteredClient returns a client with a fresh account key, pointed at
// srv and with the directory already discovered.
func newUnregisteredClient(t *testing.T, srv *httptest.Server) *xacme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &xacme.Client{Key: key, DirectoryURL: srv.URL + "/acme/directory", HTTPClient: srv.Client()}
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

// registerACME registers a fresh account (new key) under eab on srv.
func registerACME(t *testing.T, srv *httptest.Server, eab *acme.CreateEABResult) *xacme.Client {
	t.Helper()
	client := newUnregisteredClient(t, srv)
	if _, err := client.Register(context.Background(), &xacme.Account{
		ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: eab.Cred.KeyID, Key: mustHMAC(t, eab)},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return client
}

// orderAndFinalize places an order for ids and finalizes it with a CSR built
// from tmpl. It returns the leaf, the certificate URL, and any error from
// either step.
func orderAndFinalize(t *testing.T, c *xacme.Client, tmpl *x509.CertificateRequest, ids ...string) (*x509.Certificate, string, error) {
	t.Helper()
	ctx := context.Background()
	o, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(ids...))
	if err != nil {
		return nil, "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, certURL, err := c.CreateOrderCert(ctx, o.FinalizeURL, der, true)
	if err != nil {
		return nil, "", err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf, certURL, nil
}

func wantACMEProblem(t *testing.T, err error, problemType string) {
	t.Helper()
	if err == nil {
		t.Fatalf("request succeeded, want an ACME %q problem", problemType)
	}
	ae, ok := err.(*xacme.Error)
	if !ok {
		t.Fatalf("got %T (%v), want *acme.Error with type %q", err, err, problemType)
	}
	if !strings.HasSuffix(ae.ProblemType, ":"+problemType) {
		t.Fatalf("problem type = %q (%s), want ...:%s", ae.ProblemType, ae.Detail, problemType)
	}
}

// --- C1: subordinate CAs are administrator-only -------------------------

func TestIssueIntermediateCAIsAdminOnly(t *testing.T) {
	h := newHarness(t)
	body := `{"mode":"generate","profile":"intermediate-ca","subject":{"common_name":"Sub CA"},"key_type":"ec-p256","store_key":false}`

	rec, _ := h.apiJSON("POST", "/api/v1/certificates", body, h.token("user"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user-role token: status %d, want 403 - a non-admin minted a subordinate CA: %s", rec.Code, rec.Body)
	}

	// The gate must not be settable from the request body. IssueInput's
	// field is json:"-", and decodeJSON rejects unknown fields outright.
	for _, smuggled := range []string{`"AllowSubordinateCA":true`, `"allow_subordinate_ca":true`} {
		b := strings.Replace(body, `{"mode"`, `{`+smuggled+`,"mode"`, 1)
		rec, _ := h.apiJSON("POST", "/api/v1/certificates", b, h.token("user"))
		if rec.Code == http.StatusCreated {
			t.Fatalf("user-role token minted a CA by sending %s", smuggled)
		}
	}

	// Administrators keep the ability (e.g. signing an external
	// intermediate's CSR).
	rec, out := h.apiJSON("POST", "/api/v1/certificates", body, h.token("admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin token: status %d, want 201: %s", rec.Code, rec.Body)
	}
	blk, _ := pem.Decode([]byte(out["certificate"].(map[string]any)["cert_pem"].(string)))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.IsCA {
		t.Fatal("admin intermediate-ca issuance did not produce a CA")
	}
}

func TestOrdinaryProfilesStillWorkForUsers(t *testing.T) {
	h := newHarness(t)
	rec, _ := h.apiJSON("POST", "/api/v1/certificates",
		`{"mode":"generate","profile":"server","subject":{"common_name":"svc.internal"},"sans":["svc.internal"],"key_type":"ec-p256"}`,
		h.token("user"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("user-role server cert: status %d: %s", rec.Code, rec.Body)
	}
}

// --- H2: EAB profile is validated at creation ----------------------------

func TestEABProfileValidatedAtCreation(t *testing.T) {
	h := newHarness(t)
	svc := acme.New(h.svc)
	for profile, want := range map[string]string{
		"intermediate-ca": "cannot be used for ACME",
		"sever":           "", // any error; the point is it isn't stored
	} {
		_, err := svc.CreateEAB(context.Background(), acme.CreateEABInput{Name: "p", Profile: profile, Actor: "t"})
		if err == nil {
			t.Fatalf("profile %q was accepted", profile)
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Fatalf("profile %q: error %q, want it to mention %q", profile, err, want)
		}
	}
	if _, err := svc.CreateEAB(context.Background(), acme.CreateEABInput{Name: "ok", Profile: "server-client", AllowAnyDomain: true, Actor: "t"}); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
}

// --- H1: the CSR can only carry what the order authorized ----------------

func TestACMEFinalizeRejectsNonDNSNames(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "scoped", AllowedDomains: []string{"*.allowed.internal"}, Actor: "t"})
	c := registerACME(t, srv, eab)
	spiffe, _ := url.Parse("spiffe://prod.example/ns/kube-system/sa/admin")

	for name, extra := range map[string]func(*x509.CertificateRequest){
		"ip":    func(r *x509.CertificateRequest) { r.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")} },
		"uri":   func(r *x509.CertificateRequest) { r.URIs = []*url.URL{spiffe} },
		"email": func(r *x509.CertificateRequest) { r.EmailAddresses = []string{"ceo@example.com"} },
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := &x509.CertificateRequest{DNSNames: []string{"app.allowed.internal"}}
			extra(tmpl)
			_, _, err := orderAndFinalize(t, c, tmpl, "app.allowed.internal")
			wantACMEProblem(t, err, "badCSR")
		})
	}
}

func TestACMEFinalizeRejectsCommonNameOutsideOrder(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "scoped", AllowedDomains: []string{"*.allowed.internal"}, Actor: "t"})
	c := registerACME(t, srv, eab)
	_, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "goca.mylab.lan"},
		DNSNames: []string{"app.allowed.internal"},
	}, "app.allowed.internal")
	wantACMEProblem(t, err, "badCSR")
}

func TestACMECertificateSubjectIsCommonNameOnly(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "scoped", AllowedDomains: []string{"*.allowed.internal"}, Actor: "t"})
	c := registerACME(t, srv, eab)
	leaf, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "app.allowed.internal",
			Organization:       []string{"system:masters"},
			OrganizationalUnit: []string{"ops"},
		},
		DNSNames: []string{"app.allowed.internal"},
	}, "app.allowed.internal")
	if err != nil {
		t.Fatalf("a CSR whose CN is one of the order's names was refused: %v", err)
	}
	if len(leaf.Subject.Organization) != 0 || len(leaf.Subject.OrganizationalUnit) != 0 {
		t.Fatalf("CSR subject attributes leaked into the certificate: %v", leaf.Subject)
	}
	if leaf.Subject.CommonName != "app.allowed.internal" {
		t.Fatalf("CN = %q, want app.allowed.internal", leaf.Subject.CommonName)
	}
}

func TestACMEWildcardCommonNameStillAccepted(t *testing.T) {
	// cert-manager sets CN to the wildcard name when spec.commonName is set,
	// as the live *.k8s.mylab.lan certificate does - this must keep working.
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "w", AllowedDomains: []string{"*.lab.internal"}, Actor: "t"})
	c := registerACME(t, srv, eab)
	leaf, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "*.k8s.lab.internal"},
		DNSNames: []string{"k8s.lab.internal", "*.k8s.lab.internal"},
	}, "k8s.lab.internal", "*.k8s.lab.internal")
	if err != nil {
		t.Fatalf("wildcard order refused: %v", err)
	}
	if leaf.Subject.CommonName != "*.k8s.lab.internal" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
}

func TestACMERejectsMalformedIdentifiers(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "open", Actor: "t"}) // no domain scope
	c := registerACME(t, srv, eab)
	for _, id := range []string{"*", "*.com", "10.0.0.1", "a..b.internal", "*.*.internal", "foo.*.internal", "-x.internal", "under_score.internal"} {
		t.Run(id, func(t *testing.T) {
			_, err := c.AuthorizeOrder(context.Background(), xacme.DomainIDs(id))
			wantACMEProblem(t, err, "rejectedIdentifier")
		})
	}
}

// --- H3: disabling a credential cuts off its accounts; admins can deactivate one

func TestACMEDisabledEABBlocksExistingAccounts(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "leaked", Actor: "t"})
	c := registerACME(t, srv, eab)
	svc := acme.New(h.svc)
	ctx := context.Background()

	if err := svc.SetEABDisabled(ctx, eab.Cred.ID, true, "admin"); err != nil {
		t.Fatal(err)
	}
	_, err := c.AuthorizeOrder(ctx, xacme.DomainIDs("after-disable.internal"))
	wantACMEProblem(t, err, "unauthorized")

	// Re-enabling restores the same account.
	if err := svc.SetEABDisabled(ctx, eab.Cred.ID, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{DNSNames: []string{"after-enable.internal"}}, "after-enable.internal"); err != nil {
		t.Fatalf("re-enabled credential's account still blocked: %v", err)
	}
}

func TestACMEDisableBlocksFinalizeOfAnAlreadyOpenOrder(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "leaked", Actor: "t"})
	c := registerACME(t, srv, eab)
	ctx := context.Background()
	o, err := c.AuthorizeOrder(ctx, xacme.DomainIDs("open.internal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := acme.New(h.svc).SetEABDisabled(ctx, eab.Cred.ID, true, "admin"); err != nil {
		t.Fatal(err)
	}
	csr, _ := generateTestCSR(t, "open.internal")
	_, _, err = c.CreateOrderCert(ctx, o.FinalizeURL, csr, true)
	wantACMEProblem(t, err, "unauthorized")
}

func TestACMEMaxAccountsDoesNotBlockTheOneAccount(t *testing.T) {
	// activeCred must not reuse EABCred.Usable(): with max_accounts=1 the one
	// permitted account would otherwise be locked out by its own existence.
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "one-shot", MaxAccounts: 1, Actor: "t"})
	c := registerACME(t, srv, eab)
	if _, _, err := orderAndFinalize(t, c, &x509.CertificateRequest{DNSNames: []string{"x.internal"}}, "x.internal"); err != nil {
		t.Fatalf("the single permitted account cannot order: %v", err)
	}
}

func TestAdminCanDeactivateACMEAccount(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "c", Actor: "t"})
	victim := registerACME(t, srv, eab)
	sibling := registerACME(t, srv, eab)

	accts, err := acme.New(h.svc).ListAccounts(context.Background())
	if err != nil || len(accts) != 2 {
		t.Fatalf("accounts = %d, %v", len(accts), err)
	}
	victimID := accts[0].ID
	if accts[1].ID < victimID { // ListAccounts order is not part of the contract
		victimID = accts[1].ID
	}
	path := fmt.Sprintf("/api/v1/acme/accounts/%d/deactivate", victimID)

	// Baseline: the victim can order right now. Without this, the
	// "unauthorized" asserted below could come from anything (it once came
	// from a harness URL mismatch) rather than from the deactivation.
	if _, err := victim.AuthorizeOrder(context.Background(), xacme.DomainIDs("before.internal")); err != nil {
		t.Fatalf("victim cannot order even before deactivation: %v", err)
	}

	if rec, _ := h.apiJSON("POST", path, "", h.token("user")); rec.Code != http.StatusForbidden {
		t.Fatalf("user-role token: status %d, want 403", rec.Code)
	}
	if rec, _ := h.apiJSON("POST", path, "", h.token("admin")); rec.Code != http.StatusOK {
		t.Fatalf("admin deactivate: status %d: %s", rec.Code, rec.Body)
	}
	if rec, _ := h.apiJSON("POST", path, "", h.token("admin")); rec.Code != http.StatusBadRequest {
		t.Fatalf("second deactivate: status %d, want 400", rec.Code)
	}
	if rec, _ := h.apiJSON("POST", "/api/v1/acme/accounts/99999/deactivate", "", h.token("admin")); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown account: status %d, want 404", rec.Code)
	}

	// The first-registered account (victimID is the lower id) is cut off; its
	// sibling under the same credential is unaffected.
	_, err = victim.AuthorizeOrder(context.Background(), xacme.DomainIDs("v.internal"))
	wantACMEProblem(t, err, "unauthorized")
	if _, _, err := orderAndFinalize(t, sibling, &x509.CertificateRequest{DNSNames: []string{"s.internal"}}, "s.internal"); err != nil {
		t.Fatalf("sibling account affected by deactivating another: %v", err)
	}
}

// --- H4: certificate download is authenticated and scoped -----------------

func TestACMECertDownloadIsNotAnEnumerationOracle(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	// A certificate issued outside ACME.
	if rec, _ := h.apiJSON("POST", "/api/v1/certificates",
		`{"mode":"generate","subject":{"common_name":"secret-db.corp"},"sans":["secret-db.corp"],"key_type":"ec-p256"}`,
		h.token("admin")); rec.Code != http.StatusCreated {
		t.Fatalf("setup: %s", rec.Body)
	}

	// No unauthenticated GET at all.
	for id := 1; id <= 3; id++ {
		rec := h.do(httptest.NewRequest(http.MethodGet, fmt.Sprintf("/acme/cert/%d", id), nil))
		if rec.Code == http.StatusOK {
			t.Fatalf("unauthenticated GET /acme/cert/%d served a certificate", id)
		}
	}

	eabA := createTestEAB(t, h, acme.CreateEABInput{Name: "a", Actor: "t"})
	eabB := createTestEAB(t, h, acme.CreateEABInput{Name: "b", Actor: "t"})
	owner := registerACME(t, srv, eabA)
	other := registerACME(t, srv, eabB)
	_, certURL, err := orderAndFinalize(t, owner, &x509.CertificateRequest{DNSNames: []string{"mine.internal"}}, "mine.internal")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// The owner can fetch it again (POST-as-GET).
	if _, err := owner.FetchCert(ctx, certURL, true); err != nil {
		t.Fatalf("owner cannot fetch its own certificate: %v", err)
	}
	// Another account cannot - and gets the same answer as for an id that
	// doesn't exist, so it learns nothing.
	_, err = other.FetchCert(ctx, certURL, true)
	wantACMEProblem(t, err, "malformed")
	if ae := err.(*xacme.Error); ae.StatusCode != http.StatusNotFound {
		t.Fatalf("another account's fetch: status %d (%s), want 404 - the same answer as a missing id", ae.StatusCode, ae.Detail)
	}
}

// --- M1: revocation follows the credential id, not its (non-unique) name ---

func TestACMERevokeIsKeyedOnCredentialIDNotName(t *testing.T) {
	h := newHarness(t)
	srv := acmeServer(t, h)
	// Two credentials that happen to share a name - names are not unique.
	teamA := createTestEAB(t, h, acme.CreateEABInput{Name: "cert-manager", AllowedDomains: []string{"*.team-a.internal"}, Actor: "t"})
	teamB := createTestEAB(t, h, acme.CreateEABInput{Name: "cert-manager", AllowedDomains: []string{"*.team-b.internal"}, Actor: "t"})
	victim := registerACME(t, srv, teamA)
	attacker := registerACME(t, srv, teamB)
	ctx := context.Background()

	cert, _, err := orderAndFinalize(t, victim, &x509.CertificateRequest{DNSNames: []string{"db.team-a.internal"}}, "db.team-a.internal")
	if err != nil {
		t.Fatal(err)
	}
	err = attacker.RevokeCert(ctx, nil, cert.Raw, xacme.CRLReasonKeyCompromise)
	wantACMEProblem(t, err, "unauthorized")

	// A second account bootstrapped from the SAME credential may revoke it -
	// the credential is the unit of trust (cert-manager re-registers under it).
	sibling := registerACME(t, srv, teamA)
	if err := sibling.RevokeCert(ctx, nil, cert.Raw, xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("an account from the issuing credential could not revoke: %v", err)
	}
}

func TestACMERevokeRefusesNonACMECertificate(t *testing.T) {
	// A certificate issued through the API has no order; an ACME account must
	// not be able to revoke it just because the requested-by text matches.
	h := newHarness(t)
	srv := acmeServer(t, h)
	rec, out := h.apiJSON("POST", "/api/v1/certificates",
		`{"mode":"generate","subject":{"common_name":"api-issued.internal"},"sans":["api-issued.internal"],"key_type":"ec-p256"}`,
		h.token("admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: %s", rec.Body)
	}
	blk, _ := pem.Decode([]byte(out["certificate"].(map[string]any)["cert_pem"].(string)))
	c := registerACME(t, srv, createTestEAB(t, h, acme.CreateEABInput{Name: "x", Actor: "t"}))
	err := c.RevokeCert(context.Background(), nil, blk.Bytes, xacme.CRLReasonKeyCompromise)
	wantACMEProblem(t, err, "unauthorized")
}
