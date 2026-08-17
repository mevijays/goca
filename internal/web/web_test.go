package web

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

const testAdminPassword = "TestPassw0rd!"

type harness struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	svc     *ca.Service
	mgr     *auth.Manager
	root    *store.CA
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "web.db")
	cfg.Server.BaseURL = "http://ca.test"
	if err := cfg.GenerateSecrets(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.LocalAdmin = config.LocalAdmin{Username: "admin", PasswordHash: hash}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	svc, err := ca.New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := auth.NewManager(cfg, st, svc.Box())
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureLocalAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv, err := NewServer(svc, mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	root, err := svc.CreateCA(context.Background(), ca.CreateCAInput{
		Name:    "Web Test CA",
		Subject: pki.Subject{CommonName: "Web Test CA"},
		KeyType: "ec-p256",
		Days:    3650,
		Actor:   "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	return &harness{t: t, srv: srv, handler: srv.Handler(), svc: svc, mgr: mgr, root: root}
}

// do issues a request against the handler.
func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// session logs in as the admin and returns the cookies plus the CSRF token.
func (h *harness) session() (cookies []*http.Cookie, csrf string) {
	h.t.Helper()

	loginPage := h.do(httptest.NewRequest(http.MethodGet, "/login", nil))
	cookies = loginPage.Result().Cookies()
	for _, c := range cookies {
		if c.Name == csrfCookie {
			csrf = c.Value
		}
	}
	if csrf == "" {
		h.t.Fatal("the login page did not set a CSRF cookie")
	}

	form := url.Values{"username": {"admin"}, "password": {testAdminPassword}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := h.do(req)
	if rec.Code != http.StatusSeeOther {
		h.t.Fatalf("login returned %d, want 303: %s", rec.Code, rec.Body.String())
	}
	cookies = append(cookies, rec.Result().Cookies()...)
	return cookies, csrf
}

func (h *harness) get(path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return h.do(req)
}

// token mints an API token for the admin.
func (h *harness) token(role string) string {
	h.t.Helper()
	u, err := h.svc.Store().GetUserByName(context.Background(), "admin")
	if err != nil {
		h.t.Fatal(err)
	}
	tok, _, err := h.mgr.IssueAPIToken(context.Background(), u, "test-"+role, role, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) apiJSON(method, path, body, token string) (*httptest.ResponseRecorder, map[string]any) {
	h.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := h.do(req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

//
// ---------- routing ----------
//

// TestHandlerRegistersAllRoutes catches malformed ServeMux patterns, which
// panic at registration rather than at request time.
func TestHandlerRegistersAllRoutes(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("building the route table panicked: %v", r)
		}
	}()
	h := newHarness(t)
	if h.handler == nil {
		t.Fatal("nil handler")
	}
}

// TestOIDCRoutesAreDisabledByDefault guards the common case (no OIDC
// configured): the routes exist but 404 rather than panicking or redirecting
// somewhere odd, and the login page doesn't offer an SSO button nobody could
// use.
func TestOIDCRoutesAreDisabledByDefault(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/auth/oidc/login", "/auth/oidc/callback"} {
		if rec := h.get(path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s with OIDC unconfigured returned %d, want 404", path, rec.Code)
		}
	}
	login := h.get("/login", nil).Body.String()
	if strings.Contains(login, "Sign in with SSO") {
		t.Error("the login page offered SSO with no OIDC provider configured")
	}
}

func TestPublicEndpointsNeedNoAuth(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/healthz",
		"/api/v1/health",
		"/public/ca/" + h.root.Slug + ".crt",
		"/public/ca/" + h.root.Slug + ".pem",
		"/public/ca/" + h.root.Slug + ".der",
		"/public/crl/" + h.root.Slug + ".crl",
		"/public/crl/" + h.root.Slug + ".pem",
		"/static/app.css",
		"/static/app.js",
	} {
		rec := h.get(path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s returned an empty body", path)
		}
	}

	// The published certificate must be the real one.
	rec := h.get("/public/ca/"+h.root.Slug+".crt", nil)
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Error("the public CA endpoint did not return PEM")
	}
	if _, err := pki.ParseCertPEM(rec.Body.Bytes()); err != nil {
		t.Errorf("the published CA certificate does not parse: %v", err)
	}

	// An unknown slug is a 404, not a 500.
	if rec := h.get("/public/ca/nope.crt", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown CA slug returned %d, want 404", rec.Code)
	}
}

func TestPagesRequireLogin(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/cas", "/certificates", "/certificates/new", "/settings", "/audit"} {
		rec := h.get(path, nil)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET %s unauthenticated returned %d, want a redirect", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
			t.Errorf("GET %s redirected to %q, want /login", path, loc)
		}
	}
}

func TestLoginAndBrowsePages(t *testing.T) {
	h := newHarness(t)
	cookies, _ := h.session()

	for _, path := range []string{
		"/", "/cas", "/cas/new", "/certificates", "/certificates/new",
		"/tools/csr", "/tools/ssl", "/settings", "/audit",
		"/cas/1", "/cas/1/download/ca.crt", "/cas/1/download/chain.pem", "/cas/1/download/bundle.zip",
	} {
		rec := h.get(path, cookies)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s returned %d, want 200: %s", path, rec.Code, truncBody(rec))
		}
		if strings.Contains(rec.Body.String(), "template error") {
			t.Errorf("GET %s rendered a template error", path)
		}
	}
}

func TestBadCredentialsAreRejected(t *testing.T) {
	h := newHarness(t)
	page := h.do(httptest.NewRequest(http.MethodGet, "/login", nil))
	var csrf string
	for _, c := range page.Result().Cookies() {
		if c.Name == csrfCookie {
			csrf = c.Value
		}
	}
	form := url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range page.Result().Cookies() {
		req.AddCookie(c)
	}
	rec := h.do(req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bad password returned %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Error("a session cookie was issued for a failed login")
		}
	}
}

func TestPostWithoutCSRFIsRejected(t *testing.T) {
	h := newHarness(t)
	cookies, _ := h.session()

	form := url.Values{"common_name": {"nocsrf.test"}, "mode": {"generate"}}
	req := httptest.NewRequest(http.MethodPost, "/certificates/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := h.do(req)
	if rec.Code == http.StatusOK {
		t.Error("a POST without a CSRF token was accepted")
	}

	_, total, err := h.svc.Search(context.Background(), store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Error("the CSRF-less POST issued a certificate anyway")
	}
}

//
// ---------- web issuance ----------
//

func TestIssueThroughTheWebForm(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()

	form := url.Values{
		"csrf_token":   {csrf},
		"mode":         {"generate"},
		"ca":           {"1"},
		"common_name":  {"web.test"},
		"sans":         {"web.test, 10.0.0.7"},
		"key_type":     {"ec-p256"},
		"profile":      {"server"},
		"days":         {"30"},
		"store_key":    {"1"},
		"organization": {"Testing"},
	}
	req := httptest.NewRequest(http.MethodPost, "/certificates/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := h.do(req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("issuing returned %d, want 303: %s", rec.Code, truncBody(rec))
	}

	certs, total, err := h.svc.Search(context.Background(), store.CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("expected 1 certificate, got %d", total)
	}
	got := certs[0]
	if got.CommonName != "web.test" {
		t.Errorf("common name is %q", got.CommonName)
	}
	if !got.HasKey {
		t.Error("the key should have been stored")
	}

	// Every download the detail page offers must work.
	for _, file := range []string{"cert.pem", "cert.crt", "cert.der", "key.pem",
		"chain.pem", "fullchain.pem", "request.csr", "bundle.zip"} {
		rec := h.get("/certificates/1/download/"+file, cookies)
		if rec.Code != http.StatusOK {
			t.Errorf("download %s returned %d", file, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("download %s was empty", file)
		}
	}
	if rec := h.get("/certificates/1/download/nonsense", cookies); rec.Code != http.StatusNotFound {
		t.Errorf("unknown download name returned %d, want 404", rec.Code)
	}
}

//
// ---------- API ----------
//

func TestAPIRequiresAuthentication(t *testing.T) {
	h := newHarness(t)
	rec, _ := h.apiJSON(http.MethodGet, "/api/v1/cas", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated API call returned %d, want 401", rec.Code)
	}
	rec, _ = h.apiJSON(http.MethodGet, "/api/v1/cas", "", "goca_deadbeef_notarealtoken")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a bogus token returned %d, want 401", rec.Code)
	}
}

func TestAPIIssueAndDownload(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	body := `{"subject":{"common_name":"api.test"},"sans":["api.test","10.0.0.9"],
	          "key_type":"ec-p256","profile":"server","days":30}`
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/certificates", body, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue returned %d: %s", rec.Code, truncBody(rec))
	}
	if key, _ := out["private_key_pem"].(string); !strings.Contains(key, "PRIVATE KEY") {
		t.Error("the response carried no private key")
	}
	if chain, _ := out["chain_pem"].(string); !strings.Contains(chain, "BEGIN CERTIFICATE") {
		t.Error("the response carried no chain")
	}
	cert, _ := out["certificate"].(map[string]any)
	if cert == nil || cert["common_name"] != "api.test" {
		t.Fatalf("unexpected certificate payload: %v", out["certificate"])
	}
	serial, _ := cert["serial"].(string)

	// A historical lookup by serial must return the same certificate.
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/certificates/"+serial, "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup by serial returned %d", rec.Code)
	}
	if got, _ := out["common_name"].(string); got != "api.test" {
		t.Errorf("serial lookup returned %q", got)
	}

	// And the key remains downloadable.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/1/download/key.pem", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if rec := h.do(req); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Errorf("key download returned %d", rec.Code)
	}
}

func TestAPIIssueFromSuppliedCSR(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	gen, err := h.svc.GenerateCSR(context.Background(), ca.GenerateCSRInput{
		Subject: pki.Subject{CommonName: "byo-api.test"},
		SANs:    []string{"byo-api.test"},
		KeyType: "rsa-2048",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"mode": "csr", "csr_pem": gen.CSRPEM, "days": 30,
	})
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/certificates", string(payload), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("CSR issuance returned %d: %s", rec.Code, truncBody(rec))
	}
	cert, _ := out["certificate"].(map[string]any)
	if cert["common_name"] != "byo-api.test" {
		t.Errorf("subject from the CSR was lost: %v", cert["common_name"])
	}
	// No key was supplied, so none should be stored.
	if stored, _ := out["key_stored"].(bool); stored {
		t.Error("a key was stored for a CSR-only request")
	}
}

func TestAPIRevokeAndCRL(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"revoke.test"},"key_type":"ec-p256","days":30}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue returned %d", rec.Code)
	}
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/certificates/1/revoke",
		`{"reason":"keyCompromise"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke returned %d: %s", rec.Code, truncBody(rec))
	}
	if out["reason"] != "key compromise" {
		t.Errorf("reason came back as %v", out["reason"])
	}

	rec, out = h.apiJSON(http.MethodPost, "/api/v1/cas/1/crl", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("CRL generation returned %d", rec.Code)
	}
	if crl, _ := out["crl_pem"].(string); !strings.Contains(crl, "X509 CRL") {
		t.Error("no CRL in the response")
	}
}

func TestAPIRoleSeparation(t *testing.T) {
	h := newHarness(t)
	userTok := h.token(store.RoleUser)

	// A user-scoped token may issue but must not administer.
	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"user.test"},"key_type":"ec-p256","days":30}`, userTok)
	if rec.Code != http.StatusCreated {
		t.Errorf("a user token could not issue a certificate: %d", rec.Code)
	}

	for _, call := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/cas", `{"name":"x","subject":{"common_name":"x"}}`},
		{http.MethodDelete, "/api/v1/cas/1", ""},
		{http.MethodGet, "/api/v1/users", ""},
		{http.MethodGet, "/api/v1/audit", ""},
	} {
		rec, _ := h.apiJSON(call.method, call.path, call.body, userTok)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s with a user token returned %d, want 403", call.method, call.path, rec.Code)
		}
	}

	// A CA private key is admin-only even though the CA itself is readable.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cas/1/download/ca.key", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	if rec := h.do(req); rec.Code != http.StatusForbidden {
		t.Errorf("CA key download with a user token returned %d, want 403", rec.Code)
	}
}

func TestAPIGenerateCSRAndInspect(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleUser)

	rec, out := h.apiJSON(http.MethodPost, "/api/v1/csr",
		`{"subject":{"common_name":"standalone.test"},"sans":["standalone.test"],"key_type":"ed25519"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("CSR generation returned %d: %s", rec.Code, truncBody(rec))
	}
	csrPEM, _ := out["csr_pem"].(string)
	keyPEM, _ := out["private_key_pem"].(string)
	if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") || !strings.Contains(keyPEM, "PRIVATE KEY") {
		t.Fatal("CSR generation returned an incomplete pair")
	}

	payload, _ := json.Marshal(map[string]string{"pem": csrPEM})
	rec, out = h.apiJSON(http.MethodPost, "/api/v1/inspect", string(payload), tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("inspect returned %d", rec.Code)
	}
	if out["type"] != "csr" {
		t.Errorf("inspect classified the input as %v", out["type"])
	}
}

func TestAPIRejectsUnknownFields(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)
	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"x.test"},"typo_field":true}`, tok)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown JSON field returned %d, want 400", rec.Code)
	}
}

//
// ---------- misc ----------
//

func TestSecurityHeadersArePresent(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/login", nil)
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("unexpected CSP: %q", csp)
	}
}

//
// ---------- SSL utility ----------
//

// selfSignedTestCert builds a throwaway self-signed cert/key pair, entirely
// independent of the harness's own CA, for feeding to the SSL utility.
func selfSignedTestCert(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyECP256)
	if err != nil {
		t.Fatal(err)
	}
	signer := key.(crypto.Signer)
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pki.EncodeCertPEM(der)), string(keyBytes)
}

// sslInspect POSTs to /tools/ssl with no cookies at all, proving the
// endpoint needs neither a session nor a CSRF token.
func (h *harness) sslInspect(input string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/tools/ssl",
		strings.NewReader(url.Values{"input_text": {input}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(req)
}

func TestSSLUtilityIsAnonymous(t *testing.T) {
	h := newHarness(t)
	rec := h.get("/tools/ssl", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tools/ssl unauthenticated returned %d, want 200: %s", rec.Code, truncBody(rec))
	}
	if !strings.Contains(rec.Body.String(), "SSL utility") {
		t.Error("the page did not render")
	}
}

// TestSSLUtilityAnonymousLayoutMatchesLoggedIn guards against the page
// looking different for a signed-out visitor - it should get the same
// topbar/nav shell as a logged-in user, just without the links and user box
// that need an account, plus a Sign in link in their place.
func TestSSLUtilityAnonymousLayoutMatchesLoggedIn(t *testing.T) {
	h := newHarness(t)
	anon := h.get("/tools/ssl", nil).Body.String()

	for _, want := range []string{
		`<header class="topbar">`, `class="brand"`, `class="mainnav"`,
		`SSL utility</a>`, `class="active"`, `href="/login">Sign in</a>`,
		`class="with-nav"`, `class="footer"`,
	} {
		if !strings.Contains(anon, want) {
			t.Errorf("anonymous /tools/ssl is missing %q - layout differs from a logged-in page", want)
		}
	}
	// Links that need an account should not appear for an anonymous visitor.
	for _, dontWant := range []string{`>Dashboard<`, `>Authorities<`, `>Certificates<`, `>Settings<`, `class="plain"`} {
		if strings.Contains(anon, dontWant) {
			t.Errorf("anonymous /tools/ssl unexpectedly contains %q", dontWant)
		}
	}

	cookies, _ := h.session()
	loggedIn := h.get("/tools/ssl", cookies).Body.String()
	for _, want := range []string{`<header class="topbar">`, `class="with-nav"`, `SSL utility</a>`} {
		if !strings.Contains(loggedIn, want) {
			t.Errorf("logged-in /tools/ssl is missing %q", want)
		}
	}
}

func TestSSLUtilityKeyMatchesItsCertificate(t *testing.T) {
	h := newHarness(t)
	certPEM, keyPEM := selfSignedTestCert(t, "match.test")

	rec := h.sslInspect(certPEM + "\n" + keyPEM)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /tools/ssl returned %d, want 200: %s", rec.Code, truncBody(rec))
	}
	body := rec.Body.String()
	for _, want := range []string{"Certificate #1", "match.test", "Private key", `badge ok">&check; Certificate #1`} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q:\n%s", want, body)
		}
	}
	// The private key's own material must never be echoed back - not in the
	// decoded summary, and not in the textarea the form redisplays either.
	// Checked one base64 line at a time (not the whole multi-line body) so a
	// partial leak fails this just as loudly as a full one.
	for _, line := range strings.Split(keyPEM, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if strings.Contains(body, line) {
			t.Errorf("the response leaked a line of the private key's own PEM body: %q", line)
		}
	}
}

func TestSSLUtilityKeyDoesNotMatchUnrelatedCertificate(t *testing.T) {
	h := newHarness(t)
	certPEM, _ := selfSignedTestCert(t, "cert-a.test")
	_, otherKeyPEM := selfSignedTestCert(t, "cert-b.test")

	rec := h.sslInspect(certPEM + "\n" + otherKeyPEM)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /tools/ssl returned %d: %s", rec.Code, truncBody(rec))
	}
	body := rec.Body.String()
	if strings.Contains(body, "badge ok\">&check;") {
		t.Error("an unrelated key was reported as matching the certificate")
	}
	if !strings.Contains(body, "no other block in this input shares this key") {
		t.Error("expected a no-match message for an unrelated key")
	}
}

func TestSSLUtilityParsesACSR(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleUser)
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/csr",
		`{"subject":{"common_name":"csr.test"},"key_type":"ec-p256"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("CSR generation returned %d: %s", rec.Code, truncBody(rec))
	}
	csrPEM, _ := out["csr_pem"].(string)

	rec2 := h.sslInspect(csrPEM)
	body := rec2.Body.String()
	if !strings.Contains(body, "Certificate signing request") || !strings.Contains(body, "csr.test") {
		t.Errorf("CSR was not decoded:\n%s", truncBody(rec2))
	}
	if !strings.Contains(body, "signature verifies") {
		t.Error("a validly signed CSR should report its signature verifies")
	}
}

func TestSSLUtilityRejectsGarbageInput(t *testing.T) {
	h := newHarness(t)
	rec := h.sslInspect("this is not PEM data at all")
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d, want 200 (a friendly error, not a 500)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No PEM data found") {
		t.Error("expected a friendly \"no PEM data\" message")
	}
}

func TestSSLUtilityReportsAPerBlockParseError(t *testing.T) {
	h := newHarness(t)
	// Well-formed PEM armor, garbage DER inside - decodes as a block, fails
	// to parse as a certificate.
	bad := "-----BEGIN CERTIFICATE-----\n" +
		"bm90IGEgcmVhbCBjZXJ0aWZpY2F0ZSBkZXIgY29udGVudA==\n" +
		"-----END CERTIFICATE-----\n"
	rec := h.sslInspect(bad)
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Certificate #1") || !strings.Contains(body, "badge danger") {
		t.Errorf("expected a per-block error, got:\n%s", truncBody(rec))
	}
}

func TestSSLUtilityAcceptsFileUpload(t *testing.T) {
	h := newHarness(t)
	certPEM, _ := selfSignedTestCert(t, "upload.test")

	var buf strings.Builder
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("input_file", "leaf.crt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte(certPEM))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/tools/ssl", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := h.do(req)
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d: %s", rec.Code, truncBody(rec))
	}
	if !strings.Contains(rec.Body.String(), "upload.test") {
		t.Error("an uploaded certificate file was not decoded")
	}
}

func TestSSLUtilityOversizedBodyIsRejectedNotCrashed(t *testing.T) {
	h := newHarness(t)
	huge := strings.Repeat("A", 3<<20) // over the 2 MB cap
	rec := h.sslInspect(huge)
	if rec.Code != http.StatusOK {
		t.Fatalf("returned %d, want a friendly 200 error page", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2 MB max") {
		t.Error("expected the oversized-body message")
	}
}

func TestSessionCookieIsHttpOnly(t *testing.T) {
	h := newHarness(t)
	cookies, _ := h.session()
	for _, c := range cookies {
		if c.Name == sessionCookie && !c.HttpOnly {
			t.Error("the session cookie is not HttpOnly")
		}
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()

	req := httptest.NewRequest(http.MethodPost, "/logout",
		strings.NewReader(url.Values{"csrf_token": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if rec := h.do(req); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", rec.Code)
	}
	if rec := h.get("/", cookies); rec.Code != http.StatusSeeOther {
		t.Error("the session still works after logging out")
	}
}

func TestEmbeddedAssetsAreInTheBinary(t *testing.T) {
	// The portal must not depend on files next to the binary.
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Errorf("only %d templates embedded", len(entries))
	}
	for _, name := range []string{"app.css", "app.js", "favicon.svg"} {
		if _, err := staticFS.ReadFile(filepath.Join("static", name)); err != nil {
			t.Errorf("static asset %s is not embedded: %v", name, err)
		}
	}
	if _, err := os.Stat("templates"); err == nil {
		// Present in the source tree, but the server must read the embedded
		// copy - loadTemplates uses templateFS, which this asserts compiles.
		if _, err := loadTemplates(); err != nil {
			t.Errorf("loadTemplates: %v", err)
		}
	}
}

func truncBody(rec *httptest.ResponseRecorder) string {
	s := rec.Body.String()
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

//
// ---------- external CA integration & lifecycle over HTTP ----------
//

// TestExternalCARoutesRegister guards the newer route patterns, including the
// literal /cas/pending and /cas/request segments that sit alongside /cas/{id}.
func TestExternalCARoutesRegister(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	// A literal path must win over the {id} wildcard rather than 400ing.
	rec, _ := h.apiJSON(http.MethodGet, "/api/v1/cas/pending", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/cas/pending returned %d, want 200: %s", rec.Code, truncBody(rec))
	}
}

func TestAPISubordinateFlow(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	// 1. request
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/cas/request",
		`{"name":"API Sub","subject":{"common_name":"API Sub"},"key_type":"ec-p256"}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("request returned %d: %s", rec.Code, truncBody(rec))
	}
	csrPEM, _ := out["csr_pem"].(string)
	if !strings.Contains(csrPEM, "CERTIFICATE REQUEST") {
		t.Fatal("no CSR returned")
	}
	caMap, _ := out["ca"].(map[string]any)
	if caMap["status"] != "pending" {
		t.Errorf("new request has status %v, want pending", caMap["status"])
	}
	caID := int(caMap["id"].(float64))

	// It shows up as pending, and its CSR is retrievable.
	_, out = h.apiJSON(http.MethodGet, "/api/v1/cas/pending", "", tok)
	if n, _ := out["count"].(float64); int(n) != 1 {
		t.Errorf("pending count is %v, want 1", out["count"])
	}
	rec, out = h.apiJSON(http.MethodGet, fmt.Sprintf("/api/v1/cas/%d/csr", caID), "", tok)
	if rec.Code != http.StatusOK || !strings.Contains(out["csr_pem"].(string), "CERTIFICATE REQUEST") {
		t.Error("the stored CSR could not be fetched")
	}

	// 2. an external authority signs it
	ext := newExternalSigner(t)
	signed := ext.sign(t, csrPEM)

	// 3. import it back with the external root as the chain
	body, _ := json.Marshal(map[string]string{"cert_pem": signed, "chain_pem": ext.rootPEM})
	rec, out = h.apiJSON(http.MethodPost,
		fmt.Sprintf("/api/v1/cas/%d/import-signed", caID), string(body), tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("import-signed returned %d: %s", rec.Code, truncBody(rec))
	}
	if complete, _ := out["chain_complete"].(bool); !complete {
		t.Error("the chain should be complete after importing the root")
	}

	// 4. it can now issue
	rec, _ = h.apiJSON(http.MethodPost, "/api/v1/certificates",
		fmt.Sprintf(`{"ca":"%d","subject":{"common_name":"via-external.test"},`+
			`"key_type":"ec-p256","days":30}`, caID), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issuing from the imported CA returned %d: %s", rec.Code, truncBody(rec))
	}
}

func TestAPIImportTrustAnchorCannotIssue(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)
	ext := newExternalSigner(t)

	body, _ := json.Marshal(map[string]string{"cert_pem": ext.rootPEM, "name": "External Root"})
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/cas/import", string(body), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("import returned %d: %s", rec.Code, truncBody(rec))
	}
	if canIssue, _ := out["can_issue"].(bool); canIssue {
		t.Error("a key-less anchor reports that it can issue")
	}
}

func TestAPIImportRequiresAdmin(t *testing.T) {
	h := newHarness(t)
	userTok := h.token(store.RoleUser)
	ext := newExternalSigner(t)

	body, _ := json.Marshal(map[string]string{"cert_pem": ext.rootPEM})
	for _, path := range []string{"/api/v1/cas/import", "/api/v1/cas/request"} {
		rec, _ := h.apiJSON(http.MethodPost, path, string(body), userTok)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a user token returned %d, want 403", path, rec.Code)
		}
	}
}

func TestAPIRenewHoldRelease(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"rotate.test"},"sans":["rotate.test"],"key_type":"ec-p256","days":60}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue returned %d", rec.Code)
	}

	// renew
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/certificates/1/renew", `{"days":90}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("renew returned %d: %s", rec.Code, truncBody(rec))
	}
	newCert, _ := out["certificate"].(map[string]any)
	if newCert["common_name"] != "rotate.test" {
		t.Errorf("the replacement lost its identity: %v", newCert["common_name"])
	}
	if newCert["serial"] == nil || newCert["serial"] == "" {
		t.Error("no serial on the replacement")
	}

	// history now has two entries
	_, out = h.apiJSON(http.MethodGet, "/api/v1/certificates/1/history", "", tok)
	hist, _ := out["history"].([]any)
	if len(hist) != 2 {
		t.Errorf("history has %d entries, want 2", len(hist))
	}

	// hold then release the original
	rec, out = h.apiJSON(http.MethodPost, "/api/v1/certificates/1/hold", "", tok)
	if rec.Code != http.StatusOK || out["status"] != "on_hold" {
		t.Fatalf("hold returned %d (%v)", rec.Code, out["status"])
	}
	rec, out = h.apiJSON(http.MethodPost, "/api/v1/certificates/1/release", "", tok)
	if rec.Code != http.StatusOK || out["status"] != "active" {
		t.Fatalf("release returned %d (%v)", rec.Code, out["status"])
	}
}

func TestAPIBulkRevokeNeedsAFilter(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/certificates/bulk-revoke", `{}`, tok)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unfiltered bulk revoke returned %d, want 400", rec.Code)
	}

	h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"bulk-a.test"},"key_type":"ec-p256","days":30}`, tok)
	h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"bulk-b.test"},"key_type":"ec-p256","days":30}`, tok)

	rec, out := h.apiJSON(http.MethodPost, "/api/v1/certificates/bulk-revoke",
		`{"query":"bulk-","reason":"superseded"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk revoke returned %d: %s", rec.Code, truncBody(rec))
	}
	if n, _ := out["count"].(float64); int(n) != 2 {
		t.Errorf("revoked %v certificates, want 2", out["count"])
	}
}

func TestPagesForExternalCAFlow(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()

	// The import wizard renders.
	if rec := h.get("/cas/import", cookies); rec.Code != http.StatusOK {
		t.Fatalf("GET /cas/import returned %d", rec.Code)
	}

	// Creating a request through the form leaves a pending authority whose
	// page shows the CSR and the completion form.
	form := url.Values{
		"csrf_token":  {csrf},
		"mode":        {"request"},
		"name":        {"Form Sub CA"},
		"common_name": {"Form Sub CA"},
		"key_type":    {"ec-p256"},
	}
	req := httptest.NewRequest(http.MethodPost, "/cas/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := h.do(req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the request form returned %d: %s", rec.Code, truncBody(rec))
	}

	pending, err := h.svc.Store().PendingCAs(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected one pending authority, got %d (%v)", len(pending), err)
	}
	page := h.get(fmt.Sprintf("/cas/%d", pending[0].ID), cookies)
	if page.Code != http.StatusOK {
		t.Fatalf("the pending CA page returned %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"CERTIFICATE REQUEST", "Activate this authority", "awaiting an externally signed"} {
		if !strings.Contains(body, want) {
			t.Errorf("the pending CA page does not mention %q", want)
		}
	}
	// Its CSR must be downloadable.
	if rec := h.get(fmt.Sprintf("/cas/%d/download/request.csr", pending[0].ID), cookies); rec.Code != http.StatusOK {
		t.Errorf("CSR download returned %d", rec.Code)
	}
}

func TestBulkActionThroughTheList(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()
	tok := h.token(store.RoleAdmin)

	for _, cn := range []string{"one.bulk.test", "two.bulk.test"} {
		h.apiJSON(http.MethodPost, "/api/v1/certificates",
			fmt.Sprintf(`{"subject":{"common_name":"%s"},"key_type":"ec-p256","days":30}`, cn), tok)
	}

	form := url.Values{
		"csrf_token": {csrf},
		"action":     {"revoke"},
		"reason":     {fmt.Sprint(pki.ReasonSuperseded)},
		"selected":   {"1", "2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/certificates/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if rec := h.do(req); rec.Code != http.StatusSeeOther {
		t.Fatalf("bulk action returned %d: %s", rec.Code, truncBody(rec))
	}

	certs, _, err := h.svc.Search(context.Background(), store.CertFilter{Status: store.StatusRevoked})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Errorf("%d certificates were revoked, want 2", len(certs))
	}
}

// externalSigner stands in for a CA goca does not control, so the import paths
// are exercised against a genuine outside issuer.
type externalSigner struct {
	cert    *x509.Certificate
	key     crypto.Signer
	rootPEM string
}

func newExternalSigner(t *testing.T) *externalSigner {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyECP256)
	if err != nil {
		t.Fatal(err)
	}
	signer := key.(crypto.Signer)
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "External Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &externalSigner{cert: cert, key: signer, rootPEM: string(pki.EncodeCertPEM(der))}
}

// sign issues an intermediate CA certificate for a request.
func (e *externalSigner) sign(t *testing.T, csrPEM string) string {
	t.Helper()
	csr, err := pki.ParseCSR([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := pki.NewSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.cert, csr.PublicKey, e.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pki.EncodeCertPEM(der))
}

// A scoped token caps what the holder may do, and /me has to describe both
// halves of that: the account's own role and the role the credential grants.
// Reporting only the capped role -- which is what the embedded user carries,
// since UserFromAPIToken rewrites it -- makes an administrator holding a
// user-scoped token indistinguishable from an ordinary user, so `gocactl
// whoami` cannot tell its reader whether to blame the account or the token.
func TestMeReportsAccountRoleAndTokenRoleSeparately(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		name              string
		tokenRole         string
		wantEffectiveRole string
	}{
		{"admin token", store.RoleAdmin, store.RoleAdmin},
		{"user-scoped token", store.RoleUser, store.RoleUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := h.apiJSON(http.MethodGet, "/api/v1/me", "", h.token(tc.tokenRole))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /me returned %d", rec.Code)
			}
			auth, ok := body["auth"].(map[string]any)
			if !ok {
				t.Fatalf("no auth block in %v", body)
			}
			// Both tokens belong to the admin account throughout.
			if got := auth["account_role"]; got != store.RoleAdmin {
				t.Errorf("auth.account_role = %v, want %q -- the account is an administrator regardless of the token's scope",
					got, store.RoleAdmin)
			}
			if got := auth["role"]; got != tc.wantEffectiveRole {
				t.Errorf("auth.role = %v, want %q", got, tc.wantEffectiveRole)
			}
			// The embedded user keeps reporting the capped role, because that
			// is the honest answer to "what may this request do".
			if got := body["role"]; got != tc.wantEffectiveRole {
				t.Errorf("top-level role = %v, want the capped %q", got, tc.wantEffectiveRole)
			}
		})
	}
}
