package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// esoHarness wires a fake TokenReview server and installs a single trust
// domain, "test-cluster", the way NewServer would at startup - it's the
// minimum needed for apiAuthK8s to accept a request, shared by every test in
// this file so each one only has to say what secret/binding it needs.
func esoHarness(t *testing.T, username string) *harness {
	t.Helper()
	h := newHarness(t)

	api := fakeTokenReviewServer(t, username)
	t.Cleanup(api.Close)

	tok, err := h.svc.Box().EncryptString("reviewer-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Store().CreateK8sAuthMethod(h.t.Context(), &store.K8sAuthMethod{
		Name: "test-cluster", APIServerURL: api.URL, ReviewerTokenEnc: tok, CreatedBy: "test",
	}); err != nil {
		t.Fatalf("create trust domain: %v", err)
	}
	reg, err := buildK8sRegistry(h.svc)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.k8s = reg
	return h
}

func esoFetch(h *harness, key, property string) (int, map[string]any) {
	q := "key=" + key
	if property != "" {
		q += "&property=" + property
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/eso/secret?"+q, nil)
	req.Header.Set("Authorization", "Bearer pod-token")
	req.Header.Set("X-Goca-Auth-Method", "test-cluster")
	rec := h.do(req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// esoFetchAll is esoFetch with ?all=true - the ESO native provider's
// GetSecretMap path.
func esoFetchAll(h *harness, key string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/eso/secret?key="+key+"&all=true", nil)
	req.Header.Set("Authorization", "Bearer pod-token")
	req.Header.Set("X-Goca-Auth-Method", "test-cluster")
	rec := h.do(req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// TestESOFetchKVSecret is the plain happy path: a bound identity fetching a
// kv secret gets its plaintext back, both raw (value) and base64
// (value_base64), and single-file secrets need no ?property=.
func TestESOFetchKVSecret(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")

	v := h.srv.vault
	if _, err := v.Create(h.t.Context(), vault.CreateInput{Name: "team-a/db-password", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(h.t.Context(), "team-a/db-password", []byte("s3cr3t"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(h.t.Context(), "team-a/db-password", "team-a", "eso-reader", "test-cluster", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	code, out := esoFetch(h, "team-a/db-password", "")
	if code != http.StatusOK {
		t.Fatalf("fetch = %d: %v", code, out)
	}
	if out["value"] != "s3cr3t" {
		t.Fatalf("value = %v, want s3cr3t", out["value"])
	}
	wantB64 := base64.StdEncoding.EncodeToString([]byte("s3cr3t"))
	if out["value_base64"] != wantB64 {
		t.Fatalf("value_base64 = %v, want %v", out["value_base64"], wantB64)
	}
	// Materialize() names the single file after the version's content type
	// ("text/plain" here, from the Put call above); "value" is only the
	// fallback when content type is empty. Either way, no ?property= was
	// needed to fetch it - that's the thing this assertion actually checks.
	if out["property"] != "text/plain" {
		t.Fatalf("property = %v, want %q", out["property"], "text/plain")
	}
}

// TestESOFetchCertificateSecret covers a certificate secret's three parts,
// each selected by ?property=, and confirms omitting it is an error rather
// than an arbitrary guess.
func TestESOFetchCertificateSecret(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")

	cert, err := h.svc.Issue(h.t.Context(), ca.IssueInput{
		CARef: h.root.Slug, Subject: pki.Subject{CommonName: "eso.team-a.svc"},
		SANs: []string{"eso.team-a.svc"}, KeyType: "ec-p256", Days: 30, Actor: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	v := h.srv.vault
	if _, err := v.Create(h.t.Context(), vault.CreateInput{
		Name: "team-a/tls", Type: store.SecretTypeCertificate, CertID: &cert.Certificate.ID, Actor: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(h.t.Context(), "team-a/tls", "team-a", "eso-reader", "test-cluster", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	// No ?property=: ambiguous, must be refused rather than guessed.
	code, out := esoFetch(h, "team-a/tls", "")
	if code != http.StatusBadRequest {
		t.Fatalf("fetch with no property = %d, want 400: %v", code, out)
	}

	// An unknown property: also refused, listing what's actually available.
	code, out = esoFetch(h, "team-a/tls", "nope.pem")
	if code != http.StatusBadRequest {
		t.Fatalf("fetch with unknown property = %d, want 400: %v", code, out)
	}

	for _, part := range []string{"tls.crt", "tls.key", "ca.crt"} {
		code, out := esoFetch(h, "team-a/tls", part)
		if code != http.StatusOK {
			t.Fatalf("fetch %s = %d: %v", part, code, out)
		}
		if out["property"] != part {
			t.Fatalf("property = %v, want %q", out["property"], part)
		}
		val, _ := out["value"].(string)
		if val == "" {
			t.Fatalf("%s: empty value", part)
		}
	}

	// ?all=true returns every part in one response, base64-encoded, instead
	// of requiring one request per property - this is what the ESO-native
	// provider's GetSecretMap uses to sync a whole multi-file secret from a
	// single ExternalSecret data entry.
	code, out = esoFetchAll(h, "team-a/tls")
	if code != http.StatusOK {
		t.Fatalf("fetch all = %d: %v", code, out)
	}
	filesRaw, ok := out["files"].(map[string]any)
	if !ok {
		t.Fatalf("response has no files map: %v", out)
	}
	for _, part := range []string{"tls.crt", "tls.key", "ca.crt"} {
		b64, ok := filesRaw[part].(string)
		if !ok || b64 == "" {
			t.Fatalf("files[%q] missing or empty: %v", part, filesRaw)
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("files[%q] is not valid base64: %v", part, err)
		}
		if len(decoded) == 0 {
			t.Fatalf("files[%q] decoded to nothing", part)
		}
	}
	if len(filesRaw) != 3 {
		t.Fatalf("files has %d entries, want 3: %v", len(filesRaw), filesRaw)
	}
}

// TestESOFetchAllOnSingleFileSecret confirms ?all=true also works on an
// ordinary kv secret - a 1-entry files map, not a special case or an error.
func TestESOFetchAllOnSingleFileSecret(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")

	v := h.srv.vault
	if _, err := v.Create(h.t.Context(), vault.CreateInput{Name: "team-a/simple", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(h.t.Context(), "team-a/simple", []byte("hello"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(h.t.Context(), "team-a/simple", "team-a", "eso-reader", "test-cluster", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	code, out := esoFetchAll(h, "team-a/simple")
	if code != http.StatusOK {
		t.Fatalf("fetch all = %d: %v", code, out)
	}
	files, _ := out["files"].(map[string]any)
	if len(files) != 1 {
		t.Fatalf("files = %v, want exactly 1 entry", files)
	}
	b64, _ := files["text/plain"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(b64)
	if string(decoded) != "hello" {
		t.Fatalf("decoded value = %q, want hello", decoded)
	}
}

// TestESOFetchUnauthorizedLooksLikeNotFound is the same non-enumerability
// property api_vault_fetch.go's CSI path already has: a secret that exists
// but isn't bound to this identity must be indistinguishable from a secret
// that doesn't exist at all.
func TestESOFetchUnauthorizedLooksLikeNotFound(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")

	v := h.srv.vault
	if _, err := v.Create(h.t.Context(), vault.CreateInput{Name: "team-b/secret", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(h.t.Context(), "team-b/secret", []byte("not-yours"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	// Bound to team-b, not team-a - the identity this test authenticates as.
	if _, err := v.Bind(h.t.Context(), "team-b/secret", "team-b", "eso-reader", "test-cluster", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	codeUnbound, outUnbound := esoFetch(h, "team-b/secret", "")
	codeMissing, outMissing := esoFetch(h, "does-not-exist", "")

	if codeUnbound != http.StatusNotFound || codeMissing != http.StatusNotFound {
		t.Fatalf("unbound = %d, missing = %d, want 404/404", codeUnbound, codeMissing)
	}
	if outUnbound["error"] != outMissing["error"] {
		t.Fatalf("unbound and missing gave different errors, leaking existence: %q vs %q",
			outUnbound["error"], outMissing["error"])
	}
}

func TestESOFetchRequiresKeyParam(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")
	code, out := esoFetch(h, "", "")
	if code != http.StatusBadRequest {
		t.Fatalf("fetch with no key = %d, want 400: %v", code, out)
	}
}

// TestESOFetchWrongTrustDomainRefused mirrors
// TestCSITrustDomainScopesBindingAcrossClusters for the ESO path: a binding
// scoped to one trust domain must not be reachable from a token verified
// under a different one, even with an identical (namespace, ServiceAccount).
func TestESOFetchWrongTrustDomainRefused(t *testing.T) {
	h := esoHarness(t, "system:serviceaccount:team-a:eso-reader")

	api2 := fakeTokenReviewServer(t, "system:serviceaccount:team-a:eso-reader")
	t.Cleanup(api2.Close)
	tok, err := h.svc.Box().EncryptString("reviewer-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Store().CreateK8sAuthMethod(h.t.Context(), &store.K8sAuthMethod{
		Name: "other-cluster", APIServerURL: api2.URL, ReviewerTokenEnc: tok, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	reg, err := buildK8sRegistry(h.svc)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.k8s = reg

	v := h.srv.vault
	if _, err := v.Create(h.t.Context(), vault.CreateInput{Name: "team-a/scoped", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(h.t.Context(), "team-a/scoped", []byte("x"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(h.t.Context(), "team-a/scoped", "team-a", "eso-reader", "test-cluster", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/eso/secret?key=team-a/scoped", nil)
	req.Header.Set("Authorization", "Bearer pod-token")
	req.Header.Set("X-Goca-Auth-Method", "other-cluster")
	rec := h.do(req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("fetch under the wrong trust domain = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
