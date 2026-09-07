package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// fakeTokenReviewServer stands in for a Kubernetes API server's TokenReview
// endpoint. It authenticates every presented token to the same fixed
// ServiceAccount identity, which is exactly the collision the trust-domain
// feature exists to resolve: two different clusters can mint tokens for the
// same (namespace, ServiceAccount), and only the trust domain a token was
// verified under tells them apart.
func fakeTokenReviewServer(t *testing.T, username string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"status":{"authenticated":true,"user":{"username":%q}}}`, username)
	}))
}

// TestCSITrustDomainScopesBindingAcrossClusters is the end-to-end proof of the
// Phase 1 trust-domain model: a secret binding scoped to trust domain
// "cluster-a" is reachable by a token verified under "cluster-a" but refused
// for the identical (namespace, ServiceAccount) token verified under
// "cluster-b". A wildcard ("*") binding stays reachable from either cluster.
func TestCSITrustDomainScopesBindingAcrossClusters(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Two clusters that happen to mint tokens for the same (namespace, SA).
	// Both trust domains point at the same fake API server, so the only thing
	// that distinguishes a request from cluster-a from one from cluster-b is
	// the trust domain the token was verified under.
	api := fakeTokenReviewServer(t, "system:serviceaccount:prod:app")
	defer api.Close()

	box := h.svc.Box()
	for _, name := range []string{"cluster-a", "cluster-b"} {
		tok, err := box.EncryptString("reviewer-token")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.svc.Store().CreateK8sAuthMethod(ctx, &store.K8sAuthMethod{
			Name:             name,
			APIServerURL:     api.URL,
			ReviewerTokenEnc: tok,
			CreatedBy:        "test",
		}); err != nil {
			t.Fatalf("create trust domain %s: %v", name, err)
		}
	}

	// A secret bound only to cluster-a, and one bound to any cluster.
	v := h.srv.vault
	if _, err := v.Create(ctx, vault.CreateInput{Name: "db-password", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, "db-password", []byte("s3cr3t"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(ctx, "db-password", "prod", "app", "cluster-a", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create(ctx, vault.CreateInput{Name: "shared", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, "shared", []byte("shared-value"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(ctx, "shared", "prod", "app", "*", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	// Rebuild the registry from the rows and install it on the server, the way
	// NewServer would have if these rows had existed at startup.
	reg, err := buildK8sRegistry(h.svc)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.k8s = reg

	fetch := func(authMethod, secret string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"secrets": []string{secret}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vault/fetch", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer pod-token")
		req.Header.Set("X-Goca-Auth-Method", authMethod)
		rec := h.do(req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// The cluster-a token reaches the cluster-a-scoped secret...
	code, out := fetch("cluster-a", "db-password")
	if code != http.StatusOK {
		t.Fatalf("cluster-a fetch returned %d: %v", code, out)
	}
	res := out["results"].([]any)[0].(map[string]any)
	if e, _ := res["error"].(string); e != "" {
		t.Fatalf("cluster-a fetch of its own binding errored: %q", e)
	}

	// ...but the same token presented under cluster-b is refused, even though
	// (namespace, ServiceAccount) are identical.
	code, out = fetch("cluster-b", "db-password")
	if code != http.StatusOK {
		t.Fatalf("cluster-b fetch returned %d: %v", code, out)
	}
	res = out["results"].([]any)[0].(map[string]any)
	if e, _ := res["error"].(string); e != errNotFoundOrNotAuthorized {
		t.Fatalf("cluster-b fetch of a cluster-a binding = %q, want %q", e, errNotFoundOrNotAuthorized)
	}

	// A wildcard binding is reachable from either cluster.
	for _, m := range []string{"cluster-a", "cluster-b"} {
		code, out = fetch(m, "shared")
		if code != http.StatusOK {
			t.Fatalf("%s fetch of wildcard secret returned %d: %v", m, code, out)
		}
		res = out["results"].([]any)[0].(map[string]any)
		if e, _ := res["error"].(string); e != "" {
			t.Fatalf("%s fetch of wildcard binding errored: %q", m, e)
		}
	}
}
