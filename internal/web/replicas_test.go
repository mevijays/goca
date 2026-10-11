package web

// Multi-replica tests: two independent Server instances - each with its own
// in-process state, exactly like two goca pods - over one shared database,
// behind a front handler that round-robins requests between them the way a
// Kubernetes Service does. Anything that still lives in process memory shows
// up here as a request that works on one replica and not the other.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/mevijays/goca/internal/acme"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// replicaPair is two Servers over h's database plus a round-robin front.
type replicaPair struct {
	a, b  *Server
	front *httptest.Server
	// badNonces counts badNonce problems either replica returned.
	badNonces int32
}

func newReplicaPair(t *testing.T, h *harness) *replicaPair {
	t.Helper()
	b, err := NewServer(h.svc, h.mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p := &replicaPair{a: h.srv, b: b}
	handlers := []http.Handler{h.srv.Handler(), b.Handler()}
	var next uint32
	p.front = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Round-robin, like a Service - until replicas have refused a few
		// nonces. Past that, stick to one replica so the client can finish
		// and the test fails on the count, instead of x/crypto/acme retrying
		// badNonce forever (which is what a per-replica nonce store does
		// under strict alternation: every nonce lands on the wrong pod).
		i := atomic.AddUint32(&next, 1) % 2
		if atomic.LoadInt32(&p.badNonces) >= 5 {
			i = 0
		}
		target := handlers[i]
		rec := httptest.NewRecorder()
		target.ServeHTTP(rec, r)
		if strings.Contains(rec.Body.String(), "urn:ietf:params:acme:error:badNonce") {
			atomic.AddInt32(&p.badNonces, 1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(p.front.Close)
	h.svc.Config().Server.BaseURL = p.front.URL
	return p
}

func TestReplicasShareACMEState(t *testing.T) {
	h := newHarness(t)
	p := newReplicaPair(t, h)
	eab := createTestEAB(t, h, acme.CreateEABInput{Name: "lb", Actor: "t"})

	// The whole flow - every request alternating between the two replicas,
	// so each nonce is redeemed by the replica that did NOT issue it.
	c := registerACME(t, p.front, eab)
	leaf, certURL, err := orderAndFinalize(t, c, &x509.CertificateRequest{DNSNames: []string{"lb.internal"}}, "lb.internal")
	if err != nil {
		t.Fatalf("ACME flow across two replicas failed: %v", err)
	}
	if _, err := c.FetchCert(context.Background(), certURL, true); err != nil {
		t.Fatalf("fetch across replicas: %v", err)
	}
	if err := c.RevokeCert(context.Background(), nil, leaf.Raw, xacme.CRLReasonUnspecified); err != nil {
		t.Fatalf("revoke across replicas: %v", err)
	}
	// x/crypto/acme retries badNonce silently, so success alone would hide a
	// per-replica nonce store; count the badNonce responses instead.
	if n := atomic.LoadInt32(&p.badNonces); n != 0 {
		t.Fatalf("%d badNonce responses: a nonce issued by one replica was not redeemable at the other", n)
	}
}

func TestTrustDomainDisableReachesEveryReplica(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	api := fakeTokenReviewServer(t, "system:serviceaccount:prod:app")
	defer api.Close()

	tok, err := h.svc.Box().EncryptString("reviewer-token")
	if err != nil {
		t.Fatal(err)
	}
	row, err := h.svc.Store().CreateK8sAuthMethod(ctx, &store.K8sAuthMethod{
		Name: "cluster-a", APIServerURL: api.URL, ReviewerTokenEnc: tok, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := h.srv.vault
	if _, err := v.Create(ctx, vault.CreateInput{Name: "db", Type: "kv", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, "db", []byte("s3cr3t"), "text/plain", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Bind(ctx, "db", "prod", "app", "cluster-a", nil, "admin"); err != nil {
		t.Fatal(err)
	}

	// Replica B starts with the trust domain present and caches its Verifier.
	b, err := NewServer(h.svc, h.mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	fetchAtB := func() int {
		body, _ := json.Marshal(map[string]any{"secrets": []string{"db"}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/vault/fetch", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer pod-token")
		req.Header.Set("X-Goca-Auth-Method", "cluster-a")
		rec := httptest.NewRecorder()
		b.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	if code := fetchAtB(); code != http.StatusOK {
		t.Fatalf("baseline fetch at replica B: %d", code)
	}

	// An administrator disables the trust domain through replica A.
	rec, _ := h.apiJSON("POST", fmt.Sprintf("/api/v1/csi-auth-methods/%d/disable", row.ID), `{"disabled":true}`, h.token("admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable via replica A: %d %s", rec.Code, rec.Body)
	}

	// Replica B must refuse it immediately - not after a restart.
	if code := fetchAtB(); code != http.StatusUnauthorized {
		t.Fatalf("replica B still served a secret through a trust domain disabled on replica A (status %d)", code)
	}
}

func TestLoginThrottleHoldsAcrossReplicas(t *testing.T) {
	h := newHarness(t)
	p := newReplicaPair(t, h)

	attempt := func() int {
		resp, err := http.Post(p.front.URL+"/api/v1/auth/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// loginFailLimit failures, alternating replicas: with per-process
	// counters each replica would only have seen half of them.
	for i := 0; i < loginFailLimit; i++ {
		if code := attempt(); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, code)
		}
	}
	for i := 0; i < 2; i++ { // whichever replica serves the next one
		if code := attempt(); code != http.StatusTooManyRequests {
			t.Fatalf("after %d failures spread over two replicas, attempt %d got %d, want 429",
				loginFailLimit, loginFailLimit+i+1, code)
		}
	}
}
