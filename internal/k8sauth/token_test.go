package k8sauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New accepted a config with no audience")
	}
	if _, err := New(Config{Audience: "goca-csi"}); err == nil {
		t.Error("New accepted a config with neither an issuer nor TokenReview settings")
	}
	if _, err := New(Config{Audience: "goca-csi", IssuerURL: "https://issuer.example"}); err != nil {
		t.Errorf("New rejected a valid issuer-only config: %v", err)
	}
	if _, err := New(Config{Audience: "goca-csi", APIServerURL: "https://api.example", ReviewerToken: "t"}); err != nil {
		t.Errorf("New rejected a valid TokenReview-only config: %v", err)
	}
	if _, err := New(Config{
		Audience: "goca-csi", APIServerURL: "https://api.example", ReviewerToken: "t",
		CACertPEM: []byte("not a cert"),
	}); err == nil {
		t.Error("New accepted a CA bundle with no certificates in it")
	}
}

func TestParseServiceAccountSubject(t *testing.T) {
	cases := []struct {
		sub    string
		ns, sa string
		ok     bool
	}{
		{"system:serviceaccount:team-a:web", "team-a", "web", true},
		{"system:serviceaccount:default:default", "default", "default", true},
		{"system:node:worker-1", "", "", false},
		{"not-even-close", "", "", false},
		{"system:serviceaccount::web", "", "", false},
		{"system:serviceaccount:team-a:", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		ns, sa, ok := parseServiceAccountSubject(c.sub)
		if ok != c.ok || ns != c.ns || sa != c.sa {
			t.Errorf("parseServiceAccountSubject(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.sub, ns, sa, ok, c.ns, c.sa, c.ok)
		}
	}
}

//
// ---------- OIDC / JWKS path ----------
//

func newTestOIDCServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: "test-key", Algorithm: string(oidc.RS256)},
		},
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.SetIssuer(srv.URL)
	return srv, priv
}

func signBoundToken(t *testing.T, priv *rsa.PrivateKey, issuer, audience, namespace, sa, podName, podUID string, expiresIn time.Duration) string {
	t.Helper()
	claims := map[string]any{
		"iss": issuer,
		"aud": audience,
		"sub": "system:serviceaccount:" + namespace + ":" + sa,
		"exp": time.Now().Add(expiresIn).Unix(),
		"kubernetes.io": map[string]any{
			"namespace": namespace,
			"pod": map[string]any{
				"name": podName,
				"uid":  podUID,
			},
			"serviceaccount": map[string]any{
				"name": sa,
				"uid":  "sa-uid-123",
			},
		},
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return oidctest.SignIDToken(priv, "test-key", string(oidc.RS256), string(b))
}

func TestVerifyOIDCPathSucceeds(t *testing.T) {
	srv, priv := newTestOIDCServer(t)
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	token := signBoundToken(t, priv, srv.URL, "goca-csi", "team-a", "web", "web-abc123", "pod-uid-1", time.Hour)

	id, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Namespace != "team-a" || id.ServiceAccount != "web" {
		t.Errorf("identity = %+v, want namespace=team-a serviceaccount=web", id)
	}
	if id.PodName != "web-abc123" || id.PodUID != "pod-uid-1" {
		t.Errorf("identity pod info = %+v, want pod-name=web-abc123 pod-uid=pod-uid-1", id)
	}
	if id.String() != "system:serviceaccount:team-a:web" {
		t.Errorf("String() = %q", id.String())
	}
}

func TestVerifyOIDCPathRejectsWrongAudience(t *testing.T) {
	srv, priv := newTestOIDCServer(t)
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	token := signBoundToken(t, priv, srv.URL, "some-other-audience", "team-a", "web", "web-abc123", "pod-uid-1", time.Hour)
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("Verify accepted a token bound to a different audience")
	}
}

func TestVerifyOIDCPathRejectsExpiredToken(t *testing.T) {
	srv, priv := newTestOIDCServer(t)
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	token := signBoundToken(t, priv, srv.URL, "goca-csi", "team-a", "web", "web-abc123", "pod-uid-1", -time.Hour)
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("Verify accepted an expired token")
	}
}

func TestVerifyOIDCPathRejectsWrongSigner(t *testing.T) {
	srv, _ := newTestOIDCServer(t)
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	// Signed with a key the discovery server never published under "test-key".
	claims := `{"iss":"` + srv.URL + `","aud":"goca-csi","sub":"system:serviceaccount:team-a:web","exp":` +
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`
	token := oidctest.SignIDToken(otherPriv, "test-key", string(oidc.RS256), claims)
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("Verify accepted a token signed by an unpublished key")
	}
}

func TestVerifyOIDCPathFallsBackToSubjectWithoutKubernetesClaim(t *testing.T) {
	srv, priv := newTestOIDCServer(t)
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	// A long-lived ServiceAccount token Secret: no "kubernetes.io" claim, no pod info.
	claims := `{"iss":"` + srv.URL + `","aud":"goca-csi","sub":"system:serviceaccount:team-a:legacy","exp":` +
		strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `}`
	token := oidctest.SignIDToken(priv, "test-key", string(oidc.RS256), claims)

	id, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Namespace != "team-a" || id.ServiceAccount != "legacy" {
		t.Errorf("identity = %+v, want namespace=team-a serviceaccount=legacy", id)
	}
	if id.PodName != "" || id.PodUID != "" {
		t.Errorf("identity = %+v, want no pod info for a non-bound token", id)
	}
}

func TestVerifyRejectsEmptyToken(t *testing.T) {
	srv, _ := newTestOIDCServer(t)
	v, err := New(Config{IssuerURL: srv.URL, Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), "   "); err == nil {
		t.Error("Verify accepted an empty token")
	}
}

func TestVerifyFailsWithoutUsableIssuerOrFallback(t *testing.T) {
	v, err := New(Config{IssuerURL: "https://issuer.invalid.test.example", Audience: "goca-csi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), "some-token"); err == nil {
		t.Error("Verify succeeded against an unreachable issuer with no TokenReview fallback")
	}
}

//
// ---------- TokenReview fallback ----------
//

// fakeTokenReviewAPIServer emulates the subset of the Kubernetes API server
// this package talks to: POST /apis/authentication.k8s.io/v1/tokenreviews.
type fakeTokenReviewAPIServer struct {
	// wantReviewerToken, if set, requires the Authorization header
	// presented by the caller (the provider's own SA token).
	wantReviewerToken string
	// responses maps a submitted token to what TokenReview should answer.
	responses map[string]tokenReviewResponse
}

func (f *fakeTokenReviewAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
		http.NotFound(w, r)
		return
	}
	if f.wantReviewerToken != "" && r.Header.Get("Authorization") != "Bearer "+f.wantReviewerToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var in tokenReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	out, ok := f.responses[in.Spec.Token]
	if !ok {
		out.Status.Authenticated = false
		out.Status.Error = "unrecognized token"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

func TestVerifyTokenReviewFallbackSucceeds(t *testing.T) {
	valid := tokenReviewResponse{}
	valid.Status.Authenticated = true
	valid.Status.User.Username = "system:serviceaccount:team-a:web"
	valid.Status.User.Extra = map[string][]string{
		extraPodName: {"web-abc123"},
		extraPodUID:  {"pod-uid-1"},
	}
	fake := &fakeTokenReviewAPIServer{
		wantReviewerToken: "provider-own-token",
		responses:         map[string]tokenReviewResponse{"pod-token": valid},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	v, err := New(Config{
		Audience:      "goca-csi",
		APIServerURL:  srv.URL,
		ReviewerToken: "provider-own-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(context.Background(), "pod-token")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Namespace != "team-a" || id.ServiceAccount != "web" {
		t.Errorf("identity = %+v, want namespace=team-a serviceaccount=web", id)
	}
	if id.PodName != "web-abc123" || id.PodUID != "pod-uid-1" {
		t.Errorf("identity pod info = %+v", id)
	}
}

func TestVerifyTokenReviewFallbackRejectsUnauthenticated(t *testing.T) {
	rejected := tokenReviewResponse{}
	rejected.Status.Authenticated = false
	rejected.Status.Error = "token has expired"
	fake := &fakeTokenReviewAPIServer{responses: map[string]tokenReviewResponse{"bad-token": rejected}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	v, err := New(Config{Audience: "goca-csi", APIServerURL: srv.URL, ReviewerToken: "provider-own-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), "bad-token"); err == nil {
		t.Error("Verify accepted a token TokenReview marked unauthenticated")
	}
}

func TestVerifyTokenReviewFallbackRejectsNonServiceAccountIdentity(t *testing.T) {
	weird := tokenReviewResponse{}
	weird.Status.Authenticated = true
	weird.Status.User.Username = "system:node:worker-1"
	fake := &fakeTokenReviewAPIServer{responses: map[string]tokenReviewResponse{"node-token": weird}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	v, err := New(Config{Audience: "goca-csi", APIServerURL: srv.URL, ReviewerToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), "node-token"); err == nil {
		t.Error("Verify accepted an authenticated identity that is not a ServiceAccount")
	}
}

func TestVerifyPrefersOIDCAndFallsBackWhenIssuerUnreachable(t *testing.T) {
	valid := tokenReviewResponse{}
	valid.Status.Authenticated = true
	valid.Status.User.Username = "system:serviceaccount:team-a:web"
	fake := &fakeTokenReviewAPIServer{responses: map[string]tokenReviewResponse{"pod-token": valid}}
	reviewSrv := httptest.NewServer(fake)
	defer reviewSrv.Close()

	// An issuer URL that resolves to nothing usable, plus a working
	// TokenReview fallback: Verify must still succeed.
	v, err := New(Config{
		IssuerURL:     "https://issuer.invalid.test.example",
		Audience:      "goca-csi",
		APIServerURL:  reviewSrv.URL,
		ReviewerToken: "t",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(context.Background(), "pod-token")
	if err != nil {
		t.Fatalf("Verify did not fall back to TokenReview: %v", err)
	}
	if id.Namespace != "team-a" || id.ServiceAccount != "web" {
		t.Errorf("identity = %+v", id)
	}
}

func TestInClusterConfigRequiresPodEnvironment(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := InClusterConfig("", "goca-csi"); err == nil {
		t.Error("InClusterConfig succeeded outside a pod environment")
	}
}
