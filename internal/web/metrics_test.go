package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mevijays/goca/internal/store"
)

// TestMetricsEndpoint verifies the Prometheus scrape endpoint is registered,
// answers 200 with the expected content type, and exposes goca metrics once
// some traffic has flowed - given an admin credential. /metrics carries a
// live goca_auth_login_total{result} counter (a real side channel for
// watching credential-stuffing attempts land) plus per-CA/secret counts, so
// unlike a typical Prometheus endpoint it is not left open by default; see
// TestMetricsEndpointRequiresAdmin.
func TestMetricsEndpoint(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	// Generate a little activity so at least one goca counter has a series.
	if _, _, err := h.svc.Search(h.t.Context(), store.CertFilter{}); err != nil {
		t.Fatalf("seed search: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := h.do(req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# HELP goca_") {
		t.Errorf("body does not contain goca metric help lines:\n%s", body)
	}
}

// TestMetricsEndpointRequiresAdmin is the regression test for the security
// fix: /metrics must refuse both an unauthenticated caller and a user-role
// (non-admin) one, and only accept an admin credential.
func TestMetricsEndpointRequiresAdmin(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if rec := h.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /metrics (no auth) = %d, want 401", rec.Code)
	}

	userTok := h.token(store.RoleUser)
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	if rec := h.do(req); rec.Code != http.StatusForbidden {
		t.Fatalf("GET /metrics (user token) = %d, want 403", rec.Code)
	}

	adminTok := h.token(store.RoleAdmin)
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	if rec := h.do(req); rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics (admin token) = %d, want 200", rec.Code)
	}
}
