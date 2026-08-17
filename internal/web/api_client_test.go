package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mevijays/goca/internal/store"
)

// These cover the API additions that exist specifically so a remote client
// (gocactl) can render what the local CLI renders, and address resources the
// way an operator types them. Each one guards a field or behaviour whose
// absence is silent rather than loud - the API would keep returning 200 while
// the client showed something subtly wrong.

// TestCAResponseIncludesComputedFields is the regression test for the bug that
// motivated the whole caResponse change: CA.HasKey/CanIssue/Kind all read
// KeyEnc, which is json:"-", so before this an API client saw no key field at
// all and could only conclude every authority was a keyless trust anchor.
func TestCAResponseIncludesComputedFields(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	for _, path := range []string{"/api/v1/cas", "/api/v1/cas/1"} {
		rec, body := h.apiJSON(http.MethodGet, path, "", tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		ca := body
		if path == "/api/v1/cas" {
			list, _ := body["cas"].([]any)
			if len(list) == 0 {
				t.Fatalf("GET %s returned no CAs", path)
			}
			ca, _ = list[0].(map[string]any)
		}
		for _, field := range []string{"has_key", "can_issue", "kind", "origin", "expired", "days_left"} {
			if _, ok := ca[field]; !ok {
				t.Errorf("GET %s: CA is missing the computed field %q", path, field)
			}
		}
		// The harness root is a real, key-holding CA, so a client must be able
		// to see that it can issue - the exact thing the old response hid.
		if ca["has_key"] != true {
			t.Errorf("GET %s: has_key = %v, want true for a CA whose key goca holds", path, ca["has_key"])
		}
		if ca["can_issue"] != true {
			t.Errorf("GET %s: can_issue = %v, want true", path, ca["can_issue"])
		}
		if ca["kind"] != "root" {
			t.Errorf("GET %s: kind = %v, want \"root\" (not \"trust anchor\")", path, ca["kind"])
		}
	}
}

// TestCAResponseKeepsThePrivateKeyOut is the other half of the above: the fix
// must expose key *presence* without ever exposing the key itself.
func TestCAResponseKeepsThePrivateKeyOut(t *testing.T) {
	h := newHarness(t)
	rec, body := h.apiJSON(http.MethodGet, "/api/v1/cas/1", "", h.token(store.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/cas/1 = %d", rec.Code)
	}
	for _, leaked := range []string{"key_enc", "KeyEnc", "key_pem"} {
		if _, ok := body[leaked]; ok {
			t.Errorf("CA response leaks %q", leaked)
		}
	}
}

func TestSecretResponseIncludesLabels(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	rec, _ := h.apiJSON(http.MethodPost, "/api/v1/secrets",
		`{"name":"team-a/db","type":"kv","labels":{"env":"prod"}}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create secret = %d", rec.Code)
	}

	rec, body := h.apiJSON(http.MethodGet, "/api/v1/secrets/team-a%2Fdb", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET secret = %d", rec.Code)
	}
	labels, ok := body["labels"].(map[string]any)
	if !ok {
		t.Fatalf("secret response has no labels object: %v", body["labels"])
	}
	if labels["env"] != "prod" {
		t.Errorf("labels = %v, want env=prod", labels)
	}
	if _, ok := body["rotation_due"]; !ok {
		t.Error("secret response is missing rotation_due")
	}
}

// TestAPIAcceptsHumanRefs checks the {id} widening: the API should take the
// same references an operator types at the CLI, while numeric ids keep working.
func TestAPIAcceptsHumanRefs(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	// CA by slug and by numeric id must resolve to the same authority.
	rec, bySlug := h.apiJSON(http.MethodGet, "/api/v1/cas/"+h.root.Slug, "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/cas/%s = %d", h.root.Slug, rec.Code)
	}
	rec, byID := h.apiJSON(http.MethodGet, "/api/v1/cas/1", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/cas/1 = %d", rec.Code)
	}
	if bySlug["id"] != byID["id"] {
		t.Errorf("slug and id resolved to different CAs: %v vs %v", bySlug["id"], byID["id"])
	}

	// User by username.
	rec, _ = h.apiJSON(http.MethodPost, "/api/v1/users",
		`{"username":"carol","password":"CarolPassw0rd!","role":"user"}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d", rec.Code)
	}
	rec, byName := h.apiJSON(http.MethodGet, "/api/v1/users", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("list users = %d", rec.Code)
	}
	_ = byName
	rec, _ = h.apiJSON(http.MethodPatch, "/api/v1/users/carol", `{"role":"admin"}`, tok)
	if rec.Code != http.StatusOK {
		t.Errorf("PATCH /api/v1/users/carol = %d, want 200 (username should resolve)", rec.Code)
	}

	// Secret by name.
	rec, _ = h.apiJSON(http.MethodPost, "/api/v1/secrets", `{"name":"app/key","type":"kv"}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create secret = %d", rec.Code)
	}
	rec, sec := h.apiJSON(http.MethodGet, "/api/v1/secrets/app%2Fkey", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/secrets/app%%2Fkey = %d", rec.Code)
	}
	if sec["name"] != "app/key" {
		t.Errorf("resolved secret name = %v, want app/key", sec["name"])
	}
}

// TestAPIMeDescribesTheCredential covers the /me auth block. The token's own
// role caps the effective role, so an admin acting through a user-role token
// must be reported as a user - a distinction a client cannot infer from the
// user object alone.
func TestAPIMeDescribesTheCredential(t *testing.T) {
	h := newHarness(t)

	rec, body := h.apiJSON(http.MethodGet, "/api/v1/me", "", h.token(store.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me = %d", rec.Code)
	}
	if body["username"] != "admin" {
		t.Errorf("username = %v, want admin (the embedded user must still be there)", body["username"])
	}
	authInfo, ok := body["auth"].(map[string]any)
	if !ok {
		t.Fatalf("no auth block in /me: %v", body)
	}
	if authInfo["method"] != "token" {
		t.Errorf("auth.method = %v, want token", authInfo["method"])
	}
	if authInfo["role"] != store.RoleAdmin {
		t.Errorf("auth.role = %v, want admin", authInfo["role"])
	}
	for _, field := range []string{"token_id", "token_name", "expires_at"} {
		if _, ok := authInfo[field]; !ok {
			t.Errorf("auth block is missing %q", field)
		}
	}

	// The subtle case: an admin's user-role token is capped to user.
	rec, body = h.apiJSON(http.MethodGet, "/api/v1/me", "", h.token(store.RoleUser))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me with a user token = %d", rec.Code)
	}
	authInfo, _ = body["auth"].(map[string]any)
	if authInfo["role"] != store.RoleUser {
		t.Errorf("auth.role = %v for a user-scoped token, want user - the effective "+
			"role must reflect the token, not its owner", authInfo["role"])
	}
}

// TestP12PasswordFromHeader covers the PKCS#12 export password moving out of
// the query string, where it would otherwise be recorded by any reverse proxy
// in front of goca, plus shell and browser history.
func TestP12PasswordFromHeader(t *testing.T) {
	h := newHarness(t)
	tok := h.token(store.RoleAdmin)

	rec, body := h.apiJSON(http.MethodPost, "/api/v1/certificates",
		`{"subject":{"common_name":"p12.test"},"key_type":"ec-p256","days":30}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d", rec.Code)
	}
	cert, _ := body["certificate"].(map[string]any)
	id := int64(cert["id"].(float64))

	const pw = "bundle-passw0rd"
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/certificates/%d/download/bundle.p12", id), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Bundle-Password", pw)
	got := h.do(req)
	if got.Code != http.StatusOK {
		t.Fatalf("p12 download with a header password = %d: %s", got.Code, got.Body.String())
	}
	if got.Body.Len() == 0 {
		t.Error("empty PKCS#12 bundle")
	}

	// The query parameter still works, so the portal's existing links keep
	// functioning.
	req = httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/certificates/%d/download/bundle.p12?password=%s", id, pw), nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if got := h.do(req); got.Code != http.StatusOK {
		t.Errorf("p12 download with a query password = %d (must stay supported)", got.Code)
	}
}
