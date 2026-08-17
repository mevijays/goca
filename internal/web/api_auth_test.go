package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// POST /api/v1/auth/login is the only endpoint that checks a password, and the
// only one deliberately reachable without a credential. These tests pin both
// properties, plus the invariant that a password grant can never produce a
// token that never expires.

func login(h *harness, body string) (*httptest.ResponseRecorder, map[string]any) {
	// Deliberately no Authorization header: that is the point of the endpoint.
	return h.apiJSON(http.MethodPost, "/api/v1/auth/login", body, "")
}

func TestAPILoginIsReachableWithoutCredentials(t *testing.T) {
	h := newHarness(t)
	rec, body := login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (it must not be behind apiAuth): %v", rec.Code, body)
	}
	if body["token"] == "" || body["token"] == nil {
		t.Fatal("login returned no token")
	}
	if body["role"] != "admin" {
		t.Errorf("role = %v, want admin", body["role"])
	}
	user, _ := body["user"].(map[string]any)
	if user["username"] != "admin" {
		t.Errorf("user.username = %v", user["username"])
	}
	for _, field := range []string{"token_id", "token_name", "expires_at", "server_version"} {
		if _, ok := body[field]; !ok {
			t.Errorf("login response is missing %q", field)
		}
	}
}

// TestAPILoginIssuesAUsableToken is the end-to-end proof that the endpoint
// actually solves the bootstrap problem it exists for.
func TestAPILoginIssuesAUsableToken(t *testing.T) {
	h := newHarness(t)
	_, body := login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword))
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatal("no token")
	}
	rec, _ := h.apiJSON(http.MethodGet, "/api/v1/cas", "", tok)
	if rec.Code != http.StatusOK {
		t.Errorf("the freshly minted token could not list CAs: %d", rec.Code)
	}
}

// TestAPILoginNeverIssuesANonExpiringToken guards the sharpest edge here:
// auth.IssueAPIToken treats a zero TTL as "never expires", which must be
// unreachable from a password grant - a leaked password would otherwise mint
// an immortal credential.
func TestAPILoginNeverIssuesANonExpiringToken(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{
		fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword),          // days omitted
		fmt.Sprintf(`{"username":"admin","password":%q,"days":0}`, testAdminPassword), // days explicitly zero
	} {
		rec, got := login(h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("login = %d", rec.Code)
		}
		if got["expires_at"] == nil {
			t.Errorf("expires_at is null for request %s - a password grant must never "+
				"mint a token that never expires", body)
		}
	}
}

func TestAPILoginRejectsBadTTLRequests(t *testing.T) {
	h := newHarness(t)

	rec, _ := login(h, fmt.Sprintf(`{"username":"admin","password":%q,"days":-1}`, testAdminPassword))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("days=-1 returned %d, want 400", rec.Code)
	}
	// Default cap is 90 days.
	rec, _ = login(h, fmt.Sprintf(`{"username":"admin","password":%q,"days":9999}`, testAdminPassword))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("days=9999 returned %d, want 400 (over the server cap)", rec.Code)
	}
}

// TestAPILoginDoesNotEnumerateAccounts checks that a wrong password and an
// unknown user are indistinguishable.
func TestAPILoginDoesNotEnumerateAccounts(t *testing.T) {
	h := newHarness(t)

	recWrong, bodyWrong := login(h, `{"username":"admin","password":"not-the-password"}`)
	recUnknown, bodyUnknown := login(h, `{"username":"nobody","password":"not-the-password"}`)

	if recWrong.Code != http.StatusUnauthorized || recUnknown.Code != http.StatusUnauthorized {
		t.Fatalf("statuses: wrong-password=%d unknown-user=%d, want 401 for both",
			recWrong.Code, recUnknown.Code)
	}
	if bodyWrong["error"] != bodyUnknown["error"] {
		t.Errorf("a wrong password (%v) and an unknown user (%v) are distinguishable",
			bodyWrong["error"], bodyUnknown["error"])
	}
}

func TestAPILoginRequiresBothFields(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{
		`{"username":"admin"}`,
		`{"password":"x"}`,
		`{"username":"","password":""}`,
	} {
		if rec, _ := login(h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s returned %d, want 400", body, rec.Code)
		}
	}
}

// TestAPILoginSetsNoCookie: this is an API credential exchange, not a browser
// sign-in. A Set-Cookie here would create a session nobody asked for.
func TestAPILoginSetsNoCookie(t *testing.T) {
	h := newHarness(t)
	rec, _ := login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword))
	if got := rec.Result().Header.Get("Set-Cookie"); got != "" {
		t.Errorf("login set a cookie: %q", got)
	}
	// A 401 must not provoke a browser basic-auth dialog either.
	rec, _ = login(h, `{"username":"admin","password":"wrong"}`)
	if got := rec.Result().Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("failed login sent WWW-Authenticate: %q", got)
	}
}

func TestAPILoginRateLimits(t *testing.T) {
	h := newHarness(t)

	for i := 0; i < loginFailLimit; i++ {
		if rec, _ := login(h, `{"username":"admin","password":"wrong"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", i+1, rec.Code)
		}
	}
	rec, body := login(h, `{"username":"admin","password":"wrong"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d returned %d, want 429", loginFailLimit+1, rec.Code)
	}
	if rec.Result().Header.Get("Retry-After") == "" {
		t.Error("429 is missing a Retry-After header")
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "too many") {
		t.Errorf("unhelpful throttle message: %v", body["error"])
	}

	// The correct password is refused too while throttled - otherwise the
	// limiter would not actually slow down an online guessing attack.
	rec, _ = login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("a correct password during a lockout returned %d, want 429", rec.Code)
	}
}

// TestSuccessfulLoginClearsTheUserCounter: a legitimate user who mistypes a
// few times must not stay penalised once they get it right.
func TestSuccessfulLoginClearsTheUserCounter(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < loginFailLimit-1; i++ {
		login(h, `{"username":"admin","password":"wrong"}`)
	}
	if rec, _ := login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword)); rec.Code != http.StatusOK {
		t.Fatalf("login after near-miss failures = %d", rec.Code)
	}
	// Having succeeded, the budget is replenished.
	for i := 0; i < loginFailLimit-1; i++ {
		if rec, _ := login(h, `{"username":"admin","password":"wrong"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-success attempt %d returned %d, want 401 - the counter was not reset", i+1, rec.Code)
		}
	}
}

func TestAPILoginRespectsTokenName(t *testing.T) {
	h := newHarness(t)
	rec, body := login(h, fmt.Sprintf(
		`{"username":"admin","password":%q,"token_name":"gocactl@laptop"}`, testAdminPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d", rec.Code)
	}
	if body["token_name"] != "gocactl@laptop" {
		t.Errorf("token_name = %v", body["token_name"])
	}

	// An over-long name is truncated, not rejected - it is a label, not input
	// worth failing a sign-in over.
	rec, body = login(h, fmt.Sprintf(
		`{"username":"admin","password":%q,"token_name":%q}`, testAdminPassword, strings.Repeat("x", 200)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login with a long token name = %d", rec.Code)
	}
	if n := len(body["token_name"].(string)); n != maxTokenNameLen {
		t.Errorf("token name length = %d, want %d", n, maxTokenNameLen)
	}
}

// TestAPILoginTokenIsRevocable closes the loop for `gocactl logout`, which
// self-revokes using the token_id the login response hands back.
func TestAPILoginTokenIsRevocable(t *testing.T) {
	h := newHarness(t)
	_, body := login(h, fmt.Sprintf(`{"username":"admin","password":%q}`, testAdminPassword))
	tok, _ := body["token"].(string)
	id, _ := body["token_id"].(float64)

	rec, _ := h.apiJSON(http.MethodDelete, fmt.Sprintf("/api/v1/tokens/%d", int64(id)), "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("self-revoke = %d", rec.Code)
	}
	if rec, _ := h.apiJSON(http.MethodGet, "/api/v1/cas", "", tok); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token still works: %d", rec.Code)
	}
}
