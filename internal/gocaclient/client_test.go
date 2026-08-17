package gocaclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// TestClientLinksNoSQLDriver enforces the decision that shapes this whole
// package: the client hand-writes DTOs so it does not import internal/store,
// which links modernc.org/sqlite and pgx. An accidental import would compile
// and pass every other test while quietly putting a database engine in a
// binary that never opens one.
func TestClientLinksNoSQLDriver(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/mevijays/goca/internal/gocaclient").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, banned := range []string{"modernc.org/sqlite", "github.com/jackc/pgx"} {
		for _, dep := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(dep), banned) {
				t.Errorf("the client links %s - something imported internal/store", dep)
				break
			}
		}
	}
}

// newTestServer serves canned responses for one path.
func newTestServer(t *testing.T, path, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, server string) *Client {
	t.Helper()
	c, err := New(Options{Server: server, Token: "goca_test_token"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The bodies below were captured from a real goca server rather than written
// by hand, so decoding is tested against what the server actually emits.

const realCAListBody = `{
  "cas": [
    {
      "id": 1,
      "name": "Parity Root",
      "slug": "parity-root",
      "subject": "CN=Parity Root CA",
      "serial": "147288E56BD4EF4E31737AF32C5C5D1A",
      "key_type": "ec-p256",
      "is_root": true,
      "path_len": 0,
      "not_before": "2026-08-16T16:07:00Z",
      "not_after": "2036-08-13T16:12:00Z",
      "status": "active",
      "crl_number": 0,
      "fingerprint_sha256": "AF:02:E5:20",
      "is_default": true,
      "created_by": "vijay (cli)",
      "created_at": "2026-08-16T16:07:01Z",
      "external": false,
      "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "has_key": true,
      "can_issue": true,
      "kind": "root",
      "origin": "goca",
      "expired": false,
      "days_left": 3649
    }
  ],
  "count": 1
}`

func TestDecodeCAList(t *testing.T) {
	srv := newTestServer(t, "/api/v1/cas", realCAListBody)
	res, err := newTestClient(t, srv.URL).ListCAs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Value) != 1 {
		t.Fatalf("got %d CAs, want 1", len(res.Value))
	}
	ca := res.Value[0]
	if ca.Name != "Parity Root" || ca.Slug != "parity-root" {
		t.Errorf("name/slug = %q/%q", ca.Name, ca.Slug)
	}
	// The computed fields are the whole reason a remote client can render a
	// CA list correctly.
	if !ca.HasKey || !ca.CanIssue || ca.Kind != "root" || ca.Origin != "goca" {
		t.Errorf("computed fields wrong: has_key=%v can_issue=%v kind=%q origin=%q",
			ca.HasKey, ca.CanIssue, ca.Kind, ca.Origin)
	}
	if ca.DaysLeft != 3649 {
		t.Errorf("days_left = %d", ca.DaysLeft)
	}
	// Raw must be the server's bytes verbatim, so --json passes them through.
	if !json.Valid(res.Raw) || !strings.Contains(string(res.Raw), `"count": 1`) {
		t.Error("Raw is not the server's original body")
	}
}

const realCertListBody = `{
  "certificates": [
    {
      "id": 1,
      "ca_id": 1,
      "ca_name": "Parity Root",
      "serial": "3D92F5B30934CB06B6E7812BB7F7D0CB",
      "common_name": "svc.test.local",
      "subject": "CN=svc.test.local",
      "profile": "server",
      "key_type": "ec-p256",
      "has_key": true,
      "fingerprint_sha256": "62:50:6A:3B",
      "not_before": "2026-08-16T16:07:01Z",
      "not_after": "2026-11-14T16:12:01Z",
      "status": "active",
      "requested_by": "vijay (cli)",
      "created_at": "2026-08-16T16:12:01Z",
      "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
      "sans": ["svc.test.local"]
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}`

func TestDecodeCertList(t *testing.T) {
	srv := newTestServer(t, "/api/v1/certificates", realCertListBody)
	res, err := newTestClient(t, srv.URL).ListCerts(context.Background(), CertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value.Total != 1 || len(res.Value.Certificates) != 1 {
		t.Fatalf("total=%d len=%d", res.Value.Total, len(res.Value.Certificates))
	}
	c := res.Value.Certificates[0]
	if c.CommonName != "svc.test.local" {
		t.Errorf("common_name = %q", c.CommonName)
	}
	// SANs are decoded server-side; the stored blob is not serialized.
	if len(c.SANs) != 1 || c.SANs[0] != "svc.test.local" {
		t.Errorf("sans = %v", c.SANs)
	}
	if got := c.EffectiveStatus(); got != "expired" && got != "active" {
		t.Errorf("EffectiveStatus() = %q", got)
	}
}

const realSecretListBody = `{
  "secrets": [
    {
      "id": 1,
      "name": "team-a/db/password",
      "type": "kv",
      "description": "db password",
      "current_version": 2,
      "disabled": false,
      "created_by": "vijay (cli)",
      "created_at": "2026-08-16T16:11:37Z",
      "updated_at": "2026-08-16T16:11:38Z",
      "labels": {"env": "prod"},
      "rotation_due": false
    }
  ],
  "count": 1
}`

func TestDecodeSecretList(t *testing.T) {
	srv := newTestServer(t, "/api/v1/secrets", realSecretListBody)
	res, err := newTestClient(t, srv.URL).ListSecrets(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Value) != 1 {
		t.Fatalf("got %d secrets", len(res.Value))
	}
	s := res.Value[0]
	if s.Name != "team-a/db/password" || s.CurrentVersion != 2 {
		t.Errorf("secret = %+v", s)
	}
	// Labels only reach a client because the API adds them - store.Secret
	// keeps them in a json:"-" blob.
	if s.Labels["env"] != "prod" {
		t.Errorf("labels = %v", s.Labels)
	}
}

func TestAPIErrorsCarryTheServersMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"administrator role required"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsForbidden(err) {
		t.Errorf("IsForbidden = false for %v", err)
	}
	// The user should see the server's wording, not something invented here.
	if !strings.Contains(err.Error(), "administrator role required") {
		t.Errorf("error lost the server's message: %v", err)
	}
}

// TestUnauthorizedSuggestsLogin: an expired token is the most common failure
// for a long-lived client config, and the fix is one command.
func TestUnauthorizedSuggestsLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid or expired API token"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(t, srv.URL).ListCAs(context.Background())
	if !IsUnauthorized(err) {
		t.Fatalf("IsUnauthorized = false for %v", err)
	}
	if !strings.Contains(err.Error(), "gocactl login") {
		t.Errorf("a 401 should point at the fix: %v", err)
	}
}

func TestNewRejectsBadServers(t *testing.T) {
	for _, server := range []string{"", "   ", "://nope"} {
		if _, err := New(Options{Server: server}); err == nil {
			t.Errorf("New accepted server %q", server)
		}
	}
	// A bare host must become https, never http - guessing http would put the
	// token on the wire in the clear.
	c, err := New(Options{Server: "ca.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Server() != "https://ca.example.com" {
		t.Errorf("bare host became %q, want https://ca.example.com", c.Server())
	}
}

func TestSecretNamesWithSlashesAreEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"name":"team-a/db/password"}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL).GetSecret(context.Background(), "team-a/db/password"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gotPath, "team-a/db/password") {
		t.Errorf("the secret name was not escaped, so the router saw extra path segments: %s", gotPath)
	}
	if !strings.Contains(gotPath, "%2F") {
		t.Errorf("expected percent-encoded slashes in %s", gotPath)
	}
}
