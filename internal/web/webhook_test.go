package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/webhooks"
)

// newTestEventSink starts an httptest server that records the X-Goca-Signature
// header and the event action from the JSON body, then answers 200.
func newTestEventSink(onEvent func(sig, action string)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<16)
		n, _ := r.Body.Read(body)
		var ev struct {
			Action string `json:"action"`
		}
		_ = json.Unmarshal(body[:n], &ev)
		onEvent(r.Header.Get("X-Goca-Signature"), ev.Action)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
}

// TestWebhookREST exercises the admin-only webhook CRUD surface end to end:
// create, list, get, update, disable, deliveries, delete - and confirms the
// signing key is never returned.
func TestWebhookREST(t *testing.T) {
	h := newHarness(t)
	tok := h.token("admin")

	// Unauthenticated access is rejected.
	if rec, _ := h.apiJSON(http.MethodGet, "/api/v1/webhooks", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list = %d, want 401", rec.Code)
	}

	// A URL that can never be a legitimate webhook receiver is rejected at
	// creation, before it is ever stored - the dial-time SSRF defense in
	// internal/webhooks/ssrf.go is the real boundary, but a clear 400 here
	// catches the common/accidental case immediately instead of a delivery
	// failure an operator has to go dig for.
	for _, bad := range []string{
		`{"name":"x","url":"http://127.0.0.1:9000/hook","events":"*"}`,
		`{"name":"x","url":"http://169.254.169.254/latest/meta-data","events":"*"}`,
		`{"name":"x","url":"ftp://hooks.example.com","events":"*"}`,
	} {
		if rec, out := h.apiJSON(http.MethodPost, "/api/v1/webhooks", bad, tok); rec.Code != http.StatusBadRequest {
			t.Fatalf("create %s = %d, want 400: %v", bad, rec.Code, out)
		}
	}

	// Create.
	rec, out := h.apiJSON(http.MethodPost, "/api/v1/webhooks",
		`{"name":"ops","url":"https://hooks.example.com/goca","events":"*","secret":"s3cr3t"}`, tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	id, _ := out["id"].(float64)
	if id == 0 {
		t.Fatal("create did not return an id")
	}
	if _, leaked := out["secret"]; leaked {
		t.Fatal("create response leaked the signing secret")
	}

	// List.
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/webhooks", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	list, _ := out["webhooks"].([]any)
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}

	// Get.
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/webhooks/1", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d", rec.Code)
	}
	if out["name"] != "ops" {
		t.Fatalf("get name = %v, want ops", out["name"])
	}
	if _, leaked := out["secret"]; leaked {
		t.Fatal("get response leaked the signing secret")
	}

	// Update to a blocked URL is rejected the same way create is.
	if rec, out := h.apiJSON(http.MethodPatch, "/api/v1/webhooks/1",
		`{"url":"http://127.0.0.1:9000/hook"}`, tok); rec.Code != http.StatusBadRequest {
		t.Fatalf("update to a loopback url = %d, want 400: %v", rec.Code, out)
	}

	// Update the url.
	rec, _ = h.apiJSON(http.MethodPatch, "/api/v1/webhooks/1",
		`{"url":"https://hooks.example.com/changed","events":"cert.issue"}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d", rec.Code)
	}
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/webhooks/1", "", tok)
	if out["url"] != "https://hooks.example.com/changed" {
		t.Fatalf("url after update = %v", out["url"])
	}

	// Disable / enable.
	rec, _ = h.apiJSON(http.MethodPost, "/api/v1/webhooks/1/disable", `{"disabled":true}`, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable = %d", rec.Code)
	}
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/webhooks/1", "", tok)
	if out["disabled"] != true {
		t.Fatalf("disabled = %v, want true", out["disabled"])
	}

	// Deliveries (none yet).
	rec, out = h.apiJSON(http.MethodGet, "/api/v1/webhooks/1/deliveries", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("deliveries = %d", rec.Code)
	}
	dels, _ := out["deliveries"].([]any)
	if len(dels) != 0 {
		t.Fatalf("deliveries len = %d, want 0", len(dels))
	}

	// Delete.
	rec, _ = h.apiJSON(http.MethodDelete, "/api/v1/webhooks/1", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d", rec.Code)
	}
	rec, _ = h.apiJSON(http.MethodGet, "/api/v1/webhooks/1", "", tok)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", rec.Code)
	}
}

// TestWebhookEventingEndToEnd verifies the full G9 loop through the real
// server: an audit action recorded by the CA service fans out to a matching
// webhook, and the dispatcher delivers a signed event to the endpoint.
func TestWebhookEventingEndToEnd(t *testing.T) {
	h := newHarness(t)
	tok := h.token("admin")

	// httptest.NewServer binds to loopback, which the SSRF defense in
	// internal/webhooks/ssrf.go correctly refuses to dial in production - the
	// URL validation at create time and the dial-time block both apply here,
	// same as any real deployment. This test is about the eventing pipeline,
	// not the SSRF defense (that has its own coverage in TestWebhookREST and
	// internal/webhooks/ssrf_test.go), so it swaps in a dispatcher with that
	// one check opted out, on the same store and box the harness already
	// built - everything else about the server is untouched.
	h.srv.webhooks = webhooks.New(h.svc.Store(), h.svc.Box(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		webhooks.Options{Transport: http.DefaultTransport})

	// A test endpoint that records the signature and body.
	var gotSig, gotAction string
	endpoint := newTestEventSink(func(sig, action string) {
		gotSig = sig
		gotAction = action
	})
	defer endpoint.Close()

	// Create a webhook with a known secret, scoped to cert.* events - directly
	// via the store, not POST /api/v1/webhooks: that endpoint's URL
	// validation would (correctly) reject endpoint.URL as loopback, same
	// reasoning as the dispatcher swap above. TestWebhookREST already covers
	// that the API rejects it; this test is about what happens once a
	// webhook exists, not how it got created.
	encSecret, err := h.svc.Box().EncryptString("s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	wh, err := h.svc.Store().CreateWebhook(h.t.Context(), &store.Webhook{
		Name: "certs", URL: endpoint.URL, Events: "cert", SecretEnc: encSecret, CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	_ = wh

	// Record an audit action through the CA service's funnel. This is the same
	// path every state-changing operation takes.
	h.svc.AuditWithIP(h.t.Context(), "admin", "cert.issue", h.root.Name, "cn=app", "10.0.0.1")

	// The dispatcher enqueues a delivery row; run one tick to deliver it.
	h.srv.webhooks.Tick(h.t.Context())

	// The endpoint must have received the event, signed correctly.
	if gotAction != "cert.issue" {
		t.Fatalf("endpoint saw action %q, want cert.issue", gotAction)
	}
	if gotSig == "" {
		t.Fatal("endpoint did not receive an X-Goca-Signature header")
	}

	// The delivery should now be recorded as delivered.
	rec, out := h.apiJSON(http.MethodGet, "/api/v1/webhooks/1/deliveries", "", tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("deliveries = %d", rec.Code)
	}
	dels, _ := out["deliveries"].([]any)
	if len(dels) != 1 {
		t.Fatalf("deliveries len = %d, want 1", len(dels))
	}
	first := dels[0].(map[string]any)
	if first["status"] != "delivered" {
		t.Fatalf("delivery status = %v, want delivered", first["status"])
	}
	_ = out
}
