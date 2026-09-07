package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

func newTestDispatcher(t *testing.T) (*store.Store, *secret.Box, *Dispatcher) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "webhooks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secret.NewBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	d := New(st, box, nil, Options{
		MaxAttempts: 3,
		Backoff:     time.Millisecond,
		Interval:    time.Millisecond,
		Timeout:     2 * time.Second,
		ClaimStale:  50 * time.Millisecond,
		// httptest.NewServer binds to 127.0.0.1, and these tests are about
		// delivery/retry mechanics, not the SSRF defense (that has its own
		// tests in ssrf_test.go against the real, unoverridden transport) -
		// so the loopback block is deliberately opted out of here.
		Transport: http.DefaultTransport,
	})
	return st, box, d
}

func TestMatches(t *testing.T) {
	cases := []struct {
		filter, action string
		want           bool
	}{
		{"*", "cert.issue", true},
		{"", "cert.issue", true},
		{"cert.issue", "cert.issue", true},
		{"cert", "cert.issue", true},
		{"cert.issue,secret.put", "secret.put", true},
		{"cert.issue,secret.put", "cert.revoke", false},
		{"cert.issue", "secret.put", false},
		// A token must match a "." boundary, not just any string prefix -
		// "cert" is a real filter (matches cert.issue, cert.revoke, ...) but
		// must not also match an unrelated action that happens to start with
		// the same letters.
		{"cert", "certificate.import", false},
		{"user", "userinvite.sent", false},
		{"acme.eab", "acme.eab.create", true},
		{"acme.eab", "acme.eabcde.thing", false},
	}
	for _, c := range cases {
		if got := matches(c.filter, c.action); got != c.want {
			t.Errorf("matches(%q, %q) = %v, want %v", c.filter, c.action, got, c.want)
		}
	}
}

func TestSign(t *testing.T) {
	key := []byte("s3cr3t")
	body := []byte(`{"id":"evt-1"}`)
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := sign(key, body); got != want {
		t.Fatalf("sign = %q, want %q", got, want)
	}
}

// TestEmitAndDeliver verifies the full happy path: an audit event fans out to
// a matching webhook, the dispatcher POSTs the payload, and the receiver
// verifies the HMAC signature.
func TestEmitAndDeliver(t *testing.T) {
	st, box, d := newTestDispatcher(t)
	ctx := context.Background()

	secretKey := "s3cr3t"
	enc, err := box.EncryptString(secretKey)
	if err != nil {
		t.Fatal(err)
	}
	var gotSig, gotBody, gotEvent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Goca-Signature")
		gotEvent = r.Header.Get("X-Goca-Event")
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, err := st.CreateWebhook(ctx, &store.Webhook{Name: "ops", URL: srv.URL, Events: "*", SecretEnc: enc})
	if err != nil {
		t.Fatal(err)
	}

	// Emit an event; it should enqueue a delivery for the matching webhook.
	// ListWebhookDeliveries, not DueWebhookDeliveries/ClaimDueWebhookDeliveries:
	// this is a plain read, so it cannot claim the row out from under tick()
	// below the way a due-check would.
	d.Emit(ctx, "admin", "cert.issue", "ca-1", "cn=app", "10.0.0.1")
	enqueued, err := st.ListWebhookDeliveries(ctx, wh.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(enqueued) != 1 {
		t.Fatalf("enqueued = %d, want 1", len(enqueued))
	}

	// Deliver it.
	d.tick(ctx)

	del, err := st.GetWebhookDelivery(ctx, enqueued[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if del.Status != store.WebhookStatusDelivered {
		t.Fatalf("status = %q, want delivered (last_error=%q)", del.Status, del.LastError)
	}
	if gotEvent != "cert.issue" {
		t.Fatalf("X-Goca-Event = %q, want cert.issue", gotEvent)
	}
	// Verify the signature the receiver saw.
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(gotBody))
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != wantSig {
		t.Fatalf("signature mismatch:\n got %q\nwant %q", gotSig, wantSig)
	}
	// The payload must be a well-formed event.
	var ev Event
	if err := json.Unmarshal([]byte(gotBody), &ev); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if ev.Action != "cert.issue" || ev.Actor != "admin" {
		t.Fatalf("event = %+v, want action cert.issue actor admin", ev)
	}
	_ = wh
}

// TestEmitSkipsNonMatchingAndDisabled verifies the event filter and the
// disabled flag both suppress delivery.
func TestEmitSkipsNonMatchingAndDisabled(t *testing.T) {
	st, box, d := newTestDispatcher(t)
	ctx := context.Background()

	enc, _ := box.EncryptString("k")
	// A webhook that only matches cert.* and one that is disabled.
	certs, err := st.CreateWebhook(ctx, &store.Webhook{Name: "certs", URL: "https://x.example.com", Events: "cert", SecretEnc: enc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateWebhook(ctx, &store.Webhook{Name: "off", URL: "https://y.example.com", Events: "*", SecretEnc: enc, Disabled: true}); err != nil {
		t.Fatal(err)
	}

	// A secret.* event: matches neither the cert-only webhook nor the disabled
	// one, so nothing is enqueued. A plain read (ListWebhookDeliveries), not a
	// claim - this test never delivers anything, so nothing needs releasing.
	d.Emit(ctx, "admin", "secret.put", "s1", "", "")
	enqueued, err := st.ListWebhookDeliveries(ctx, certs.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(enqueued) != 0 {
		t.Fatalf("enqueued = %d, want 0 (no matching enabled webhook)", len(enqueued))
	}

	// A cert.* event: matches only the cert webhook, not the disabled one.
	d.Emit(ctx, "admin", "cert.issue", "ca-1", "", "")
	enqueued, _ = st.ListWebhookDeliveries(ctx, certs.ID, 10)
	if len(enqueued) != 1 {
		t.Fatalf("enqueued = %d, want 1", len(enqueued))
	}
	if enqueued[0].WebhookID != certs.ID {
		t.Fatalf("delivery went to webhook %d, want the enabled certs webhook %d", enqueued[0].WebhookID, certs.ID)
	}
}

// TestDeliverRetriesThenDeadLetters verifies that a failing endpoint is
// retried and eventually dead-lettered after MaxAttempts.
func TestDeliverRetriesThenDeadLetters(t *testing.T) {
	st, _, d := newTestDispatcher(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	wh, err := st.CreateWebhook(ctx, &store.Webhook{Name: "ops", URL: srv.URL, Events: "*"})
	if err != nil {
		t.Fatal(err)
	}
	del, err := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", `{"id":"evt-1"}`)
	if err != nil {
		t.Fatal(err)
	}

	// Each tick performs one attempt. With MaxAttempts=3 the delivery goes
	// failed, failed, then dead. The backoff is 1ms, so a short real sleep
	// between ticks lets each scheduled next_attempt elapse before the next
	// poll - tick() claims and reads next_attempt itself using real time, so
	// there is no separate due-check here to race against it (a due-check
	// using a synthetic future "now" would claim the row with that same
	// future timestamp, which tick()'s own real-time claim would then never
	// recognize as stale, and the delivery would never actually be attempted).
	for i := 0; i < d.maxAttempts; i++ {
		time.Sleep(20 * time.Millisecond)
		d.tick(ctx)
	}

	got, err := st.GetWebhookDelivery(ctx, del.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.WebhookStatusDead {
		t.Fatalf("status = %q, want dead", got.Status)
	}
	if got.Attempts != d.maxAttempts {
		t.Fatalf("attempts = %d, want %d", got.Attempts, d.maxAttempts)
	}
	if got.LastStatus != 500 {
		t.Fatalf("last_status = %d, want 500", got.LastStatus)
	}
	// A dead delivery is never due again.
	due, _ := st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC().Add(time.Hour), time.Minute, 10)
	if len(due) != 0 {
		t.Fatalf("dead delivery still due (%d)", len(due))
	}
}
