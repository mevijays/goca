package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWebhookCRUD(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "webhook.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Create.
	wh, err := st.CreateWebhook(ctx, &Webhook{
		Name:      "ops",
		URL:       "https://hooks.example.com/goca",
		Events:    "*",
		SecretEnc: "enc:v1:deadbeef",
		CreatedBy: "admin",
	})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	if wh.ID == 0 {
		t.Fatal("created webhook has zero id")
	}
	if wh.Events != "*" {
		t.Fatalf("events = %q, want *", wh.Events)
	}

	// Get by id and by name.
	got, err := st.GetWebhook(ctx, wh.ID)
	if err != nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if got.SecretEnc != "enc:v1:deadbeef" {
		t.Fatalf("secret_enc = %q, want the encrypted value", got.SecretEnc)
	}
	byName, err := st.GetWebhookByName(ctx, "ops")
	if err != nil {
		t.Fatalf("GetWebhookByName: %v", err)
	}
	if byName.ID != wh.ID {
		t.Fatalf("by-name id = %d, want %d", byName.ID, wh.ID)
	}

	// List (key-less variant must not leak the secret).
	list, err := st.ListWebhooks(ctx)
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	if list[0].SecretEnc != "" {
		t.Fatalf("ListWebhooks leaked secret_enc = %q", list[0].SecretEnc)
	}

	// Update: change url and events, keep the secret.
	wh.URL = "https://hooks.example.com/changed"
	wh.Events = "cert.issue,secret.put"
	updated, err := st.UpdateWebhook(ctx, wh)
	if err != nil {
		t.Fatalf("UpdateWebhook: %v", err)
	}
	if updated.URL != "https://hooks.example.com/changed" {
		t.Fatalf("url = %q, want the new url", updated.URL)
	}
	if updated.SecretEnc != "enc:v1:deadbeef" {
		t.Fatalf("update dropped the secret: %q", updated.SecretEnc)
	}

	// Disable / enable.
	if err := st.SetWebhookDisabled(ctx, wh.ID, true); err != nil {
		t.Fatalf("SetWebhookDisabled: %v", err)
	}
	if got, _ := st.GetWebhook(ctx, wh.ID); !got.Disabled {
		t.Fatal("webhook not disabled")
	}
	if err := st.SetWebhookDisabled(ctx, wh.ID, false); err != nil {
		t.Fatalf("SetWebhookDisabled enable: %v", err)
	}

	// Delete cascades to deliveries.
	del, err := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", `{"id":"evt-1"}`)
	if err != nil {
		t.Fatalf("CreateWebhookDelivery: %v", err)
	}
	if del.Status != WebhookStatusPending {
		t.Fatalf("new delivery status = %q, want pending", del.Status)
	}
	if err := st.DeleteWebhook(ctx, wh.ID); err != nil {
		t.Fatalf("DeleteWebhook: %v", err)
	}
	if _, err := st.GetWebhook(ctx, wh.ID); err != ErrNotFound {
		t.Fatalf("GetWebhook after delete = %v, want ErrNotFound", err)
	}
	deliveries, err := st.ListWebhookDeliveries(ctx, wh.ID, 10)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(deliveries) != 0 {
		t.Fatalf("deliveries after cascade delete = %d, want 0", len(deliveries))
	}
}

func TestWebhookDeliveryRetryAndDeadLetter(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "webhook-delivery.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	wh, err := st.CreateWebhook(ctx, &Webhook{Name: "ops", URL: "https://x.example.com", Events: "*"})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	del, err := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", `{"id":"evt-1"}`)
	if err != nil {
		t.Fatalf("CreateWebhookDelivery: %v", err)
	}

	const staleAfter = time.Minute

	// A pending delivery is due (and claimed) immediately.
	due, err := st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), staleAfter, 10)
	if err != nil {
		t.Fatalf("ClaimDueWebhookDeliveries: %v", err)
	}
	if len(due) != 1 || due[0].ID != del.ID {
		t.Fatalf("due = %d deliveries, want the one pending delivery", len(due))
	}

	// Record a failure that schedules a retry in the future: it must no longer
	// be due now, but will be due after the delay. RecordWebhookDeliveryResult
	// also clears the claim set above, so the delivery is reclaimable as soon
	// as it is due again - not stuck waiting for staleAfter to pass.
	future := time.Now().UTC().Add(time.Hour)
	if err := st.RecordWebhookDeliveryResult(ctx, del.ID, false, 500, "boom", &future); err != nil {
		t.Fatalf("RecordWebhookDeliveryResult: %v", err)
	}
	got, _ := st.GetWebhookDelivery(ctx, del.ID)
	if got.Status != WebhookStatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if got.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", got.Attempts)
	}
	due, _ = st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), staleAfter, 10)
	if len(due) != 0 {
		t.Fatalf("delivery with a future next_attempt is still due (%d)", len(due))
	}
	// Once the clock passes next_attempt it is due again.
	due, _ = st.ClaimDueWebhookDeliveries(ctx, future.Add(time.Minute), staleAfter, 10)
	if len(due) != 1 {
		t.Fatalf("delivery not due after next_attempt passed (%d)", len(due))
	}

	// Exhausting attempts (nextAttempt nil) dead-letters the delivery.
	if err := st.RecordWebhookDeliveryResult(ctx, del.ID, false, 500, "boom", nil); err != nil {
		t.Fatalf("RecordWebhookDeliveryResult dead: %v", err)
	}
	got, _ = st.GetWebhookDelivery(ctx, del.ID)
	if got.Status != WebhookStatusDead {
		t.Fatalf("status = %q, want dead", got.Status)
	}
	// Dead deliveries are never due.
	due, _ = st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC().Add(time.Hour), staleAfter, 10)
	if len(due) != 0 {
		t.Fatalf("dead delivery is still due (%d)", len(due))
	}

	// A delivered delivery is never due.
	del2, _ := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", `{"id":"evt-2"}`)
	if err := st.RecordWebhookDeliveryResult(ctx, del2.ID, true, 200, "", nil); err != nil {
		t.Fatalf("RecordWebhookDeliveryResult delivered: %v", err)
	}
	got2, _ := st.GetWebhookDelivery(ctx, del2.ID)
	if got2.Status != WebhookStatusDelivered {
		t.Fatalf("status = %q, want delivered", got2.Status)
	}
	due, _ = st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), staleAfter, 10)
	if len(due) != 0 {
		t.Fatalf("delivered delivery is still due (%d)", len(due))
	}
}

// TestClaimDueWebhookDeliveriesNoDoubleClaim is the regression test for the
// bug this whole claiming mechanism exists to fix: concurrent callers (two
// goca processes sharing a database, or just two overlapping ticks) must
// never both claim the same delivery. Without the claimed_at gate, this test
// fails by finding an id claimed more than once.
func TestClaimDueWebhookDeliveriesNoDoubleClaim(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "webhook-claim-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	wh, err := st.CreateWebhook(ctx, &Webhook{Name: "ops", URL: "https://x.example.com", Events: "*"})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}

	const numDeliveries = 40
	want := make(map[int64]bool, numDeliveries)
	for i := 0; i < numDeliveries; i++ {
		del, err := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", `{"id":"evt"}`)
		if err != nil {
			t.Fatalf("CreateWebhookDelivery: %v", err)
		}
		want[del.ID] = true
	}

	const numClaimers = 8
	results := make(chan []*WebhookDelivery, numClaimers)
	var wg sync.WaitGroup
	for i := 0; i < numClaimers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claimed, err := st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), time.Minute, numDeliveries)
			if err != nil {
				t.Errorf("ClaimDueWebhookDeliveries: %v", err)
				return
			}
			results <- claimed
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]int, numDeliveries)
	for claimed := range results {
		for _, d := range claimed {
			seen[d.ID]++
		}
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("delivery %d claimed %d times concurrently, want at most 1", id, count)
		}
	}
	for id := range want {
		if seen[id] == 0 {
			t.Errorf("delivery %d was never claimed by any of the %d concurrent claimers", id, numClaimers)
		}
	}
	if len(seen) != numDeliveries {
		t.Errorf("claimed %d distinct deliveries across all claimers, want %d", len(seen), numDeliveries)
	}
}
