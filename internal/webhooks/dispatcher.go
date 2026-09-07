// Package webhooks implements goca's eventing (G9): when the CA service
// records an audit action, matching webhooks receive a signed JSON event over
// HTTP. Delivery is durable - each event is written to the webhook_deliveries
// table and a background worker retries failures with exponential backoff,
// dead-lettering a delivery once it exhausts its attempts.
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

// Event is the JSON body delivered to a webhook endpoint. It mirrors an audit
// record plus a stable event id (the delivery id) so receivers can
// de-duplicate.
type Event struct {
	ID     string    `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// Dispatcher enqueues and delivers webhook events.
type Dispatcher struct {
	st          *store.Store
	box         *secret.Box
	log         *slog.Logger
	http        *http.Client
	maxAttempts int
	backoff     time.Duration
	interval    time.Duration
	claimStale  time.Duration
}

// Options tunes the dispatcher. Zero values fall back to sensible defaults.
type Options struct {
	// MaxAttempts is how many delivery attempts a delivery gets before it is
	// dead-lettered. Default 5.
	MaxAttempts int
	// Backoff is the base retry delay; the nth failure waits
	// Backoff * 2^(n-1). Default 30s.
	Backoff time.Duration
	// Interval is how often the worker polls for due deliveries. Default 5s.
	Interval time.Duration
	// Timeout bounds a single HTTP delivery. Default 10s.
	Timeout time.Duration
	// Transport overrides the delivery HTTP client's transport. Default
	// newDeliveryTransport(), which refuses to connect to loopback and
	// link-local (including cloud metadata) addresses - see ssrf.go. Only
	// meant for tests that deliberately point at a local httptest server and
	// are testing delivery/retry behavior, not the SSRF defense itself;
	// production code should never set this.
	Transport http.RoundTripper
	// ClaimStale is how long a claimed-but-unresolved delivery is left alone
	// before another tick (in this process or, sharing a database, another
	// goca instance entirely) is allowed to reclaim it - the process that
	// claimed it is assumed to have crashed. Must comfortably exceed Timeout
	// plus processing overhead, or a dispatcher's own in-flight deliveries
	// could be reclaimed and double-sent by itself. Default 2m.
	ClaimStale time.Duration
}

func (o Options) withDefaults() Options {
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 5
	}
	if o.Backoff <= 0 {
		o.Backoff = 30 * time.Second
	}
	if o.Interval <= 0 {
		o.Interval = 5 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.ClaimStale <= 0 {
		o.ClaimStale = 2 * time.Minute
	}
	return o
}

// New builds a Dispatcher. box is used to decrypt each webhook's signing key.
func New(st *store.Store, box *secret.Box, logger *slog.Logger, opts Options) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	opts = opts.withDefaults()
	transport := opts.Transport
	if transport == nil {
		transport = newDeliveryTransport()
	}
	return &Dispatcher{
		st:          st,
		box:         box,
		log:         logger,
		http:        &http.Client{Timeout: opts.Timeout, Transport: transport},
		maxAttempts: opts.MaxAttempts,
		backoff:     opts.Backoff,
		interval:    opts.Interval,
		claimStale:  opts.ClaimStale,
	}
}

// Emit is the event sink installed on the CA service. It is called after each
// audit write. It enqueues a durable delivery row for every enabled webhook
// whose event filter matches the action. It never returns an error: eventing
// must not disturb the operation that just succeeded.
func (d *Dispatcher) Emit(ctx context.Context, actor, action, target, detail, ip string) {
	webhooks, err := d.st.ListWebhooksWithSecret(ctx)
	if err != nil {
		d.log.Warn("webhook: list webhooks", "error", err)
		return
	}
	for _, wh := range webhooks {
		if wh.Disabled || !matches(wh.Events, action) {
			continue
		}
		payload, err := json.Marshal(Event{
			ID:     fmt.Sprintf("evt-%d", time.Now().UnixNano()),
			TS:     time.Now().UTC(),
			Actor:  actor,
			Action: action,
			Target: target,
			Detail: detail,
			IP:     ip,
		})
		if err != nil {
			d.log.Warn("webhook: encode event", "error", err)
			continue
		}
		if _, err := d.st.CreateWebhookDelivery(ctx, wh.ID, action, string(payload)); err != nil {
			d.log.Warn("webhook: enqueue delivery", "webhook", wh.Name, "error", err)
		}
	}
}

// Run polls for due deliveries and delivers them until ctx is cancelled. It is
// meant to run in its own goroutine, started by the web server.
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.tick(ctx)
		}
	}
}

// tick delivers every delivery that is due now.
func (d *Dispatcher) tick(ctx context.Context) {
	due, err := d.st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), d.claimStale, 100)
	if err != nil {
		d.log.Warn("webhook: claim due deliveries", "error", err)
		return
	}
	for _, del := range due {
		d.deliver(ctx, del)
	}
}

// Tick delivers every delivery that is due now. It is exported so tests (and
// operators who want to force a flush) can drive a single poll without waiting
// for the worker's interval.
func (d *Dispatcher) Tick(ctx context.Context) { d.tick(ctx) }

// deliver performs one attempt of a delivery and records the outcome.
func (d *Dispatcher) deliver(ctx context.Context, del *store.WebhookDelivery) {
	wh, err := d.st.GetWebhook(ctx, del.WebhookID)
	if err != nil {
		// The webhook was deleted; nothing to deliver to.
		d.log.Debug("webhook: webhook gone", "delivery", del.ID, "error", err)
		return
	}
	var key []byte
	if wh.SecretEnc != "" {
		key, err = d.box.Decrypt(wh.SecretEnc)
		if err != nil {
			d.log.Warn("webhook: decrypt signing key", "webhook", wh.Name, "error", err)
			return
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader([]byte(del.Payload)))
	if err != nil {
		d.recordFailure(ctx, del, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goca-Event", del.Event)
	req.Header.Set("X-Goca-Delivery", fmt.Sprintf("%d", del.ID))
	if len(key) > 0 {
		req.Header.Set("X-Goca-Signature", sign(key, []byte(del.Payload)))
	}
	resp, err := d.http.Do(req)
	if err != nil {
		d.recordFailure(ctx, del, 0, err.Error())
		return
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; we do not care about the
	// body content, only the status.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_ = d.st.RecordWebhookDeliveryResult(ctx, del.ID, true, resp.StatusCode, "", nil)
		return
	}
	d.recordFailure(ctx, del, resp.StatusCode, fmt.Sprintf("unexpected status %d", resp.StatusCode))
}

// recordFailure stores a failed attempt and decides whether to retry or
// dead-letter.
func (d *Dispatcher) recordFailure(ctx context.Context, del *store.WebhookDelivery, httpStatus int, errMsg string) {
	attempts := del.Attempts + 1
	var next *time.Time
	if attempts < d.maxAttempts {
		delay := d.backoff << (attempts - 1) // backoff * 2^(attempts-1)
		if delay > 15*time.Minute {
			delay = 15 * time.Minute
		}
		t := time.Now().UTC().Add(delay)
		next = &t
	}
	if err := d.st.RecordWebhookDeliveryResult(ctx, del.ID, false, httpStatus, errMsg, next); err != nil {
		d.log.Warn("webhook: record failure", "delivery", del.ID, "error", err)
	}
}

// matches reports whether an event filter matches an action. The filter is a
// comma-separated list of action prefixes; "*" matches everything. A token
// matches when the action equals it, or is a "."-separated ancestor of it (so
// "cert" matches "cert.issue", and "acme.eab" matches "acme.eab.create").
//
// The boundary check (tok+".") matters: a bare strings.HasPrefix(action, tok)
// would also match an unrelated action that merely shares tok as a string
// prefix - "cert" matching a hypothetical future "certificate.import" action,
// silently subscribing a webhook filtered on "cert" to events its operator
// never asked for. There is no such collision in today's action vocabulary,
// which is exactly why this had no failing test until one was added for it.
func matches(filter, action string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" || filter == "*" {
		return true
	}
	for _, tok := range strings.Split(filter, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == action || strings.HasPrefix(action, tok+".") {
			return true
		}
	}
	return false
}

// sign returns "sha256=<hex>" of the HMAC-SHA256 of body under key.
func sign(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
