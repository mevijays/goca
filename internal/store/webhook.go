package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

//
// ---------- webhooks (G9) ----------
//
// A webhook is a named HTTP endpoint that receives a signed JSON event when
// goca records an audit action. The signing key is stored encrypted (enc:
// prefix) and is only ever decrypted by the dispatcher, which signs each
// delivery; it must never appear in a list or detail response.

// webhookCols is the column list every webhooks SELECT uses. secret_enc is
// deliberately excluded - it is only read by the dispatcher.
const webhookCols = `id, name, url, events, disabled, created_by, created_at, updated_at`

// webhookColsWithSecret adds the encrypted signing key, in its table position
// (after events), for the lookups the dispatcher needs to sign deliveries.
const webhookColsWithSecret = `id, name, url, events, secret_enc, disabled, created_by, created_at, updated_at`

func scanWebhook(sc interface{ Scan(...any) error }) (*Webhook, error) {
	var w Webhook
	err := sc.Scan(&w.ID, &w.Name, &w.URL, &w.Events, &w.Disabled, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func scanWebhookWithSecret(sc interface{ Scan(...any) error }) (*Webhook, error) {
	var w Webhook
	err := sc.Scan(&w.ID, &w.Name, &w.URL, &w.Events, &w.SecretEnc, &w.Disabled, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// CreateWebhook stores a new webhook. w.SecretEnc must already be encrypted
// (enc: prefix) by the caller; an empty value means the webhook is delivered
// unsigned.
func (s *Store) CreateWebhook(ctx context.Context, w *Webhook) (*Webhook, error) {
	now := time.Now().UTC()
	if w.CreatedAt.IsZero() {
		w.CreatedAt = now
	}
	w.UpdatedAt = now
	if w.Events == "" {
		w.Events = "*"
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO webhooks
	 (name, url, events, secret_enc, disabled, created_by, created_at, updated_at)
	 VALUES (?,?,?,?,?,?,?,?) RETURNING id`,
		w.Name, w.URL, w.Events, w.SecretEnc, w.Disabled, w.CreatedBy,
		w.CreatedAt.UTC(), w.UpdatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetWebhook(ctx, id)
}

// GetWebhook fetches one webhook by id, including the encrypted signing key.
func (s *Store) GetWebhook(ctx context.Context, id int64) (*Webhook, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+webhookColsWithSecret+` FROM webhooks WHERE id = ?`, id)
	w, err := scanWebhookWithSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return w, err
}

// GetWebhookByName fetches one webhook by its unique name.
func (s *Store) GetWebhookByName(ctx context.Context, name string) (*Webhook, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+webhookColsWithSecret+` FROM webhooks WHERE name = ?`, name)
	w, err := scanWebhookWithSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return w, err
}

// ListWebhooks returns every webhook, oldest first. The signing key is not
// included.
func (s *Store) ListWebhooks(ctx context.Context) ([]*Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+webhookCols+` FROM webhooks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListWebhooksWithSecret is ListWebhooks but includes the encrypted signing
// key. It exists only for the dispatcher, which must decrypt the key to sign
// each delivery; the REST list endpoint keeps using the key-less variant.
func (s *Store) ListWebhooksWithSecret(ctx context.Context) ([]*Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+webhookColsWithSecret+` FROM webhooks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Webhook
	for rows.Next() {
		w, err := scanWebhookWithSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// UpdateWebhook changes a webhook's url, events and disabled state. When
// w.SecretEnc is non-empty it replaces the stored key; when empty the existing
// key is kept.
func (s *Store) UpdateWebhook(ctx context.Context, w *Webhook) (*Webhook, error) {
	secret := w.SecretEnc
	if secret == "" {
		existing, err := s.GetWebhook(ctx, w.ID)
		if err != nil {
			return nil, err
		}
		secret = existing.SecretEnc
	}
	if w.Events == "" {
		w.Events = "*"
	}
	w.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE webhooks SET
	 url = ?, events = ?, secret_enc = ?, disabled = ?, updated_at = ?
	 WHERE id = ?`,
		w.URL, w.Events, secret, w.Disabled, w.UpdatedAt.UTC(), w.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetWebhook(ctx, w.ID)
}

// SetWebhookDisabled enables or disables a webhook. A disabled webhook is
// skipped by the dispatcher.
func (s *Store) SetWebhookDisabled(ctx context.Context, id int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE webhooks SET disabled = ?, updated_at = ? WHERE id = ?`,
		disabled, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebhook removes a webhook and, via the foreign key, its delivery
// history.
func (s *Store) DeleteWebhook(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

//
// ---------- webhook deliveries ----------
//

// CreateWebhookDelivery records a new, not-yet-attempted delivery of event to
// webhookID. The dispatcher picks it up on its next tick.
func (s *Store) CreateWebhookDelivery(ctx context.Context, webhookID int64, event, payload string) (*WebhookDelivery, error) {
	now := time.Now().UTC()
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO webhook_deliveries
	 (webhook_id, event, payload, status, attempts, last_status, last_error, next_attempt, created_at, updated_at)
	 VALUES (?,?,?,?,0,0,'',?, ?, ?) RETURNING id`,
		webhookID, event, payload, WebhookStatusPending, now, now, now).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetWebhookDelivery(ctx, id)
}

// GetWebhookDelivery fetches one delivery by id.
func (s *Store) GetWebhookDelivery(ctx context.Context, id int64) (*WebhookDelivery, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, webhook_id, event, payload, status, attempts,
	 last_status, last_error, next_attempt, created_at, updated_at
	 FROM webhook_deliveries WHERE id = ?`, id)
	d, err := scanWebhookDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ListWebhookDeliveries returns the most recent deliveries for one webhook,
// newest first, up to limit.
func (s *Store) ListWebhookDeliveries(ctx context.Context, webhookID int64, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, webhook_id, event, payload, status, attempts,
	 last_status, last_error, next_attempt, created_at, updated_at
	 FROM webhook_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT ?`, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookDelivery
	for rows.Next() {
		d, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ClaimDueWebhookDeliveries atomically selects and claims deliveries the
// dispatcher should attempt now - pending ones, plus failed ones whose
// next_attempt has passed - and returns only the rows this call actually
// claimed. Dead and delivered rows are never returned.
//
// Claiming (not just reading) is what makes this safe when goca runs as more
// than one process against a shared database (the documented Postgres
// backend supports exactly that deployment shape): two dispatchers polling
// concurrently must never both deliver the same event. This is a single
// UPDATE ... WHERE id IN (subquery) ... RETURNING statement, which is
// portable to both backends without a dialect branch (RETURNING is already
// used elsewhere in this package) and needs no explicit row lock - the UPDATE
// itself is what serializes concurrent claimants: on Postgres, a second
// UPDATE targeting an overlapping row set blocks on the first's row lock,
// then re-evaluates its WHERE clause and finds the row no longer pending, so
// it is excluded; on SQLite, writes are already serialized at the database
// level. A row already claimed by staleAfter ago is treated as abandoned (the
// claiming process crashed before recording a result) and is reclaimable.
func (s *Store) ClaimDueWebhookDeliveries(ctx context.Context, now time.Time, staleAfter time.Duration, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 {
		limit = 100
	}
	staleBefore := now.Add(-staleAfter)
	rows, err := s.db.QueryContext(ctx, `UPDATE webhook_deliveries
	 SET claimed_at = ?
	 WHERE id IN (
	   SELECT id FROM webhook_deliveries
	   WHERE (status = ? OR (status = ? AND next_attempt IS NOT NULL AND next_attempt <= ?))
	     AND (claimed_at IS NULL OR claimed_at <= ?)
	   ORDER BY id ASC LIMIT ?
	 )
	 RETURNING id, webhook_id, event, payload, status, attempts,
	 last_status, last_error, next_attempt, created_at, updated_at`,
		now, WebhookStatusPending, WebhookStatusFailed, now, staleBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookDelivery
	for rows.Next() {
		d, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordWebhookDeliveryResult records the outcome of one delivery attempt.
// delivered marks the row delivered; otherwise it increments attempts, stores
// the HTTP status and error, and either schedules a retry at nextAttempt
// (status failed) or gives up (status dead).
func (s *Store) RecordWebhookDeliveryResult(ctx context.Context, id int64, delivered bool, httpStatus int, errMsg string, nextAttempt *time.Time) error {
	now := time.Now().UTC()
	if delivered {
		_, err := s.db.ExecContext(ctx, `UPDATE webhook_deliveries SET
		 status = ?, last_status = ?, last_error = '', claimed_at = NULL, updated_at = ? WHERE id = ?`,
			WebhookStatusDelivered, httpStatus, now, id)
		return err
	}
	// Not delivered: bump the attempt count and decide failed vs dead. Clear
	// the claim either way - a retry (status failed) must be reclaimable by
	// the next tick, not stuck looking claimed until staleAfter passes.
	var status string
	if nextAttempt != nil {
		status = WebhookStatusFailed
	} else {
		status = WebhookStatusDead
	}
	_, err := s.db.ExecContext(ctx, `UPDATE webhook_deliveries SET
	 status = ?, attempts = attempts + 1, last_status = ?, last_error = ?, next_attempt = ?, claimed_at = NULL, updated_at = ?
	 WHERE id = ?`,
		status, httpStatus, errMsg, nextAttempt, now, id)
	return err
}

func scanWebhookDelivery(sc interface{ Scan(...any) error }) (*WebhookDelivery, error) {
	var d WebhookDelivery
	var next sql.NullTime
	err := sc.Scan(&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.Status, &d.Attempts,
		&d.LastStatus, &d.LastError, &next, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if next.Valid {
		t := next.Time
		d.NextAttempt = &t
	}
	return &d, nil
}
