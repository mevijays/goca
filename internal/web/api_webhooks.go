package web

import (
	"net/http"

	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/webhooks"
)

// This file is the operator-facing REST surface for webhooks (G9): named HTTP
// endpoints that receive signed event notifications when goca records an audit
// action. It mirrors the CSI trust-domain surface in api_csi_auth.go -
// admin-only, JSON in/out. The signing key is encrypted with the master key
// before it is stored and is never returned by any endpoint.

// webhookView is the JSON shape of a webhook. Secret is write-only: it is
// accepted on create/update (plaintext or enc:) and never serialized back out.
type webhookView struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Events    string `json:"events"`
	Secret    string `json:"secret,omitempty"`
	Disabled  bool   `json:"disabled"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toWebhookView(w *store.Webhook) webhookView {
	return webhookView{
		ID:        w.ID,
		Name:      w.Name,
		URL:       w.URL,
		Events:    w.Events,
		Disabled:  w.Disabled,
		CreatedBy: w.CreatedBy,
		CreatedAt: w.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: w.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// webhookDeliveryView is the JSON shape of a delivery record.
type webhookDeliveryView struct {
	ID          int64  `json:"id"`
	WebhookID   int64  `json:"webhook_id"`
	Event       string `json:"event"`
	Status      string `json:"status"`
	Attempts    int    `json:"attempts"`
	LastStatus  int    `json:"last_status"`
	LastError   string `json:"last_error"`
	NextAttempt string `json:"next_attempt,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func toWebhookDeliveryView(d *store.WebhookDelivery) webhookDeliveryView {
	v := webhookDeliveryView{
		ID:         d.ID,
		WebhookID:  d.WebhookID,
		Event:      d.Event,
		Status:     d.Status,
		Attempts:   d.Attempts,
		LastStatus: d.LastStatus,
		LastError:  d.LastError,
		CreatedAt:  d.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  d.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if d.NextAttempt != nil {
		v.NextAttempt = d.NextAttempt.Format("2006-01-02T15:04:05Z")
	}
	return v
}

// webhookInput is the create/update request body.
type webhookInput struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Events   string `json:"events"`
	Secret   string `json:"secret"`
	Disabled bool   `json:"disabled"`
}

// encryptWebhookSecret stores a signing key at rest: an already-encrypted
// (enc:) value is kept as-is, anything else is encrypted with the master key.
func (s *Server) encryptWebhookSecret(key string) (string, error) {
	if key == "" || secret.IsEncrypted(key) {
		return key, nil
	}
	return s.svc.Box().EncryptString(key)
}

func (s *Server) apiWebhookList(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.svc.Store().ListWebhooks(r.Context())
	if err != nil {
		return err
	}
	out := make([]webhookView, 0, len(rows))
	for _, wh := range rows {
		out = append(out, toWebhookView(wh))
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": out})
	return nil
}

func (s *Server) apiWebhookCreate(w http.ResponseWriter, r *http.Request) error {
	var in webhookInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Name == "" {
		return badRequest("name is required")
	}
	if in.URL == "" {
		return badRequest("url is required")
	}
	if err := webhooks.ValidateWebhookURL(in.URL); err != nil {
		return badRequest("url: %v", err)
	}
	sec, err := s.encryptWebhookSecret(in.Secret)
	if err != nil {
		return badRequest("encrypt webhook secret: %v", err)
	}
	row, err := s.svc.Store().CreateWebhook(r.Context(), &store.Webhook{
		Name:      in.Name,
		URL:       in.URL,
		Events:    in.Events,
		SecretEnc: sec,
		Disabled:  in.Disabled,
		CreatedBy: currentUser(r).Username,
	})
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusCreated, toWebhookView(row))
	return nil
}

func (s *Server) apiWebhookGet(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	row, err := s.svc.Store().GetWebhook(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toWebhookView(row))
	return nil
}

func (s *Server) apiWebhookUpdate(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in webhookInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	existing, err := s.svc.Store().GetWebhook(r.Context(), id)
	if err != nil {
		return err
	}
	// The name is the webhook's identity; it is not mutable through this
	// endpoint.
	in.Name = existing.Name
	if in.URL == "" {
		in.URL = existing.URL
	}
	if err := webhooks.ValidateWebhookURL(in.URL); err != nil {
		return badRequest("url: %v", err)
	}
	sec, err := s.encryptWebhookSecret(in.Secret)
	if err != nil {
		return badRequest("encrypt webhook secret: %v", err)
	}
	row, err := s.svc.Store().UpdateWebhook(r.Context(), &store.Webhook{
		ID:        id,
		Name:      existing.Name,
		URL:       in.URL,
		Events:    in.Events,
		SecretEnc: sec, // empty => keep existing (handled in store)
		Disabled:  in.Disabled,
	})
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, toWebhookView(row))
	return nil
}

func (s *Server) apiWebhookDisable(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	disabled := true
	if body.Disabled != nil {
		disabled = *body.Disabled
	}
	if _, err := s.svc.Store().GetWebhook(r.Context(), id); err != nil {
		return err
	}
	if err := s.svc.Store().SetWebhookDisabled(r.Context(), id, disabled); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": disabled})
	return nil
}

func (s *Server) apiWebhookDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if _, err := s.svc.Store().GetWebhook(r.Context(), id); err != nil {
		return err
	}
	if err := s.svc.Store().DeleteWebhook(r.Context(), id); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiWebhookDeliveries(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if _, err := s.svc.Store().GetWebhook(r.Context(), id); err != nil {
		return err
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	rows, err := s.svc.Store().ListWebhookDeliveries(r.Context(), id, limit)
	if err != nil {
		return err
	}
	out := make([]webhookDeliveryView, 0, len(rows))
	for _, d := range rows {
		out = append(out, toWebhookDeliveryView(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": out})
	return nil
}
