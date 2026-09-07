package web

import (
	"context"
	"net/http"

	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

// This file is the operator-facing REST surface for CSI trust domains
// (k8s_auth_methods rows): the named Kubernetes clusters whose ServiceAccount
// tokens goca will verify. It mirrors the ACME EAB administration surface in
// acme_admin.go - admin-only, JSON in/out. The reviewer token is encrypted
// with the master key before it is stored and is never returned by any
// endpoint.

// csiAuthMethodView is the JSON shape of a trust domain. ReviewerToken is
// write-only: it is accepted on create/update (plaintext or enc:) and never
// serialized back out.
type csiAuthMethodView struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Audience           string `json:"audience"`
	IssuerURL          string `json:"issuer_url"`
	APIServerURL       string `json:"api_server_url"`
	CACert             string `json:"ca_cert"`
	ReviewerToken      string `json:"reviewer_token,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Disabled           bool   `json:"disabled"`
	CreatedBy          string `json:"created_by"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

func toCsiAuthMethodView(m *store.K8sAuthMethod) csiAuthMethodView {
	return csiAuthMethodView{
		ID:                 m.ID,
		Name:               m.Name,
		Audience:           m.Audience,
		IssuerURL:          m.IssuerURL,
		APIServerURL:       m.APIServerURL,
		CACert:             m.CACert,
		InsecureSkipVerify: m.InsecureSkipVerify,
		Disabled:           m.Disabled,
		CreatedBy:          m.CreatedBy,
		CreatedAt:          m.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:          m.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// csiAuthMethodInput is the create/update request body.
type csiAuthMethodInput struct {
	Name               string `json:"name"`
	Audience           string `json:"audience"`
	IssuerURL          string `json:"issuer_url"`
	APIServerURL       string `json:"api_server_url"`
	CACert             string `json:"ca_cert"`
	ReviewerToken      string `json:"reviewer_token"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	Disabled           bool   `json:"disabled"`
}

// encryptReviewerToken stores a reviewer token at rest: an already-encrypted
// (enc:) value is kept as-is, anything else is encrypted with the master key.
func (s *Server) encryptReviewerToken(token string) (string, error) {
	if token == "" || secret.IsEncrypted(token) {
		return token, nil
	}
	return s.svc.Box().EncryptString(token)
}

// refreshK8sRegistry reloads the named trust domain's Verifier into the
// registry after a row change, or drops it when the row is gone or disabled.
func (s *Server) refreshK8sRegistry(ctx context.Context, name string) {
	if s.k8s == nil {
		return
	}
	row, err := s.svc.Store().GetK8sAuthMethodByName(ctx, name)
	if err != nil || row.Disabled {
		s.k8s.Remove(name)
		return
	}
	v, err := verifierFromRow(s.svc, row)
	if err != nil {
		s.log.Error("rebuild k8s auth method verifier", "name", name, "error", err)
		s.k8s.Remove(name)
		return
	}
	s.k8s.Set(name, v)
}

func (s *Server) apiCsiAuthMethodList(w http.ResponseWriter, r *http.Request) error {
	rows, err := s.svc.Store().ListK8sAuthMethods(r.Context())
	if err != nil {
		return err
	}
	out := make([]csiAuthMethodView, 0, len(rows))
	for _, m := range rows {
		out = append(out, toCsiAuthMethodView(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"methods": out})
	return nil
}

func (s *Server) apiCsiAuthMethodCreate(w http.ResponseWriter, r *http.Request) error {
	var in csiAuthMethodInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if in.Name == "" {
		return badRequest("name is required")
	}
	token, err := s.encryptReviewerToken(in.ReviewerToken)
	if err != nil {
		return badRequest("encrypt reviewer token: %v", err)
	}
	row, err := s.svc.Store().CreateK8sAuthMethod(r.Context(), &store.K8sAuthMethod{
		Name:               in.Name,
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		APIServerURL:       in.APIServerURL,
		CACert:             in.CACert,
		ReviewerTokenEnc:   token,
		InsecureSkipVerify: in.InsecureSkipVerify,
		Disabled:           in.Disabled,
		CreatedBy:          currentUser(r).Username,
	})
	if err != nil {
		return badRequest("%v", err)
	}
	s.refreshK8sRegistry(r.Context(), in.Name)
	writeJSON(w, http.StatusCreated, toCsiAuthMethodView(row))
	return nil
}

func (s *Server) apiCsiAuthMethodGet(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	row, err := s.svc.Store().GetK8sAuthMethod(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, toCsiAuthMethodView(row))
	return nil
}

func (s *Server) apiCsiAuthMethodUpdate(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	var in csiAuthMethodInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	existing, err := s.svc.Store().GetK8sAuthMethod(r.Context(), id)
	if err != nil {
		return err
	}
	// The name is the trust-domain identity the CSI provider references; it is
	// not mutable through this endpoint.
	in.Name = existing.Name
	token, err := s.encryptReviewerToken(in.ReviewerToken)
	if err != nil {
		return badRequest("encrypt reviewer token: %v", err)
	}
	row, err := s.svc.Store().UpdateK8sAuthMethod(r.Context(), &store.K8sAuthMethod{
		ID:                 id,
		Name:               existing.Name,
		Audience:           in.Audience,
		IssuerURL:          in.IssuerURL,
		APIServerURL:       in.APIServerURL,
		CACert:             in.CACert,
		ReviewerTokenEnc:   token, // empty => keep existing (handled in store)
		InsecureSkipVerify: in.InsecureSkipVerify,
		Disabled:           in.Disabled,
	})
	if err != nil {
		return badRequest("%v", err)
	}
	s.refreshK8sRegistry(r.Context(), existing.Name)
	writeJSON(w, http.StatusOK, toCsiAuthMethodView(row))
	return nil
}

func (s *Server) apiCsiAuthMethodDisable(w http.ResponseWriter, r *http.Request) error {
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
	row, err := s.svc.Store().GetK8sAuthMethod(r.Context(), id)
	if err != nil {
		return err
	}
	if err := s.svc.Store().SetK8sAuthMethodDisabled(r.Context(), id, disabled); err != nil {
		return badRequest("%v", err)
	}
	s.refreshK8sRegistry(r.Context(), row.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": disabled})
	return nil
}

func (s *Server) apiCsiAuthMethodDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	row, err := s.svc.Store().GetK8sAuthMethod(r.Context(), id)
	if err != nil {
		return err
	}
	if n, err := s.svc.Store().CountSecretBindingsByAuthMethod(r.Context(), row.Name); err == nil && n > 0 {
		return badRequest("trust domain %q is referenced by %d secret binding(s); rebind or delete them first", row.Name, n)
	}
	if err := s.svc.Store().DeleteK8sAuthMethod(r.Context(), id); err != nil {
		return badRequest("%v", err)
	}
	s.refreshK8sRegistry(r.Context(), row.Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}
