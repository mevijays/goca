package web

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// This file is the REST API for goca's secret manager (internal/vault).
// Admin-only in this phase, mirroring the ACME EAB administration surface in
// acme_admin.go. A scoped, workload-facing fetch endpoint - authenticated by
// a Kubernetes ServiceAccount token rather than a session or API token -
// arrives with the CSI provider in a later phase; see docs/secrets.md.
//
// Secrets are addressed by numeric id here, the same way CAs and
// certificates are, even though every other interface (the CLI, Bind's glob
// matching) addresses them by name - vault.Service.GetByID bridges the two.

func pathIntParam(r *http.Request, name string) (int64, error) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, badRequest("%q is not a valid %s", r.PathValue(name), name)
	}
	return v, nil
}

func (s *Server) secretByPathID(r *http.Request) (*store.Secret, error) {
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	sec, err := s.vault.GetByID(r.Context(), id)
	if err != nil {
		return nil, err
	}
	return sec, nil
}

//
// ---------- secrets ----------
//

func (s *Server) apiSecretList(w http.ResponseWriter, r *http.Request) error {
	secrets, err := s.vault.List(r.Context(), r.URL.Query().Get("type"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": secrets})
	return nil
}

func (s *Server) apiSecretCreate(w http.ResponseWriter, r *http.Request) error {
	var in vault.CreateInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	sec, err := s.vault.Create(r.Context(), in)
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusCreated, sec)
	return nil
}

func (s *Server) apiSecretGet(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, sec)
	return nil
}

func (s *Server) apiSecretUpdate(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	var body struct {
		Description  *string           `json:"description"`
		Labels       map[string]string `json:"labels"`
		RotationDays *int              `json:"rotation_days"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	description := sec.Description
	if body.Description != nil {
		description = *body.Description
	}
	labels := sec.Labels()
	if body.Labels != nil {
		labels = body.Labels
	}
	rotationDays := sec.RotationDays
	if body.RotationDays != nil {
		rotationDays = *body.RotationDays
	}
	updated, err := s.vault.UpdateMeta(r.Context(), sec.Name, description, labels, rotationDays, currentUser(r).Username)
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, updated)
	return nil
}

func (s *Server) apiSecretDelete(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	if err := s.vault.Delete(r.Context(), sec.Name, currentUser(r).Username); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiSecretDisable(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
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
	if err := s.vault.SetDisabled(r.Context(), sec.Name, disabled, currentUser(r).Username); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": disabled})
	return nil
}

// apiSecretMaterialize returns a secret's current content: one file for
// kv/file secrets, or the tls.crt/tls.key/ca.crt triad for a certificate
// secret - the same resolution a later CSI provider Mount will perform.
// Every file is base64, since a kv/file payload is arbitrary bytes.
func (s *Server) apiSecretMaterialize(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	_, files, version, err := s.vault.Materialize(r.Context(), sec.Name)
	if err != nil {
		return badRequest("%v", err)
	}
	s.vault.AuditWithIP(r.Context(), currentUser(r).Username, "secret.materialize", sec.Name, "", clientIP(r))
	type fileJSON struct {
		Name       string `json:"name"`
		DataBase64 string `json:"data_base64"`
	}
	out := make([]fileJSON, len(files))
	for i, f := range files {
		out[i] = fileJSON{Name: f.Name, DataBase64: base64.StdEncoding.EncodeToString(f.Data)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": sec, "version": version, "files": out})
	return nil
}

//
// ---------- versions ----------
//

func (s *Server) apiSecretVersionList(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	_, versions, err := s.vault.Versions(r.Context(), sec.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
	return nil
}

func (s *Server) apiSecretVersionPut(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	var body struct {
		ValueBase64 string `json:"value_base64"`
		ContentType string `json:"content_type"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	value, err := base64.StdEncoding.DecodeString(body.ValueBase64)
	if err != nil {
		return badRequest("value_base64 is not valid base64: %v", err)
	}
	v, err := s.vault.Put(r.Context(), sec.Name, value, body.ContentType, currentUser(r).Username)
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusCreated, v)
	return nil
}

func (s *Server) apiSecretVersionGet(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	version, err := pathIntParam(r, "version")
	if err != nil {
		return err
	}
	_, pt, err := s.vault.GetVersion(r.Context(), sec.Name, int(version))
	if err != nil {
		return badRequest("%v", err)
	}
	s.vault.AuditWithIP(r.Context(), currentUser(r).Username, "secret.version_read", sec.Name,
		"version="+strconv.FormatInt(version, 10), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": sec, "version": version, "value_base64": base64.StdEncoding.EncodeToString(pt),
	})
	return nil
}

func (s *Server) apiSecretVersionDestroy(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	version, err := pathIntParam(r, "version")
	if err != nil {
		return err
	}
	if err := s.vault.DestroyVersion(r.Context(), sec.Name, int(version), currentUser(r).Username); err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "destroyed"})
	return nil
}

//
// ---------- bindings ----------
//

func (s *Server) apiSecretBindingList(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	bindings, err := s.vault.Bindings(r.Context(), sec.Name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": bindings})
	return nil
}

func (s *Server) apiSecretBindingCreate(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.secretByPathID(r)
	if err != nil {
		return err
	}
	var body struct {
		K8sNamespace      string `json:"k8s_namespace"`
		K8sServiceAccount string `json:"k8s_service_account"`
		ExpiresInDays     int    `json:"expires_in_days"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, body.ExpiresInDays)
		expiresAt = &t
	}
	b, err := s.vault.Bind(r.Context(), sec.Name, body.K8sNamespace, body.K8sServiceAccount, expiresAt, currentUser(r).Username)
	if err != nil {
		return badRequest("%v", err)
	}
	writeJSON(w, http.StatusCreated, b)
	return nil
}

func (s *Server) apiSecretBindingDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	if err := s.vault.Unbind(r.Context(), id, currentUser(r).Username); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}
