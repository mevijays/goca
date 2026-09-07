package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// This file is the portal side of goca's secret manager - admin-only, like
// its REST API counterpart in api_secrets.go, which internal/vault.Service
// backs identically. See docs/secrets.md for the design and threat model.

//
// ---------- list + create ----------
//

func (s *Server) handleSecretsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	secrets, err := s.vault.List(ctx, r.URL.Query().Get("type"))
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	certs, _, _ := s.svc.Search(ctx, store.CertFilter{Limit: 200, SortBy: "created_at", SortDesc: true})
	s.render(w, r, "secrets.html", viewData{
		Title: "Secrets",
		Nav:   "secrets",
		Data: map[string]any{
			"Secrets":    secrets,
			"Certs":      certs,
			"FilterType": r.URL.Query().Get("type"),
			"CSIEnabled": s.k8s != nil,
		},
	})
}

func (s *Server) handleSecretCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	in := vault.CreateInput{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Type:         r.FormValue("type"),
		Description:  strings.TrimSpace(r.FormValue("description")),
		Labels:       parseLabelsForm(r.FormValue("labels")),
		RotationDays: atoiDefault(r.FormValue("rotation_days"), 0),
		Actor:        currentUser(r).Username,
	}
	if in.Type == store.SecretTypeCertificate {
		if ref := strings.TrimSpace(r.FormValue("cert_id")); ref != "" {
			cert, err := s.svc.FindCertificate(r.Context(), ref)
			if err != nil {
				s.flash(w, r, "error", fmt.Sprintf("Resolve certificate %q: %v", ref, err))
				http.Redirect(w, r, "/secrets", http.StatusSeeOther)
				return
			}
			in.CertID = &cert.ID
		}
	}
	sec, err := s.vault.Create(r.Context(), in)
	if err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}
	s.flash(w, r, "success", fmt.Sprintf("Secret %q created.", sec.Name))
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

//
// ---------- detail ----------
//

func (s *Server) lookupSecret(w http.ResponseWriter, r *http.Request) (*store.Secret, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad secret id", "That is not a valid id.")
		return nil, false
	}
	sec, err := s.vault.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Secret not found", "No secret with that id exists.")
		} else {
			s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		}
		return nil, false
	}
	return sec, true
}

func (s *Server) handleSecretDetail(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	data := map[string]any{
		"Secret":     sec,
		"Labels":     sec.Labels(),
		"LabelsForm": labelsToForm(sec.Labels()),
	}

	bindings, err := s.vault.Bindings(ctx, sec.Name)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
		return
	}
	data["Bindings"] = bindings

	switch sec.Type {
	case store.SecretTypeCertificate:
		if sec.CertID != nil {
			if cert, err := s.svc.GetCertificate(ctx, *sec.CertID); err == nil {
				data["Cert"] = cert
			}
		}
	default:
		_, versions, err := s.vault.Versions(ctx, sec.Name)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "Database error", err.Error())
			return
		}
		data["Versions"] = versions

		// The download link needs the exact file name Materialize will
		// produce - which mirrors its own "" -> "value" fallback, and (since
		// the newest version can itself be destroyed) is not always
		// versions[0] - so ask the store for the same row Materialize would
		// resolve, without decrypting it just to render this page.
		if latest, err := s.vault.Store().GetLatestSecretVersion(ctx, sec.ID); err == nil {
			fname := strings.TrimSpace(latest.ContentType)
			if fname == "" {
				fname = "value"
			}
			data["DownloadFile"] = fname
		}
	}

	s.render(w, r, "secret_detail.html", viewData{
		Title: sec.Name,
		Nav:   "secrets",
		Data:  data,
	})
}

func (s *Server) handleSecretUpdateMeta(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	_, err := s.vault.UpdateMeta(r.Context(), sec.Name,
		strings.TrimSpace(r.FormValue("description")),
		parseLabelsForm(r.FormValue("labels")),
		atoiDefault(r.FormValue("rotation_days"), sec.RotationDays),
		currentUser(r).Username)
	if err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", "Updated.")
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

func (s *Server) handleSecretDisable(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	disabled := r.FormValue("disabled") != "0"
	if err := s.vault.SetDisabled(r.Context(), sec.Name, disabled, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else if disabled {
		s.flash(w, r, "success", "Secret disabled.")
	} else {
		s.flash(w, r, "success", "Secret re-enabled.")
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

func (s *Server) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	if err := s.vault.Delete(r.Context(), sec.Name, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
		http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
		return
	}
	s.flash(w, r, "success", fmt.Sprintf("Secret %q deleted.", sec.Name))
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

//
// ---------- versions ----------
//

func (s *Server) handleSecretVersionPut(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(4 << 20); err != nil && err != http.ErrNotMultipart {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}

	var value []byte
	contentType := ""
	if file, hdr, err := r.FormFile("value_file"); err == nil {
		defer file.Close()
		buf, err := io.ReadAll(file)
		if err != nil {
			s.flash(w, r, "error", "read uploaded file: "+err.Error())
			http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
			return
		}
		value = buf
		contentType = hdr.Filename
	} else {
		value = []byte(r.FormValue("value"))
	}
	if len(value) == 0 {
		s.flash(w, r, "error", "Provide a value or choose a file to upload.")
		http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
		return
	}

	v, err := s.vault.Put(r.Context(), sec.Name, value, contentType, currentUser(r).Username)
	if err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf("Wrote version %d (%d bytes).", v.Version, v.SizeBytes))
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

func (s *Server) handleSecretVersionDestroy(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad version", "That is not a valid version number.")
		return
	}
	if err := s.vault.DestroyVersion(r.Context(), sec.Name, version, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", fmt.Sprintf("Version %d destroyed.", version))
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

//
// ---------- bindings ----------
//

func (s *Server) handleSecretBindingCreate(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Malformed form", err.Error())
		return
	}
	var expiresAt *time.Time
	if days := atoiDefault(r.FormValue("expires_in_days"), 0); days > 0 {
		t := time.Now().AddDate(0, 0, days)
		expiresAt = &t
	}
	_, err := s.vault.Bind(r.Context(), sec.Name,
		r.FormValue("k8s_namespace"), r.FormValue("k8s_service_account"), r.FormValue("k8s_auth_method"), expiresAt,
		currentUser(r).Username)
	if err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", "Binding added.")
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

func (s *Server) handleSecretBindingDelete(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	bindingID, err := strconv.ParseInt(r.PathValue("bindingID"), 10, 64)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Bad binding id", "That is not a valid id.")
		return
	}
	if err := s.vault.Unbind(r.Context(), bindingID, currentUser(r).Username); err != nil {
		s.flash(w, r, "error", err.Error())
	} else {
		s.flash(w, r, "success", "Binding revoked.")
	}
	http.Redirect(w, r, fmt.Sprintf("/secrets/%d", sec.ID), http.StatusSeeOther)
}

//
// ---------- download ----------
//

// handleSecretDownload serves a secret's current materialized content: the
// single "value" file for a kv/file secret, or one named file of a
// certificate secret's tls.crt/tls.key/ca.crt triad.
func (s *Server) handleSecretDownload(w http.ResponseWriter, r *http.Request) {
	sec, ok := s.lookupSecret(w, r)
	if !ok {
		return
	}
	file := r.PathValue("file")
	_, files, _, err := s.vault.Materialize(r.Context(), sec.Name)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Cannot materialize secret", err.Error())
		return
	}
	for _, f := range files {
		if f.Name == file {
			s.vault.AuditWithIP(r.Context(), currentUser(r).Username, "secret.download", sec.Name, "file="+file, s.clientIP(r))
			sendFile(w, downloadFileName(sec.Name, file), "application/octet-stream", f.Data)
			return
		}
	}
	s.renderError(w, r, http.StatusNotFound, "File not found",
		fmt.Sprintf("Secret %q has no file named %q.", sec.Name, file))
}

//
// ---------- helpers ----------
//

// parseLabelsForm turns a "key=value, key2=value2" form field into a map,
// the web-form counterpart to the CLI's repeatable --label flag.
func parseLabelsForm(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || strings.TrimSpace(k) == "" {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// labelsToForm is parseLabelsForm's inverse, for pre-filling the edit form.
func labelsToForm(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ", ")
}

// downloadFileName builds the Content-Disposition file name for one
// materialized file. A kv/file secret only ever has one file ("value"),
// so the secret's own name is enough; a certificate secret has three
// (tls.crt/tls.key/ca.crt), which share extensions across each other (two
// end in ".crt"), so those need the file's own stem folded in too or two of
// the three downloads would collide on the same file name.
func downloadFileName(secretName, file string) string {
	base := safeFileName(secretName)
	ext := ""
	stem := file
	if i := strings.LastIndex(file, "."); i >= 0 {
		ext, stem = file[i:], file[:i]
	}
	if stem == "" || stem == "value" {
		return base + ext
	}
	return base + "-" + stem + ext
}
