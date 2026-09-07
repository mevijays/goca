package web

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/mevijays/goca/internal/k8sauth"
	"github.com/mevijays/goca/internal/vault"
)

// This file implements the CSI-facing side of the secret manager:
// POST /api/v1/vault/fetch. It is called by `goca run csi-provider` on
// behalf of a specific requesting pod - never directly by that pod - and is
// authenticated by a Kubernetes ServiceAccount token (internal/k8sauth)
// instead of a goca session or API token. Authorization is per secret, via
// internal/vault's bindings (vault.MatchesBinding), not by any goca user
// role: this endpoint has no concept of a goca user at all.

// ctxKeyK8sIdentity is the request-context key apiAuthK8s populates.
type ctxKeyK8sIdentity struct{}

// apiAuthK8s authenticates a JSON request by Kubernetes ServiceAccount
// bearer token - the CSI-facing counterpart to apiAuth. The trust domain is
// selected by the X-Goca-Auth-Method header (set by the CSI provider from its
// --auth-method flag); an empty header means "default". The token is verified
// under exactly that domain's Verifier, so a token from one cluster cannot be
// presented against a binding scoped to another.
func (s *Server) apiAuthK8s(h apiHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.k8s == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "the Kubernetes CSI integration is not enabled on this server (no CSI trust domains configured)",
			})
			return
		}
		method := strings.TrimSpace(r.Header.Get("X-Goca-Auth-Method"))
		if method == "" {
			method = "default"
		}
		verifier, ok := s.k8s.Get(method)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "unknown CSI trust domain " + method + ": no such k8s auth method is configured on this server",
			})
			return
		}
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="goca-csi"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "a Kubernetes ServiceAccount bearer token is required",
			})
			return
		}
		token := strings.TrimSpace(authz[len("bearer "):])
		id, err := verifier.Verify(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token rejected: " + err.Error()})
			return
		}
		id.AuthMethod = method

		ctx := context.WithValue(r.Context(), ctxKeyK8sIdentity{}, id)
		if err := h(w, r.WithContext(ctx)); err != nil {
			var ae *apiError
			if errors.As(err, &ae) {
				writeJSON(w, ae.Status, map[string]string{"error": ae.Msg})
				return
			}
			s.log.Error("vault fetch api error", "path", r.URL.Path, "error", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
	})
}

// k8sIdentity retrieves the identity apiAuthK8s verified for this request.
// Only ever nil if called outside a handler wrapped by apiAuthK8s.
func k8sIdentity(r *http.Request) *k8sauth.Identity {
	id, _ := r.Context().Value(ctxKeyK8sIdentity{}).(*k8sauth.Identity)
	return id
}

type vaultFetchRequest struct {
	Secrets []string `json:"secrets"`
}

type vaultFetchFile struct {
	Name       string `json:"name"`
	DataBase64 string `json:"data_base64"`
}

type vaultFetchResult struct {
	SecretName string           `json:"secret_name"`
	Version    string           `json:"version,omitempty"`
	Files      []vaultFetchFile `json:"files,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type vaultFetchResponse struct {
	Identity string             `json:"identity"`
	Results  []vaultFetchResult `json:"results"`
}

// errNotFoundOrNotAuthorized is returned for both "no such secret" and
// "exists but this identity has no binding to it" - deliberately identical,
// so an unauthorized caller cannot use this endpoint to enumerate which
// secret names exist.
const errNotFoundOrNotAuthorized = "not found or not authorized"

// apiVaultFetch materializes every requested secret the caller's verified
// (namespace, ServiceAccount) is bound to. One request can name several
// secrets - a single CSI Mount call often does - and a failure on one
// secret does not affect the others; internal/csi.Provider decides whether
// any per-item error should fail the whole Mount.
func (s *Server) apiVaultFetch(w http.ResponseWriter, r *http.Request) error {
	id := k8sIdentity(r)
	var in vaultFetchRequest
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	if len(in.Secrets) == 0 {
		return badRequest("secrets must list at least one secret name")
	}

	out := vaultFetchResponse{Identity: id.String(), Results: make([]vaultFetchResult, 0, len(in.Secrets))}
	for _, name := range in.Secrets {
		out.Results = append(out.Results, s.fetchOneVaultSecret(r, id, name))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) fetchOneVaultSecret(r *http.Request, id *k8sauth.Identity, name string) vaultFetchResult {
	sec, err := s.vault.Get(r.Context(), name)
	if err != nil {
		return vaultFetchResult{SecretName: name, Error: errNotFoundOrNotAuthorized}
	}
	bindings, err := s.vault.Bindings(r.Context(), sec.Name)
	if err != nil {
		return vaultFetchResult{SecretName: name, Error: "internal error resolving bindings"}
	}
	authorized := false
	for _, b := range bindings {
		if vault.MatchesBinding(b, id.Namespace, id.ServiceAccount, id.AuthMethod) {
			authorized = true
			break
		}
	}
	if !authorized {
		return vaultFetchResult{SecretName: name, Error: errNotFoundOrNotAuthorized}
	}

	_, files, version, err := s.vault.Materialize(r.Context(), sec.Name)
	if err != nil {
		return vaultFetchResult{SecretName: name, Error: err.Error()}
	}
	s.vault.AuditWithIP(r.Context(), id.String(), "secret.csi_fetch", sec.Name,
		"pod="+id.PodName+" auth_method="+id.AuthMethod, s.clientIP(r))

	files64 := make([]vaultFetchFile, len(files))
	for i, f := range files {
		files64[i] = vaultFetchFile{Name: f.Name, DataBase64: base64.StdEncoding.EncodeToString(f.Data)}
	}
	return vaultFetchResult{SecretName: name, Version: version, Files: files64}
}
