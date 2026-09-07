package web

import (
	"encoding/base64"
	"net/http"
	"unicode/utf8"

	"github.com/mevijays/goca/internal/vault"
)

// This file implements the External Secrets Operator (ESO)-facing side of the
// secret manager: GET /api/v1/eso/secret. It reuses exactly the same
// authentication (apiAuthK8s, internal/k8sauth) and authorization
// (vault.MatchesBinding) as the CSI-facing /api/v1/vault/fetch in
// api_vault_fetch.go - a binding scoped to (namespace, ServiceAccount,
// auth method) authorizes both consumption paths identically. What differs
// is the caller's identity model, and it is a real, not cosmetic,
// difference: CSI's caller is a kubelet-minted, pod-bound, single-use token
// forwarded by a provider running in the same cluster; ESO's webhook
// provider has no equivalent (see docs/eso.md) - it authenticates with
// whatever static bearer token a SecretStore was given, so the verified
// identity here reflects "this SecretStore's ServiceAccount", not any
// particular pod. Correct namespace isolation therefore depends on the
// deployment giving each tenant namespace its own SecretStore and its own
// ServiceAccount, not one shared identity for the whole cluster - see
// docs/eso.md for why, and MatchesBinding still does the same enforcement
// either way, exactly as it does for CSI.
//
// The request shape (query parameters, not a path segment, for the secret
// name) matches how ESO's webhook provider actually builds a request: its
// URL template URL-query-escapes {{ .remoteRef.key }} and
// {{ .remoteRef.property }} before substitution, so a name containing "/"
// (goca secret names commonly look like "team/db-password") arrives here
// pre-escaped in the query string rather than as an extra path segment.

func (s *Server) apiESOFetchSecret(w http.ResponseWriter, r *http.Request) error {
	id := k8sIdentity(r)
	key := r.URL.Query().Get("key")
	if key == "" {
		return badRequest("query parameter %q is required (ESO: template it from {{ .remoteRef.key }})", "key")
	}
	property := r.URL.Query().Get("property")

	sec, err := s.vault.Get(r.Context(), key)
	if err != nil {
		return notFound(errNotFoundOrNotAuthorized)
	}
	bindings, err := s.vault.Bindings(r.Context(), sec.Name)
	if err != nil {
		return badRequest("resolve bindings: %v", err)
	}
	authorized := false
	for _, b := range bindings {
		if vault.MatchesBinding(b, id.Namespace, id.ServiceAccount, id.AuthMethod) {
			authorized = true
			break
		}
	}
	if !authorized {
		// Identical to the "doesn't exist" error, deliberately - see
		// errNotFoundOrNotAuthorized's doc comment in api_vault_fetch.go.
		return notFound(errNotFoundOrNotAuthorized)
	}

	_, files, version, err := s.vault.Materialize(r.Context(), sec.Name)
	if err != nil {
		return badRequest("%v", err)
	}

	var file *vault.File
	switch {
	case property != "":
		for i := range files {
			if files[i].Name == property {
				file = &files[i]
				break
			}
		}
		if file == nil {
			names := make([]string, len(files))
			for i, f := range files {
				names[i] = f.Name
			}
			return badRequest("secret %q has no part named %q; available: %v", key, property, names)
		}
	case len(files) == 1:
		file = &files[0]
	default:
		// A certificate secret with no ?property= is ambiguous - tls.crt,
		// tls.key and ca.crt are three different files, and guessing which
		// one an ExternalSecret wanted would be a worse failure mode than
		// asking for it explicitly.
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.Name
		}
		return badRequest("secret %q has %d parts; add ?property= to select one (e.g. %v)", key, len(files), names)
	}

	s.vault.AuditWithIP(r.Context(), id.String(), "secret.eso_fetch", sec.Name,
		"property="+file.Name+" auth_method="+id.AuthMethod, s.clientIP(r))

	out := map[string]any{
		"name":     sec.Name,
		"property": file.Name,
		"version":  version,
		// value_base64 is always populated and safe for any content. value is
		// only set when the content is valid UTF-8, which every goca secret
		// type in practice is (PEM certificates/keys, kv/file text) - so a
		// SecretStore's result.jsonPath can point at plain $.value for the
		// common case, and $.value_base64 (decoded on the ESO side via
		// decodingStrategy) for anything binary.
		"value_base64": base64.StdEncoding.EncodeToString(file.Data),
	}
	if utf8.Valid(file.Data) {
		out["value"] = string(file.Data)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}
