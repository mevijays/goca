package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// apiHandler is a handler that can return an error, which the wrapper renders
// as a JSON problem response.
type apiHandler func(w http.ResponseWriter, r *http.Request) error

// apiError carries an HTTP status alongside a message.
type apiError struct {
	Status int
	Msg    string
	Err    error
}

func (e *apiError) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func badRequest(format string, args ...any) *apiError {
	return &apiError{Status: http.StatusBadRequest, Msg: fmt.Sprintf(format, args...)}
}

func notFound(msg string) *apiError {
	return &apiError{Status: http.StatusNotFound, Msg: msg}
}

func forbidden(msg string) *apiError {
	return &apiError{Status: http.StatusForbidden, Msg: msg}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// apiAuth authenticates a JSON request by bearer token or portal session.
func (s *Server) apiAuth(h apiHandler, adminOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u *store.User
		// Kept so apiMe can describe the credential itself, not just its
		// owner - a remote client needs the token's expiry and its (possibly
		// lower) capped role, neither of which is visible on the user.
		var tok *store.APIToken

		if authz := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			token := strings.TrimSpace(authz[7:])
			user, rec, err := s.auth.UserFromAPIToken(r.Context(), token)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "invalid or expired API token"})
				return
			}
			u, tok = user, rec
		} else if user, _ := s.userFromRequest(r); user != nil {
			// Session-authenticated calls from the portal's own JavaScript must
			// carry the CSRF token, or a third-party page could drive the API.
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.checkCSRF(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing or invalid CSRF token"})
				return
			}
			u = user
		}

		if u == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="goca"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required: send an Authorization: Bearer <token> header"})
			return
		}
		if adminOnly && !u.IsAdmin() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator role required"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxUser, u)
		if tok != nil {
			ctx = context.WithValue(ctx, ctxToken, tok)
		}
		if err := h(w, r.WithContext(ctx)); err != nil {
			s.renderAPIError(w, r, err)
		}
	})
}

// renderAPIError writes a handler's error as a JSON problem response. Split
// out of apiAuth so unauthenticated JSON endpoints (apiPublic) render errors
// identically without inheriting a credential check.
func (s *Server) renderAPIError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		body := map[string]string{"error": ae.Msg}
		if ae.Err != nil {
			body["detail"] = ae.Err.Error()
		}
		writeJSON(w, ae.Status, body)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.log.Error("api error", "path", r.URL.Path, "error", err)
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

// apiPublic wraps a handler that performs its own authentication, or needs
// none. It shares apiAuth's JSON error rendering but applies no credential
// check of its own, so it must only ever be used for endpoints that are
// deliberately reachable unauthenticated - today just POST /api/v1/auth/login,
// which *is* the credential check and is the bootstrap for the rest of the API.
func (s *Server) apiPublic(h apiHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			s.renderAPIError(w, r, err)
		}
	})
}

// currentToken returns the API token this request authenticated with, or nil
// for a session-authenticated (browser) call.
func currentToken(r *http.Request) *store.APIToken {
	tok, _ := r.Context().Value(ctxToken).(*store.APIToken)
	return tok
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return badRequest("invalid JSON body: %v", err)
	}
	return nil
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, badRequest("%q is not a valid id", r.PathValue("id"))
	}
	return id, nil
}

// The {id} path segment accepts a human reference as well as a numeric id, so
// the API takes the same arguments an operator types at the CLI - `acme-root-ca`
// rather than `3`. Certificates have always worked this way via
// FindCertificate; these bring CAs, secrets and users into line.
//
// A numeric id is always tried first, so an all-digit slug or username can
// never shadow a real id.

// pathCA resolves {id} to a CA by numeric id, slug or name.
func (s *Server) pathCA(r *http.Request) (*store.CA, error) {
	ref := r.PathValue("id")
	if ref == "" {
		return nil, badRequest("a certificate authority id, slug or name is required")
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		if c, err := s.svc.GetCA(r.Context(), id); err == nil {
			return c, nil
		}
	}
	return s.svc.ResolveCA(r.Context(), ref)
}

// pathCAID is pathCA for handlers that only need the id.
func (s *Server) pathCAID(r *http.Request) (int64, error) {
	c, err := s.pathCA(r)
	if err != nil {
		return 0, err
	}
	return c.ID, nil
}

// pathUser resolves {id} to a user by numeric id or username.
func (s *Server) pathUser(r *http.Request) (*store.User, error) {
	ref := r.PathValue("id")
	if ref == "" {
		return nil, badRequest("a user id or username is required")
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		if u, err := s.svc.Store().GetUser(r.Context(), id); err == nil {
			return u, nil
		}
	}
	return s.svc.Store().GetUserByName(r.Context(), ref)
}

//
// ---------- identity & stats ----------
//

// apiMe describes the caller. The "auth" block describes the *credential*
// rather than its owner, which a remote client needs and cannot infer: an API
// token's own role caps the effective role (a user-role token owned by an
// admin acts as a user), and only the token carries an expiry.
func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) error {
	u := currentUser(r)
	authInfo := map[string]any{"method": "session", "role": u.Role, "account_role": u.Role}
	if tok := currentToken(r); tok != nil {
		authInfo = map[string]any{
			"method":     "token",
			"token_id":   tok.ID,
			"token_name": tok.Name,
			"role":       tok.Role,
			"expires_at": tok.ExpiresAt,
		}
		// UserFromAPIToken caps the returned user's role at the token's role, so
		// the embedded user reports "user" even for an administrator holding a
		// scoped token. That is the right answer for "what may I do", but it
		// leaves no way to tell a limited account from a limited credential --
		// so report the stored role too, and let the caller say which is which.
		authInfo["account_role"] = u.Role
		if stored, err := s.svc.Store().GetUser(r.Context(), u.ID); err == nil && stored != nil {
			authInfo["account_role"] = stored.Role
		}
	}
	writeJSON(w, http.StatusOK, meResponse{User: u, Auth: authInfo})
	return nil
}

// meResponse embeds the user so existing consumers see an unchanged shape,
// with the auth block added alongside.
type meResponse struct {
	*store.User
	Auth map[string]any `json:"auth"`
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) error {
	st, err := s.svc.Store().Stats(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, st)
	return nil
}

//
// ---------- CAs ----------
//

// caResponse is the JSON view of a CA, including its PEM certificate.
type caResponse struct {
	*store.CA
	CertPEM string        `json:"cert_pem"`
	Info    *pki.CertInfo `json:"info,omitempty"`

	// Computed views an API client cannot derive for itself. store.CA's
	// HasKey/CanIssue/Kind all read KeyEnc, which is json:"-" because it is
	// the encrypted signing key and must never be served. Without these an
	// API consumer sees no key field at all and can only conclude that every
	// authority is a keyless trust anchor. (store.Certificate does not have
	// this problem - its HasKey is a real serialized field.)
	HasKey   bool   `json:"has_key"`
	CanIssue bool   `json:"can_issue"`
	Kind     string `json:"kind"`
	Origin   string `json:"origin"`
	Expired  bool   `json:"expired"`
	DaysLeft int    `json:"days_left"`
}

// newCAResponse builds the JSON view of a CA. Every caResponse is constructed
// here so the computed fields above cannot silently go missing from one
// endpoint - which is exactly how they came to be missing in the first place.
func newCAResponse(c *store.CA, info *pki.CertInfo) caResponse {
	return caResponse{
		CA:       c,
		CertPEM:  c.CertPEM,
		Info:     info,
		HasKey:   c.HasKey(),
		CanIssue: c.CanIssue(),
		Kind:     c.Kind(),
		Origin:   c.Origin(),
		Expired:  c.Expired(),
		DaysLeft: c.DaysLeft(),
	}
}

func (s *Server) apiCAList(w http.ResponseWriter, r *http.Request) error {
	cas, err := s.svc.ListCAs(r.Context())
	if err != nil {
		return err
	}
	out := make([]caResponse, 0, len(cas))
	for _, c := range cas {
		out = append(out, newCAResponse(c, nil))
	}
	writeJSON(w, http.StatusOK, map[string]any{"cas": out, "count": len(out)})
	return nil
}

func (s *Server) apiCAGet(w http.ResponseWriter, r *http.Request) error {
	c, err := s.pathCA(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, newCAResponse(c, describeOrNil(c.CertPEM)))
	return nil
}

func (s *Server) apiCACreate(w http.ResponseWriter, r *http.Request) error {
	var in ca.CreateCAInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	c, err := s.svc.CreateCA(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusCreated, newCAResponse(c, describeOrNil(c.CertPEM)))
	return nil
}

func (s *Server) apiCADelete(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	if err := s.svc.DeleteCA(r.Context(), id, currentUser(r).Username); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiCASetDefault(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	if err := s.svc.SetDefaultCA(r.Context(), id, currentUser(r).Username); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "default"})
	return nil
}

func (s *Server) apiCASetStatus(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if err := s.svc.SetCAStatus(r.Context(), id, body.Status, currentUser(r).Username); err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Status})
	return nil
}

func (s *Server) apiCAGenerateCRL(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	_, pemBytes, err := s.svc.GenerateCRL(r.Context(), id, currentUser(r).Username)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"crl_pem": string(pemBytes)})
	return nil
}

func (s *Server) apiCADownload(w http.ResponseWriter, r *http.Request) error {
	id, err := s.pathCAID(r)
	if err != nil {
		return err
	}
	c, err := s.svc.GetCA(r.Context(), id)
	if err != nil {
		return err
	}
	file := r.PathValue("file")
	if (file == "ca.key" || file == "key.pem") && !currentUser(r).IsAdmin() {
		return forbidden("only administrators may download a CA private key")
	}
	if !s.serveCADownload(w, r, c, file, currentUser(r).IsAdmin()) {
		return notFound(fmt.Sprintf("unknown file %q; try ca.crt, ca.pem, ca.der, ca.key, chain.pem, crl.pem, crl.crl or bundle.zip", file))
	}
	return nil
}

//
// ---------- certificates ----------
//

type certResponse struct {
	*store.Certificate
	CertPEM string        `json:"cert_pem"`
	SANs    []string      `json:"sans"`
	Info    *pki.CertInfo `json:"info,omitempty"`
}

func (s *Server) apiCertList(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 50)
	if limit > 500 {
		limit = 500
	}
	filter := store.CertFilter{
		Query:      strings.TrimSpace(q.Get("q")),
		CAID:       int64(atoiDefault(q.Get("ca"), 0)),
		Status:     q.Get("status"),
		Profile:    q.Get("profile"),
		ExpiringIn: atoiDefault(q.Get("expiring"), 0),
		Limit:      limit,
		Offset:     atoiDefault(q.Get("offset"), 0),
		SortBy:     q.Get("sort"),
		SortDesc:   q.Get("order") != "asc",
	}
	if !currentUser(r).IsAdmin() {
		filter.RequestedBy = currentUser(r).Username
	} else if v := q.Get("requested_by"); v != "" {
		filter.RequestedBy = v
	}

	certs, total, err := s.svc.Search(r.Context(), filter)
	if err != nil {
		return err
	}
	out := make([]certResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, certResponse{Certificate: c, CertPEM: c.CertPEM, SANs: c.SANs()})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"certificates": out,
		"total":        total,
		"limit":        filter.Limit,
		"offset":       filter.Offset,
	})
	return nil
}

func (s *Server) apiCertGet(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, certResponse{
		Certificate: c, CertPEM: c.CertPEM, SANs: c.SANs(), Info: describeOrNil(c.CertPEM),
	})
	return nil
}

// apiCertIssue signs a certificate. The response includes the private key when
// goca generated it, since that is the caller's only chance to receive it if
// storage was disabled.
func (s *Server) apiCertIssue(w http.ResponseWriter, r *http.Request) error {
	var in ca.IssueInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Actor = currentUser(r).Username
	res, err := s.svc.Issue(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"certificate":     certResponse{Certificate: res.Certificate, CertPEM: res.Certificate.CertPEM, SANs: res.Certificate.SANs()},
		"private_key_pem": res.PrivateKeyPEM,
		"csr_pem":         res.CSRPEM,
		"chain_pem":       res.ChainPEM,
		"key_stored":      res.Certificate.HasKey,
	})
	return nil
}

func (s *Server) apiCertRevoke(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	var body struct {
		Reason any `json:"reason"`
	}
	// A body is optional; an absent one means "unspecified".
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			return err
		}
	}
	code := pki.ReasonUnspecified
	switch v := body.Reason.(type) {
	case float64:
		code = int(v)
	case string:
		parsed, err := pki.ParseReason(v)
		if err != nil {
			return badRequestFrom(err)
		}
		code = parsed
	}
	if err := s.svc.Revoke(r.Context(), c.ID, code, currentUser(r).Username); err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revoked", "reason": pki.ReasonName(code), "reason_code": code,
	})
	return nil
}

func (s *Server) apiCertDelete(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	c, err := s.svc.GetCertificate(r.Context(), id)
	if err != nil {
		return err
	}
	if err := s.svc.Store().DeleteCertificate(r.Context(), id); err != nil {
		return err
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "cert.delete", c.CommonName,
		"serial="+c.SerialHex, s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiCertDownload(w http.ResponseWriter, r *http.Request) error {
	c, err := s.apiLookupCert(r)
	if err != nil {
		return err
	}
	file := r.PathValue("file")
	if !s.serveCertDownload(w, r, c, file) {
		return notFound(fmt.Sprintf("unknown file %q; try cert.pem, cert.der, key.pem, chain.pem, "+
			"fullchain.pem, request.csr, bundle.p12 or bundle.zip", file))
	}
	return nil
}

func (s *Server) apiLookupCert(r *http.Request) (*store.Certificate, error) {
	ref := r.PathValue("id")
	c, err := s.svc.FindCertificate(r.Context(), ref)
	if err != nil {
		return nil, notFound(fmt.Sprintf("no certificate with id or serial %q", ref))
	}
	u := currentUser(r)
	if !u.IsAdmin() && c.RequestedBy != "" && c.RequestedBy != u.Username {
		return nil, forbidden("you can only access certificates you requested")
	}
	return c, nil
}

//
// ---------- CSR tooling ----------
//

func (s *Server) apiGenerateCSR(w http.ResponseWriter, r *http.Request) error {
	var in ca.GenerateCSRInput
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	res, err := s.svc.GenerateCSR(r.Context(), in)
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

// apiInspect parses a PEM certificate or CSR and describes it.
func (s *Server) apiInspect(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		PEM string `json:"pem"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if strings.Contains(body.PEM, "CERTIFICATE REQUEST") {
		csr, err := pki.ParseCSR([]byte(body.PEM))
		if err != nil {
			return badRequestFrom(err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"type": "csr", "csr": pki.DescribeCSR(csr)})
		return nil
	}
	cert, err := pki.ParseCertPEM([]byte(body.PEM))
	if err != nil {
		return badRequestFrom(err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"type": "certificate", "certificate": pki.Describe(cert)})
	return nil
}

//
// ---------- tokens ----------
//

func (s *Server) apiTokenList(w http.ResponseWriter, r *http.Request) error {
	u := currentUser(r)
	scope := u.ID
	if u.IsAdmin() {
		scope = 0
	}
	tokens, err := s.auth.ListAPITokens(r.Context(), scope)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
	return nil
}

func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
		Days int    `json:"days"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if body.Days < 0 {
		return badRequest("days must be zero (never expires) or positive")
	}
	var ttl time.Duration
	if body.Days > 0 {
		ttl = time.Duration(body.Days) * 24 * time.Hour
	}
	plaintext, rec, err := s.auth.IssueAPIToken(r.Context(), currentUser(r), body.Name, body.Role, ttl)
	if err != nil {
		return badRequestFrom(err)
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "token.create", rec.Name,
		"role="+rec.Role, s.clientIP(r))
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "record": rec})
	return nil
}

func (s *Server) apiTokenRevoke(w http.ResponseWriter, r *http.Request) error {
	id, err := pathID(r)
	if err != nil {
		return err
	}
	u := currentUser(r)
	if !u.IsAdmin() {
		mine, _ := s.auth.ListAPITokens(r.Context(), u.ID)
		owned := false
		for _, t := range mine {
			if t.ID == id {
				owned = true
				break
			}
		}
		if !owned {
			return forbidden("you can only revoke your own tokens")
		}
	}
	if err := s.auth.RevokeAPIToken(r.Context(), id); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	return nil
}

//
// ---------- users & audit ----------
//

func (s *Server) apiUserList(w http.ResponseWriter, r *http.Request) error {
	users, err := s.svc.Store().ListUsers(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
	return nil
}

func (s *Server) apiUserCreate(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	u, err := s.auth.CreateLocalUser(r.Context(), body.Username, body.Password,
		body.DisplayName, body.Email, body.Role)
	if err != nil {
		return badRequestFrom(err)
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.create", u.Username, "role="+u.Role, s.clientIP(r))
	writeJSON(w, http.StatusCreated, u)
	return nil
}

func (s *Server) apiUserPatch(w http.ResponseWriter, r *http.Request) error {
	target, err := s.pathUser(r)
	if err != nil {
		return err
	}
	id := target.ID
	var body struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return err
	}
	if body.Role != nil {
		role := *body.Role
		if role != store.RoleAdmin {
			role = store.RoleUser
		}
		if role == store.RoleUser && s.isLastAdmin(r, target) {
			return badRequest("that is the last administrator; promote someone else first")
		}
		if err := s.svc.Store().SetUserRole(r.Context(), id, role); err != nil {
			return err
		}
	}
	if body.Disabled != nil {
		if *body.Disabled && s.isLastAdmin(r, target) {
			return badRequest("that is the last administrator; it cannot be disabled")
		}
		if err := s.svc.Store().SetUserDisabled(r.Context(), id, *body.Disabled); err != nil {
			return err
		}
		if *body.Disabled {
			_ = s.svc.Store().DeleteUserSessions(r.Context(), id)
		}
	}
	if body.Password != nil {
		if err := s.auth.SetPassword(r.Context(), target, *body.Password); err != nil {
			return badRequestFrom(err)
		}
	}
	updated, err := s.svc.Store().GetUser(r.Context(), id)
	if err != nil {
		return err
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.update", updated.Username, "", s.clientIP(r))
	writeJSON(w, http.StatusOK, updated)
	return nil
}

func (s *Server) apiUserDelete(w http.ResponseWriter, r *http.Request) error {
	target, err := s.pathUser(r)
	if err != nil {
		return err
	}
	id := target.ID
	if s.isLastAdmin(r, target) {
		return badRequest("that is the last administrator; it cannot be deleted")
	}
	if err := s.svc.Store().DeleteUser(r.Context(), id); err != nil {
		return err
	}
	s.svc.AuditWithIP(r.Context(), currentUser(r).Username, "user.delete", target.Username, "", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	return nil
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 100)
	cursor := atoiDefault(q.Get("cursor"), 0)
	entries, err := s.svc.Store().ListAuditPage(r.Context(), int64(cursor), limit)
	if err != nil {
		return err
	}
	// next_cursor is the smallest ID on this page; pass it back to fetch the
	// following (older) page. Empty when the page returned fewer than `limit`
	// rows, i.e. there is no older page.
	nextCursor := ""
	if len(entries) == limit && len(entries) > 0 {
		nextCursor = strconv.FormatInt(entries[len(entries)-1].ID, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "next_cursor": nextCursor})
	return nil
}

func (s *Server) apiLDAPTest(w http.ResponseWriter, r *http.Request) error {
	if !s.auth.LDAPEnabled() {
		return badRequest("LDAP is not enabled in the configuration")
	}
	if err := s.auth.LDAP().TestConnection(r.Context()); err != nil {
		return &apiError{Status: http.StatusBadGateway, Msg: "LDAP test failed", Err: err}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// badRequestFrom preserves an existing apiError, otherwise wraps as 400.
func badRequestFrom(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	return &apiError{Status: http.StatusBadRequest, Msg: err.Error()}
}
