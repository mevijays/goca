// Package web serves the embedded portal and the REST API. Both are backed by
// the same ca.Service the CLI uses, so every capability exists in all three
// interfaces.
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/acme"
	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/k8sauth"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// defaultCSIAudience is used when CSIConfig.Audience is left blank.
const defaultCSIAudience = "goca-csi"

// Server owns the HTTP handlers and their dependencies.
type Server struct {
	svc   *ca.Service
	auth  *auth.Manager
	cfg   *config.Config
	log   *slog.Logger
	tpl   *templates
	acme  *acme.Service
	vault *vault.Service
	// k8s verifies the ServiceAccount tokens a CSI provider forwards on a
	// requesting pod's behalf. nil when CSIConfig.Enabled is false - the
	// vault/fetch handler reports that plainly rather than panicking.
	k8s *k8sauth.Verifier
}

// Options tune the HTTP listener at run time, overriding the config file.
type Options struct {
	Listen  string
	Port    int
	TLSCert string
	TLSKey  string
	Logger  *slog.Logger
}

// NewServer builds a portal server.
func NewServer(svc *ca.Service, mgr *auth.Manager, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	vSvc, err := vault.New(svc.Config(), svc.Store(), svc)
	if err != nil {
		return nil, fmt.Errorf("build vault service: %w", err)
	}
	k8s, err := buildK8sVerifier(svc)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes ServiceAccount token verifier: %w", err)
	}
	return &Server{svc: svc, auth: mgr, cfg: svc.Config(), log: logger, tpl: tpl, acme: acme.New(svc), vault: vSvc, k8s: k8s}, nil
}

// buildK8sVerifier constructs the CSI provider's token verifier from
// CSIConfig, or returns nil when the integration is disabled. The reviewer
// token accepts either an encrypted (enc: prefix) or plaintext value, like
// database.password - see CSIConfig's doc comment.
func buildK8sVerifier(svc *ca.Service) (*k8sauth.Verifier, error) {
	cfg := svc.Config().CSI
	if !cfg.Enabled {
		return nil, nil
	}
	reviewerToken := cfg.ReviewerToken
	if secret.IsEncrypted(reviewerToken) {
		var err error
		reviewerToken, err = svc.Box().DecryptString(reviewerToken)
		if err != nil {
			return nil, fmt.Errorf("decrypt csi.reviewer_token: %w", err)
		}
	}
	audience := cfg.Audience
	if audience == "" {
		audience = defaultCSIAudience
	}
	return k8sauth.New(k8sauth.Config{
		IssuerURL:          cfg.IssuerURL,
		Audience:           audience,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		APIServerURL:       cfg.APIServerURL,
		CACertPEM:          []byte(cfg.CACert),
		ReviewerToken:      reviewerToken,
	})
}

// Handler builds the complete route table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// ---- static assets & public distribution endpoints ----
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	// Anonymous trust-anchor distribution, so machines can fetch the root and
	// CRL without credentials. The file name carries the CA slug plus an
	// extension (acme-root-ca.crt), which ServeMux cannot split for us.
	mux.HandleFunc("GET /public/ca/{file}", s.handlePublicCACert)
	mux.HandleFunc("GET /public/crl/{file}", s.handlePublicCRL)

	// ---- ACME (RFC 8555, EAB-only) ----
	// Unauthenticated at the routing level: every endpoint here authenticates
	// itself via the JWS the ACME protocol carries, not a portal session or
	// bearer token. See internal/acme and ACME-EAB.md.
	mux.HandleFunc("GET /acme/directory", s.handleACMEDirectory)
	mux.HandleFunc("GET /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("HEAD /acme/new-nonce", s.handleACMENewNonce)
	mux.HandleFunc("POST /acme/new-account", s.handleACMENewAccount)
	mux.HandleFunc("POST /acme/account/{id}", s.handleACMEAccount)
	mux.HandleFunc("POST /acme/new-order", s.handleACMENewOrder)
	mux.HandleFunc("POST /acme/order/{id}", s.handleACMEOrder)
	mux.HandleFunc("POST /acme/order/{id}/finalize", s.handleACMEFinalize)
	mux.HandleFunc("POST /acme/authz/{id}", s.handleACMEAuthz)
	mux.HandleFunc("POST /acme/challenge/{id}", s.handleACMEChallenge)
	mux.HandleFunc("POST /acme/cert/{id}", s.handleACMECert)
	mux.HandleFunc("GET /acme/cert/{id}", s.handleACMECert)
	mux.HandleFunc("POST /acme/revoke-cert", s.handleACMERevokeCert)

	// ---- session pages ----
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /logout", s.handleLogout)
	// SSO. Unauthenticated at the routing level, same as /login itself: the
	// state cookie plus the ID token's own signature/nonce are what protect
	// the callback, not a session.
	mux.HandleFunc("GET /auth/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", s.handleOIDCCallback)

	page := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireUser(h)) }
	admin := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAdmin(h)) }

	page("GET /{$}", s.handleDashboard)
	page("GET /cas", s.handleCAList)
	admin("GET /cas/new", s.handleCANewForm)
	admin("POST /cas/new", s.handleCACreate)
	admin("GET /cas/import", s.handleCAImportForm)
	admin("POST /cas/import", s.handleCAImportSubmit)
	page("GET /cas/{id}", s.handleCADetail)
	admin("POST /cas/{id}/import-signed", s.handleCACompleteSigned)
	admin("POST /cas/{id}/revoke", s.handleCARevoke)
	admin("POST /cas/{id}/default", s.handleCASetDefault)
	admin("POST /cas/{id}/status", s.handleCASetStatus)
	admin("POST /cas/{id}/delete", s.handleCADelete)
	admin("POST /cas/{id}/crl", s.handleCAGenerateCRL)
	page("GET /cas/{id}/download/{file}", s.handleCADownload)

	page("GET /certificates", s.handleCertList)
	page("GET /certificates/new", s.handleCertNewForm)
	page("POST /certificates/new", s.handleCertCreate)
	page("POST /certificates/bulk", s.handleCertBulkAction)
	page("GET /certificates/{id}", s.handleCertDetail)
	page("POST /certificates/{id}/revoke", s.handleCertRevoke)
	page("POST /certificates/{id}/renew", s.handleCertRenew)
	page("POST /certificates/{id}/hold", s.handleCertHold)
	page("POST /certificates/{id}/release", s.handleCertRelease)
	page("GET /certificates/{id}/download/{file}", s.handleCertDownload)
	admin("POST /certificates/{id}/delete", s.handleCertDelete)

	page("GET /tools/csr", s.handleCSRToolForm)
	page("POST /tools/csr", s.handleCSRToolSubmit)

	// The SSL utility works for anonymous visitors on purpose (see
	// handleSSLToolSubmit): it never touches the database, so there's no
	// account to require. optionalUser still attaches a session when one
	// exists, so a signed-in user reaching it via the nav tab keeps the
	// normal portal chrome.
	mux.Handle("GET /tools/ssl", s.optionalUser(s.handleSSLToolForm))
	mux.Handle("POST /tools/ssl", s.optionalUser(s.handleSSLToolSubmit))

	page("GET /settings", s.handleSettings)
	page("POST /settings/password", s.handleChangePassword)
	page("POST /settings/tokens", s.handleTokenCreate)
	page("POST /settings/tokens/{id}/revoke", s.handleTokenRevoke)
	admin("POST /settings/users", s.handleUserCreate)
	admin("POST /settings/users/{id}/role", s.handleUserRole)
	admin("POST /settings/users/{id}/disable", s.handleUserDisable)
	admin("POST /settings/users/{id}/delete", s.handleUserDelete)
	admin("POST /settings/ldap/test", s.handleLDAPTest)
	admin("GET /audit", s.handleAuditPage)

	admin("GET /settings/acme", s.handleACMESettings)
	admin("POST /settings/acme/eab", s.handleACMEEABCreate)
	admin("POST /settings/acme/eab/{id}/disable", s.handleACMEEABDisable)
	admin("POST /settings/acme/eab/{id}/delete", s.handleACMEEABDelete)

	admin("GET /settings/api-docs", s.handleAPIDocsPage)
	admin("GET /settings/api-docs/openapi.yaml", s.handleOpenAPISpec)

	// ---- secret manager (portal pages; REST API is under /api/v1/secrets*, below) ----
	admin("GET /secrets", s.handleSecretsList)
	admin("POST /secrets", s.handleSecretCreate)
	admin("GET /secrets/{id}", s.handleSecretDetail)
	admin("POST /secrets/{id}/meta", s.handleSecretUpdateMeta)
	admin("POST /secrets/{id}/disable", s.handleSecretDisable)
	admin("POST /secrets/{id}/delete", s.handleSecretDelete)
	admin("POST /secrets/{id}/versions", s.handleSecretVersionPut)
	admin("POST /secrets/{id}/versions/{version}/destroy", s.handleSecretVersionDestroy)
	admin("POST /secrets/{id}/bindings", s.handleSecretBindingCreate)
	admin("POST /secrets/{id}/bindings/{bindingID}/delete", s.handleSecretBindingDelete)
	admin("GET /secrets/{id}/download/{file}", s.handleSecretDownload)

	// ---- REST API ----
	api := func(pattern string, h apiHandler) { mux.Handle(pattern, s.apiAuth(h, false)) }
	apiAdmin := func(pattern string, h apiHandler) { mux.Handle(pattern, s.apiAuth(h, true)) }

	api("GET /api/v1/me", s.apiMe)
	api("GET /api/v1/stats", s.apiStats)

	api("GET /api/v1/cas", s.apiCAList)
	apiAdmin("POST /api/v1/cas", s.apiCACreate)
	api("GET /api/v1/cas/{id}", s.apiCAGet)
	apiAdmin("DELETE /api/v1/cas/{id}", s.apiCADelete)
	apiAdmin("POST /api/v1/cas/{id}/default", s.apiCASetDefault)
	apiAdmin("POST /api/v1/cas/{id}/status", s.apiCASetStatus)
	apiAdmin("POST /api/v1/cas/{id}/crl", s.apiCAGenerateCRL)
	api("GET /api/v1/cas/{id}/download/{file}", s.apiCADownload)

	// Running underneath an external authority (pfSense and the like).
	apiAdmin("POST /api/v1/cas/request", s.apiCASubordinateCSR)
	apiAdmin("POST /api/v1/cas/import", s.apiCAImport)
	apiAdmin("GET /api/v1/cas/pending", s.apiCAPending)
	api("GET /api/v1/cas/{id}/csr", s.apiCACSR)
	apiAdmin("POST /api/v1/cas/{id}/import-signed", s.apiCAImportSigned)
	apiAdmin("POST /api/v1/cas/{id}/revoke", s.apiCARevoke)

	api("GET /api/v1/certificates", s.apiCertList)
	api("POST /api/v1/certificates", s.apiCertIssue)
	api("GET /api/v1/certificates/{id}", s.apiCertGet)
	api("POST /api/v1/certificates/{id}/revoke", s.apiCertRevoke)
	api("GET /api/v1/certificates/{id}/download/{file}", s.apiCertDownload)
	apiAdmin("DELETE /api/v1/certificates/{id}", s.apiCertDelete)

	// Lifecycle: rotation, holds and bulk revocation.
	api("POST /api/v1/certificates/{id}/renew", s.apiCertRenew)
	api("GET /api/v1/certificates/{id}/history", s.apiCertHistory)
	api("POST /api/v1/certificates/{id}/hold", s.apiCertHold)
	api("POST /api/v1/certificates/{id}/release", s.apiCertRelease)
	apiAdmin("POST /api/v1/certificates/renew-expiring", s.apiCertRenewExpiring)
	apiAdmin("POST /api/v1/certificates/bulk-revoke", s.apiCertBulkRevoke)

	api("POST /api/v1/csr", s.apiGenerateCSR)
	api("POST /api/v1/inspect", s.apiInspect)

	api("GET /api/v1/tokens", s.apiTokenList)
	api("POST /api/v1/tokens", s.apiTokenCreate)
	api("DELETE /api/v1/tokens/{id}", s.apiTokenRevoke)

	apiAdmin("GET /api/v1/users", s.apiUserList)
	apiAdmin("POST /api/v1/users", s.apiUserCreate)
	apiAdmin("PATCH /api/v1/users/{id}", s.apiUserPatch)
	apiAdmin("DELETE /api/v1/users/{id}", s.apiUserDelete)
	apiAdmin("GET /api/v1/audit", s.apiAudit)
	apiAdmin("POST /api/v1/ldap/test", s.apiLDAPTest)

	// ACME administration (the protocol itself lives at /acme/*, above).
	apiAdmin("GET /api/v1/acme/eab", s.apiACMEEABList)
	apiAdmin("POST /api/v1/acme/eab", s.apiACMEEABCreate)
	apiAdmin("GET /api/v1/acme/eab/{id}", s.apiACMEEABGet)
	apiAdmin("POST /api/v1/acme/eab/{id}/disable", s.apiACMEEABDisable)
	apiAdmin("DELETE /api/v1/acme/eab/{id}", s.apiACMEEABDelete)
	apiAdmin("GET /api/v1/acme/accounts", s.apiACMEAccountList)
	apiAdmin("GET /api/v1/acme/accounts/{id}", s.apiACMEAccountGet)
	apiAdmin("GET /api/v1/acme/accounts/{id}/orders", s.apiACMEAccountOrders)

	// Secret manager. Admin-only in this phase; a scoped, workload-facing
	// fetch endpoint arrives with the Kubernetes CSI provider in a later
	// phase. See internal/vault and SECRETS.md.
	apiAdmin("GET /api/v1/secrets", s.apiSecretList)
	apiAdmin("POST /api/v1/secrets", s.apiSecretCreate)
	apiAdmin("GET /api/v1/secrets/{id}", s.apiSecretGet)
	apiAdmin("PATCH /api/v1/secrets/{id}", s.apiSecretUpdate)
	apiAdmin("DELETE /api/v1/secrets/{id}", s.apiSecretDelete)
	apiAdmin("POST /api/v1/secrets/{id}/disable", s.apiSecretDisable)
	apiAdmin("GET /api/v1/secrets/{id}/materialize", s.apiSecretMaterialize)
	apiAdmin("GET /api/v1/secrets/{id}/versions", s.apiSecretVersionList)
	apiAdmin("POST /api/v1/secrets/{id}/versions", s.apiSecretVersionPut)
	apiAdmin("GET /api/v1/secrets/{id}/versions/{version}", s.apiSecretVersionGet)
	apiAdmin("POST /api/v1/secrets/{id}/versions/{version}/destroy", s.apiSecretVersionDestroy)
	apiAdmin("GET /api/v1/secrets/{id}/bindings", s.apiSecretBindingList)
	apiAdmin("POST /api/v1/secrets/{id}/bindings", s.apiSecretBindingCreate)
	apiAdmin("DELETE /api/v1/secret-bindings/{id}", s.apiSecretBindingDelete)

	// CSI-facing fetch, authenticated by a Kubernetes ServiceAccount token
	// (internal/k8sauth) rather than a goca session or API token - see
	// api_vault_fetch.go.
	mux.Handle("POST /api/v1/vault/fetch", s.apiAuthK8s(s.apiVaultFetch))

	return s.recoverer(s.logRequests(securityHeaders(mux)))
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context, opts Options) error {
	listen := opts.Listen
	if listen == "" {
		listen = s.cfg.Server.Listen
	}
	port := opts.Port
	if port == 0 {
		port = s.cfg.Server.Port
	}
	addr := net.JoinHostPort(listen, fmt.Sprint(port))

	certFile := firstNonEmpty(opts.TLSCert, s.cfg.Server.TLS.CertFile)
	keyFile := firstNonEmpty(opts.TLSKey, s.cfg.Server.TLS.KeyFile)
	useTLS := (s.cfg.Server.TLS.Enabled || opts.TLSCert != "") && certFile != "" && keyFile != ""

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	if useTLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	if err := s.auth.EnsureLocalAdmin(ctx); err != nil {
		return fmt.Errorf("prepare local admin: %w", err)
	}
	if n, err := s.svc.Store().PurgeExpiredSessions(ctx); err == nil && n > 0 {
		s.log.Debug("purged expired sessions", "count", n)
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	display := listen
	if display == "0.0.0.0" || display == "" || display == "::" {
		display = "localhost"
	}
	s.log.Info("goca web portal listening",
		"url", fmt.Sprintf("%s://%s:%d", scheme, display, port),
		"database", s.cfg.DatabaseSummary(),
		"auth", string(s.cfg.Auth.Mode))

	errCh := make(chan error, 1)
	go func() {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	// Housekeeping: drop expired sessions once an hour.
	go s.sessionJanitor(ctx)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func (s *Server) sessionJanitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.svc.Store().PurgeExpiredSessions(ctx); err == nil && n > 0 {
				s.log.Debug("purged expired sessions", "count", n)
			}
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	n, err := s.svc.Store().CountCAs(r.Context())
	status := "ok"
	code := http.StatusOK
	if err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{
		"status":  status,
		"cas":     n,
		"version": Version,
		"setup":   n > 0,
	})
}

// Version is stamped by the CLI at start-up.
var Version = "dev"

//
// ---------- middleware ----------
//

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		// The portal ships all of its CSS and JS inline from /static; no
		// external origins are ever contacted.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			return
		}
		s.log.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"bytes", rec.bytes, "duration", time.Since(start).Round(time.Millisecond).String(),
			"remote", clientIP(r))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic serving request", "path", r.URL.Path, "panic", rec)
				if isAPI(r) {
					writeJSON(w, http.StatusInternalServerError,
						map[string]string{"error": "internal server error"})
				} else {
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func isAPI(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/") }

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// currentUser is a convenience accessor used by handlers.
func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}
