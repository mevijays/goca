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
	"github.com/mevijays/goca/internal/metrics"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
	"github.com/mevijays/goca/internal/webhooks"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	// k8s is the registry of named ServiceAccount-token verifiers - one per
	// CSI trust domain (k8s_auth_methods row). nil when no trust domain is
	// configured - the vault/fetch handler reports that plainly rather than
	// panicking. The CSI provider names the trust domain it runs in via the
	// X-Goca-Auth-Method header; see apiAuthK8s.
	k8s *k8sauth.Registry
	// logins throttles the two endpoints that check a password - see
	// ratelimit.go.
	logins *failCounter
	// webhooks delivers signed event notifications for audit actions (G9).
	// It is always non-nil; when no webhook is configured its worker simply
	// finds nothing to do.
	webhooks *webhooks.Dispatcher
	// trustedProxies are the parsed CIDRs from ServerConfig.TrustedProxies.
	// Only a request whose direct peer is in this list may set
	// X-Forwarded-For; see clientIP.
	trustedProxies []*net.IPNet
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
	if err := migrateLegacyCSIToRow(svc); err != nil {
		return nil, fmt.Errorf("migrate legacy CSI config: %w", err)
	}
	k8s, err := buildK8sRegistry(svc)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes ServiceAccount token verifiers: %w", err)
	}
	// G9: wire the webhook dispatcher as the CA service's event sink, so every
	// audit write fans out to matching webhooks. The dispatcher only enqueues
	// durable delivery rows here; a worker in Run performs the HTTP calls.
	dispatcher := webhooks.New(svc.Store(), svc.Box(), logger, webhooks.Options{})
	svc.SetEventSink(dispatcher.Emit)
	s := &Server{svc: svc, auth: mgr, cfg: svc.Config(), log: logger, tpl: tpl, acme: acme.New(svc), vault: vSvc, k8s: k8s, logins: newFailCounter(), webhooks: dispatcher}
	s.trustedProxies = parseTrustedProxies(s.cfg.Server.TrustedProxies)
	s.logSecurityWarnings()
	return s, nil
}

// parseTrustedProxies parses CIDR/IP strings into networks. A bare IP is
// treated as a /32 (or /128). Entries that do not parse are skipped with a
// warning rather than failing startup - a typo in one proxy address should
// not take the whole portal down, and Validate already rejects them when the
// config is loaded through the normal path.
func parseTrustedProxies(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, e := range entries {
		ipnet, err := parseCIDROrIP(e)
		if err != nil {
			slog.Default().Warn("skipping unparseable server.trusted_proxies entry", "entry", e, "error", err)
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

// parseCIDROrIP parses a CIDR ("10.0.0.0/8") or a bare IP ("192.168.1.10",
// treated as /32 or /128) into an IPNet.
func parseCIDROrIP(s string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet, nil
	}
	trimmed := strings.TrimSpace(s)
	if ip := net.ParseIP(trimmed); ip != nil {
		ones := "32"
		if ip.To4() == nil {
			ones = "128"
		}
		// Re-parse with an explicit prefix so the mask has the correct width
		// for the address family (a bare net.ParseIP is 16 bytes, which would
		// make a /32 mask an IPv6-space mask).
		_, ipnet, err := net.ParseCIDR(trimmed + "/" + ones)
		return ipnet, err
	}
	return nil, fmt.Errorf("not a valid CIDR or IP")
}

// logSecurityWarnings surfaces the settings that weaken goca's security
// posture at startup, so they are visible in the service log instead of
// buried in the config file.
func (s *Server) logSecurityWarnings() {
	if s.cfg.Auth.LDAP.InsecureSkipVerify {
		s.log.Warn("auth.ldap.insecure_skip_verify is true: LDAP server certificates are not verified")
	}
	if s.cfg.Auth.OIDC.InsecureSkipVerify {
		s.log.Warn("auth.oidc.insecure_skip_verify is true: OIDC provider TLS certificates are not verified")
	}
	if s.cfg.CSI.Enabled && s.cfg.CSI.InsecureSkipVerify {
		s.log.Warn("csi.insecure_skip_verify is true: Kubernetes API server TLS certificates are not verified")
	}
	if len(s.cfg.Server.TrustedProxies) == 0 {
		s.log.Info("server.trusted_proxies is empty: X-Forwarded-For will be ignored and the TCP peer is always the client IP")
	}
}

// buildK8sRegistry builds the registry of named ServiceAccount-token
// verifiers - one per CSI trust domain. It reads every enabled
// k8s_auth_methods row and builds a Verifier from it. If no rows exist but the
// legacy csi.* config is enabled, that config is registered as a "default"
// trust domain so existing deployments keep working (a later migration
// persists it as a real row).
func buildK8sRegistry(svc *ca.Service) (*k8sauth.Registry, error) {
	reg := k8sauth.NewRegistry()
	st := svc.Store()
	rows, err := st.ListK8sAuthMethodsWithToken(context.Background())
	if err != nil {
		return nil, fmt.Errorf("list k8s auth methods: %w", err)
	}
	for _, row := range rows {
		if row.Disabled {
			continue
		}
		v, err := verifierFromRow(svc, row)
		if err != nil {
			return nil, err
		}
		reg.Set(row.Name, v)
	}
	if reg.Len() == 0 {
		v, err := legacyCSIVerifier(svc)
		if err != nil {
			return nil, err
		}
		if v != nil {
			reg.Set("default", v)
		}
	}
	return reg, nil
}

// legacyCSIVerifier returns the Verifier built from the legacy csi.* config
// block, or (nil, nil) when the integration is disabled. It is the
// single-trust-domain fallback used when no k8s_auth_methods rows exist.
func legacyCSIVerifier(svc *ca.Service) (*k8sauth.Verifier, error) {
	if !svc.Config().CSI.Enabled {
		return nil, nil
	}
	return verifierFromLegacyConfig(svc)
}

// migrateLegacyCSIToRow persists the legacy csi.* config block as a real
// "default" k8s_auth_methods row on first start, so the registry becomes
// row-driven and the config block can be retired. It is a no-op when any
// trust-domain rows already exist (the operator has moved to the new model)
// or when the legacy config is disabled / under-configured. The reviewer
// token is encrypted at rest, like every other stored secret.
func migrateLegacyCSIToRow(svc *ca.Service) error {
	cfg := svc.Config().CSI
	if !cfg.Enabled {
		return nil
	}
	st := svc.Store()
	rows, err := st.ListK8sAuthMethods(context.Background())
	if err != nil {
		return fmt.Errorf("list k8s auth methods: %w", err)
	}
	if len(rows) > 0 {
		return nil // already migrated, or the operator created rows manually
	}
	// The legacy config must be complete enough to build a verifier; otherwise
	// buildK8sRegistry will surface the detailed "which keys to set" error.
	if cfg.IssuerURL == "" && cfg.APIServerURL == "" {
		return nil
	}
	if cfg.APIServerURL != "" && cfg.IssuerURL == "" && cfg.ReviewerToken == "" {
		return nil // TokenReview path with no credential; let the verifier error
	}
	audience := cfg.Audience
	if audience == "" {
		audience = defaultCSIAudience
	}
	reviewerTokenEnc := cfg.ReviewerToken
	if reviewerTokenEnc != "" && !secret.IsEncrypted(reviewerTokenEnc) {
		reviewerTokenEnc, err = svc.Box().EncryptString(reviewerTokenEnc)
		if err != nil {
			return fmt.Errorf("encrypt legacy reviewer token: %w", err)
		}
	}
	_, err = st.CreateK8sAuthMethod(context.Background(), &store.K8sAuthMethod{
		Name:               "default",
		Audience:           audience,
		IssuerURL:          cfg.IssuerURL,
		APIServerURL:       cfg.APIServerURL,
		CACert:             cfg.CACert,
		ReviewerTokenEnc:   reviewerTokenEnc,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CreatedBy:          "migration",
	})
	if err != nil {
		return fmt.Errorf("create default trust domain row: %w", err)
	}
	return nil
}

// verifierFromRow builds a Verifier from a stored trust-domain row, decrypting
// its reviewer token first.
func verifierFromRow(svc *ca.Service, row *store.K8sAuthMethod) (*k8sauth.Verifier, error) {
	reviewerToken := row.ReviewerTokenEnc
	if secret.IsEncrypted(reviewerToken) {
		var err error
		reviewerToken, err = svc.Box().DecryptString(reviewerToken)
		if err != nil {
			return nil, fmt.Errorf("decrypt reviewer token for trust domain %q: %w", row.Name, err)
		}
	}
	audience := row.Audience
	if audience == "" {
		audience = defaultCSIAudience
	}
	if row.IssuerURL == "" && row.APIServerURL == "" {
		return nil, fmt.Errorf("trust domain %q has neither issuer_url nor api_server_url set", row.Name)
	}
	if row.IssuerURL == "" && reviewerToken == "" {
		return nil, fmt.Errorf("trust domain %q has api_server_url set but no reviewer token", row.Name)
	}
	return k8sauth.New(k8sauth.Config{
		IssuerURL:          row.IssuerURL,
		Audience:           audience,
		InsecureSkipVerify: row.InsecureSkipVerify,
		APIServerURL:       row.APIServerURL,
		CACertPEM:          []byte(row.CACert),
		ReviewerToken:      reviewerToken,
	})
}

// verifierFromLegacyConfig constructs a Verifier from the legacy csi.* config
// block, or returns an error when the integration is enabled but
// under-configured. The reviewer token accepts either an encrypted (enc:
// prefix) or plaintext value, like database.password - see CSIConfig's doc
// comment.
func verifierFromLegacyConfig(svc *ca.Service) (*k8sauth.Verifier, error) {
	cfg := svc.Config().CSI
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
	// `csi.enabled: true` on its own is the obvious thing to try, and it is not
	// enough: there is no safe default for how ServiceAccount tokens get
	// verified, so one of the two paths has to be chosen deliberately. k8sauth
	// is a generic package and does not know the YAML key names, so name them
	// here rather than leaving the operator to read the source.
	if cfg.IssuerURL == "" {
		switch {
		case cfg.APIServerURL == "":
			return nil, errors.New(
				"csi.enabled is true but no way to verify ServiceAccount tokens is configured. " +
					"Set csi.issuer_url to the cluster's ServiceAccount issuer (EKS/GKE/AKS, or any " +
					"cluster whose issuer is publicly reachable), or csi.api_server_url plus " +
					"csi.reviewer_token and csi.ca_cert to use the TokenReview API instead (kind, " +
					"most on-prem clusters). Find the issuer with: " +
					"kubectl get --raw /.well-known/openid-configuration. " +
					"Full walkthrough: docs/kubernetes/csi.md")
		case reviewerToken == "":
			// Half-configured TokenReview is the easy mistake on the on-prem
			// path, and without this it falls through to a message that does
			// not mention the one key that is actually missing.
			return nil, errors.New(
				"csi.api_server_url is set but csi.reviewer_token is empty, so goca cannot call " +
					"the TokenReview API. The token belongs to a ServiceAccount bound to " +
					"system:auth-delegator; k8s-demo/csi/rbac.yaml creates one. Get it with: " +
					"kubectl create token goca-server-token-reviewer -n goca-csi --duration=8760h. " +
					"Full walkthrough: docs/kubernetes/csi.md")
		}
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

// routeMux is a http.ServeMux that also remembers the patterns registered on
// it. ServeMux itself does not expose them, and the OpenAPI coverage test
// needs the real route table rather than a hand-maintained list that would
// drift out of date exactly as the spec did.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

func (m *routeMux) Handle(pattern string, h http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}

// routePatterns returns every pattern Handler() registers, for tests.
func (s *Server) routePatterns() []string {
	mux := newRouteMux()
	s.routes(mux)
	return mux.patterns
}

// Handler builds the complete route table.
func (s *Server) Handler() http.Handler {
	mux := newRouteMux()
	s.routes(mux)
	return s.recoverer(s.logRequests(securityHeaders(mux)))
}

// routes registers every pattern. Split from Handler so tests can enumerate
// the route table without building the middleware stack.
func (s *Server) routes(mux *routeMux) {

	// ---- static assets & public distribution endpoints ----
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	// Prometheus scrape endpoint. Admin-gated, unlike a typical unauthenticated
	// Prometheus endpoint: unlike most services' metrics, these carry a live
	// goca_auth_login_total{result="success"|"failure"} counter, which is a
	// real side channel (an unauthenticated network caller could watch
	// credential-stuffing attempts land in real time, entirely separate from
	// whatever the login rate limiter itself allows them to observe) plus
	// per-CA issuance and secret counts - not the "no secret material" case
	// an open /metrics endpoint is normally excused on. Point Prometheus's
	// scrape config at it with an admin-role API token
	// (`goca token create prometheus --role admin`) via
	// `authorization: {credentials_file: ...}` in prometheus.yml.
	metricsHandler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
	mux.Handle("GET /metrics", s.apiAuth(func(w http.ResponseWriter, r *http.Request) error {
		metricsHandler.ServeHTTP(w, r)
		return nil
	}, true))
	// Kubernetes-style probes. /livez answers "is the process up" (always 200
	// once the listener is serving) and /readyz answers "can I take traffic"
	// (200 only while the database is reachable). Keeping them separate from
	// /healthz lets a load balancer or k8s liveness probe restart a wedged
	// process without treating a transient DB blip as a crash, and vice versa.
	mux.HandleFunc("GET /livez", s.handleLivez)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	// Unauthenticated by design: this endpoint *is* the credential check, and
	// it is the bootstrap for POST /api/v1/tokens, which is itself behind
	// apiAuth. Registered here, above the api/apiAdmin helpers, so it cannot
	// be mistaken for an authenticated route. Throttled per username and per
	// client address - see ratelimit.go.
	mux.Handle("POST /api/v1/auth/login", s.apiPublic(s.apiAuthLogin))
	// Anonymous trust-anchor distribution, so machines can fetch the root and
	// CRL without credentials. The file name carries the CA slug plus an
	// extension (acme-root-ca.crt), which ServeMux cannot split for us.
	mux.HandleFunc("GET /public/ca/{file}", s.handlePublicCACert)
	mux.HandleFunc("GET /public/crl/{file}", s.handlePublicCRL)

	// ---- ACME (RFC 8555, EAB-only) ----
	// Unauthenticated at the routing level: every endpoint here authenticates
	// itself via the JWS the ACME protocol carries, not a portal session or
	// bearer token. See internal/acme and docs/acme-eab.md.
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
	// phase. See internal/vault and docs/secrets.md.
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

	// CSI trust domains (k8s_auth_methods): the named Kubernetes clusters
	// whose ServiceAccount tokens goca verifies. See api_csi_auth.go.
	apiAdmin("GET /api/v1/csi-auth-methods", s.apiCsiAuthMethodList)
	apiAdmin("POST /api/v1/csi-auth-methods", s.apiCsiAuthMethodCreate)
	apiAdmin("GET /api/v1/csi-auth-methods/{id}", s.apiCsiAuthMethodGet)
	apiAdmin("PATCH /api/v1/csi-auth-methods/{id}", s.apiCsiAuthMethodUpdate)
	apiAdmin("POST /api/v1/csi-auth-methods/{id}/disable", s.apiCsiAuthMethodDisable)
	apiAdmin("DELETE /api/v1/csi-auth-methods/{id}", s.apiCsiAuthMethodDelete)

	// Webhooks (G9): named HTTP endpoints that receive signed event
	// notifications for audit actions. See api_webhooks.go.
	apiAdmin("GET /api/v1/webhooks", s.apiWebhookList)
	apiAdmin("POST /api/v1/webhooks", s.apiWebhookCreate)
	apiAdmin("GET /api/v1/webhooks/{id}", s.apiWebhookGet)
	apiAdmin("PATCH /api/v1/webhooks/{id}", s.apiWebhookUpdate)
	apiAdmin("POST /api/v1/webhooks/{id}/disable", s.apiWebhookDisable)
	apiAdmin("DELETE /api/v1/webhooks/{id}", s.apiWebhookDelete)
	apiAdmin("GET /api/v1/webhooks/{id}/deliveries", s.apiWebhookDeliveries)

	// CSI-facing fetch, authenticated by a Kubernetes ServiceAccount token
	// (internal/k8sauth) rather than a goca session or API token - see
	// api_vault_fetch.go.
	mux.Handle("POST /api/v1/vault/fetch", s.apiAuthK8s(s.apiVaultFetch))

	// External Secrets Operator (ESO)-facing fetch - same auth and
	// authorization as the CSI path above, reshaped for ESO's webhook
	// provider (a GET with query parameters, one secret per request,
	// JSONPath-friendly response). See api_eso.go and docs/eso.md.
	mux.Handle("GET /api/v1/eso/secret", s.apiAuthK8s(s.apiESOFetchSecret))
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

	// G9: deliver queued webhook events.
	go s.webhooks.Run(ctx)

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

// handleLivez reports that the process is up and serving. It deliberately
// does no dependency checks: a liveness probe that fails on a transient DB
// blip would restart a healthy process and make the outage worse.
func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz reports whether the server can accept traffic. It pings the
// database, because every real request needs it; a 503 here tells a load
// balancer or k8s readiness probe to stop sending traffic until the DB
// recovers, without restarting the process.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.svc.Store().Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready: " + err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
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
			"remote", s.clientIP(r))
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

// clientIP determines the real client address for audit records and per-IP
// login throttling.
//
// X-Forwarded-For is only honored when the request's direct peer is one of
// the configured trusted proxies (ServerConfig.TrustedProxies). With no
// trusted proxies configured, or when the peer is not one of them, the header
// is ignored entirely and the TCP peer is the client - a non-trusted peer may
// set X-Forwarded-For to anything, so trusting it would let anyone forge the
// client IP.
//
// When the peer IS a trusted proxy its X-Forwarded-For is credible. The chain
// is "client, proxy1, proxy2, ...": each proxy appends the address it
// received the request from, so the rightmost entry is the hop just before
// this proxy. We walk from the right and return the first entry that is not
// itself a trusted proxy - that is the real client. An attacker who injects a
// fake leftmost entry cannot win, because the walk stops at the rightmost
// non-proxy, which the attacker does not control.
func (s *Server) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if len(s.trustedProxies) == 0 || !s.isTrustedProxy(peer) {
		return peer
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr := strings.TrimSpace(parts[i])
		if addr == "" {
			continue
		}
		if !s.isTrustedProxy(addr) {
			return addr
		}
	}
	// Every entry is a trusted proxy (a chain of proxies with no client
	// recorded); fall back to the direct peer rather than trusting a
	// proxy-supplied address.
	return peer
}

// isTrustedProxy reports whether addr (an IP literal, possibly with a port)
// falls inside one of the configured trusted proxy networks.
func (s *Server) isTrustedProxy(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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
