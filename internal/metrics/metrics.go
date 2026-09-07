// Package metrics provides Prometheus instrumentation for goca's service layer.
//
// All collectors are registered once, at package init, with a single shared
// prometheus.Registry (Registry). Services emit by calling the package-level
// collectors directly, e.g. metrics.CertIssuedTotal.WithLabelValues(ca,
// profile).Inc(). The web server exposes the registry at /metrics via
// promhttp.HandlerFor(metrics.Registry, ...).
//
// Every label is chosen to be low-cardinality (a CA name, a profile, a status,
// a reason) so the metric series set stays bounded no matter how many
// certificates or secrets goca serves.
//
// Metrics emitted:
//
//	goca_ca_cert_issued_total{ca,profile}   — certificates issued
//	goca_ca_cert_revoked_total{reason}      — certificates revoked
//	goca_ca_cert_search_total{status}       — certificate searches
//	goca_vault_secret_created_total{type}   — secrets created
//	goca_vault_secret_read_total{type,result} — secret reads (success/denied)
//	goca_vault_secret_put_total{type}       — secret versions written
//	goca_vault_secret_deleted_total         — secrets deleted
//	goca_acme_order_total{status}           — ACME orders created
//	goca_acme_account_total{status}         — ACME accounts created
//	goca_acme_challenge_total{status}       — ACME challenges
//	goca_auth_login_total{result}           — login attempts (success/failure)
//	goca_auth_token_total{action}           — API token operations
//	goca_db_query_errors_total              — SQL query failures
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is the shared prometheus registry for every goca collector. The
// web server hands it to promhttp.HandlerFor to serve /metrics.
var Registry = prometheus.NewRegistry()

// factory registers new collectors with the shared Registry.
var factory = promauto.With(Registry)

// --- CA metrics ---

// CertIssuedTotal counts certificates issued, partitioned by CA name and
// profile.
var CertIssuedTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "ca",
		Name:      "cert_issued_total",
		Help:      "Total certificates issued, partitioned by CA name and profile.",
	},
	[]string{"ca", "profile"},
)

// CertRevokedTotal counts certificates revoked, partitioned by RFC 5280
// reason.
var CertRevokedTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "ca",
		Name:      "cert_revoked_total",
		Help:      "Total certificates revoked, partitioned by revocation reason.",
	},
	[]string{"reason"},
)

// CertSearchTotal counts certificate searches, partitioned by the status
// filter applied (empty string means "any").
var CertSearchTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "ca",
		Name:      "cert_search_total",
		Help:      "Total certificate searches, partitioned by status filter.",
	},
	[]string{"status"},
)

// --- Vault metrics ---

// SecretCreatedTotal counts secrets created, partitioned by type.
var SecretCreatedTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "vault",
		Name:      "secret_created_total",
		Help:      "Total secrets created, partitioned by type.",
	},
	[]string{"type"},
)

// SecretReadTotal counts secret reads (decryptions), partitioned by type and
// result (success or denied).
var SecretReadTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "vault",
		Name:      "secret_read_total",
		Help:      "Total secret reads, partitioned by type and result.",
	},
	[]string{"type", "result"},
)

// SecretPutTotal counts secret version writes, partitioned by type.
var SecretPutTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "vault",
		Name:      "secret_put_total",
		Help:      "Total secret version writes, partitioned by type.",
	},
	[]string{"type"},
)

// SecretDeletedTotal counts secrets deleted.
var SecretDeletedTotal = factory.NewCounter(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "vault",
		Name:      "secret_deleted_total",
		Help:      "Total secrets deleted.",
	},
)

// --- ACME metrics ---

// OrderTotal counts ACME orders created, partitioned by status.
var OrderTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "acme",
		Name:      "order_total",
		Help:      "Total ACME orders created, partitioned by status.",
	},
	[]string{"status"},
)

// AccountTotal counts ACME accounts created, partitioned by status.
var AccountTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "acme",
		Name:      "account_total",
		Help:      "Total ACME accounts created, partitioned by status.",
	},
	[]string{"status"},
)

// ChallengeTotal counts ACME challenges, partitioned by status.
var ChallengeTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "acme",
		Name:      "challenge_total",
		Help:      "Total ACME challenges, partitioned by status.",
	},
	[]string{"status"},
)

// --- Auth metrics ---

// LoginTotal counts login attempts, partitioned by result (success or
// failure).
var LoginTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "auth",
		Name:      "login_total",
		Help:      "Total login attempts, partitioned by result.",
	},
	[]string{"result"},
)

// TokenTotal counts API token operations, partitioned by action.
var TokenTotal = factory.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "auth",
		Name:      "token_total",
		Help:      "Total API token operations, partitioned by action.",
	},
	[]string{"action"},
)

// --- DB metrics ---

// DBQueryErrors counts SQL query failures.
var DBQueryErrors = factory.NewCounter(
	prometheus.CounterOpts{
		Namespace: "goca",
		Subsystem: "db",
		Name:      "query_errors_total",
		Help:      "Total SQL query errors.",
	},
)
