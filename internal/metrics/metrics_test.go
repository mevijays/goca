package metrics

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// gather collects every metric family currently observable from the shared
// Registry into a map keyed by full metric name. A CounterVec with no child
// series yet exports nothing, so a test must touch a metric before it appears
// here - which is exactly the behaviour /metrics exhibits.
func gather(t *testing.T) map[string]*dto.MetricFamily {
	t.Helper()
	fams, err := Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(fams))
	for _, f := range fams {
		out[f.GetName()] = f
	}
	return out
}

// touch increments every collector once with a canonical label set so that
// each one has at least one observable series. This mirrors what real traffic
// does and is the precondition for a metric to appear in a Gather().
func touch() {
	CertIssuedTotal.WithLabelValues("ca", "server").Inc()
	CertRevokedTotal.WithLabelValues("superseded").Inc()
	CertSearchTotal.WithLabelValues("active").Inc()
	SecretCreatedTotal.WithLabelValues("kv").Inc()
	SecretReadTotal.WithLabelValues("kv", "success").Inc()
	SecretPutTotal.WithLabelValues("kv").Inc()
	SecretDeletedTotal.Inc()
	OrderTotal.WithLabelValues("valid").Inc()
	AccountTotal.WithLabelValues("valid").Inc()
	ChallengeTotal.WithLabelValues("valid").Inc()
	LoginTotal.WithLabelValues("success").Inc()
	TokenTotal.WithLabelValues("issue").Inc()
	DBQueryErrors.Inc()
}

// allMetricNames is the full set of goca metric names the package must expose.
var allMetricNames = []string{
	"goca_ca_cert_issued_total",
	"goca_ca_cert_revoked_total",
	"goca_ca_cert_search_total",
	"goca_vault_secret_created_total",
	"goca_vault_secret_read_total",
	"goca_vault_secret_put_total",
	"goca_vault_secret_deleted_total",
	"goca_acme_order_total",
	"goca_acme_account_total",
	"goca_acme_challenge_total",
	"goca_auth_login_total",
	"goca_auth_token_total",
	"goca_db_query_errors_total",
}

func TestAllMetricsExposedAfterUse(t *testing.T) {
	touch()
	fams := gather(t)
	for _, name := range allMetricNames {
		if _, ok := fams[name]; !ok {
			t.Errorf("expected metric %q to be exposed after use", name)
		}
	}
}

func TestCertIssuedIncrements(t *testing.T) {
	before := counterValue(t, gather(t), "goca_ca_cert_issued_total")
	CertIssuedTotal.WithLabelValues("uniq-ca", "client").Inc()
	CertIssuedTotal.WithLabelValues("uniq-ca", "client").Inc()
	after := counterValue(t, gather(t), "goca_ca_cert_issued_total")
	if after-before != 2 {
		t.Errorf("expected cert_issued_total to increase by 2, got %v", after-before)
	}
}

// counterValue returns the sum of all sample values for a metric family, or 0
// if the family is absent.
func counterValue(t *testing.T, fams map[string]*dto.MetricFamily, name string) float64 {
	t.Helper()
	f, ok := fams[name]
	if !ok {
		return 0
	}
	var sum float64
	for _, m := range f.GetMetric() {
		if c := m.GetCounter(); c != nil {
			sum += c.GetValue()
		}
	}
	return sum
}

func TestSecretReadPartitionsByResult(t *testing.T) {
	SecretReadTotal.WithLabelValues("file", "success").Inc()
	SecretReadTotal.WithLabelValues("file", "denied").Inc()

	f := gather(t)["goca_vault_secret_read_total"]
	if f == nil {
		t.Fatal("goca_vault_secret_read_total not exposed")
	}
	// The two (type,result) label sets must be distinct series.
	seen := map[string]bool{}
	for _, m := range f.GetMetric() {
		var typ, res string
		for _, lp := range m.GetLabel() {
			switch lp.GetName() {
			case "type":
				typ = lp.GetValue()
			case "result":
				res = lp.GetValue()
			}
		}
		seen[typ+"\x00"+res] = true
	}
	if !seen["file\x00success"] || !seen["file\x00denied"] {
		t.Errorf("expected distinct success/denied series for type=file, got %v", seen)
	}
}

func TestLoginTotalPartitionsByResult(t *testing.T) {
	LoginTotal.WithLabelValues("success").Inc()
	LoginTotal.WithLabelValues("failure").Inc()

	f := gather(t)["goca_auth_login_total"]
	if f == nil {
		t.Fatal("goca_auth_login_total not exposed")
	}
	seen := map[string]bool{}
	for _, m := range f.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "result" {
				seen[lp.GetValue()] = true
			}
		}
	}
	if !seen["success"] || !seen["failure"] {
		t.Errorf("expected success and failure series, got %v", seen)
	}
}

// TestHelpTextPresent ensures every exposed goca metric carries a non-empty
// Help string - a scrape-friendly registry should always document its metrics.
func TestHelpTextPresent(t *testing.T) {
	touch()
	fams := gather(t)
	for name, f := range fams {
		if !strings.HasPrefix(name, "goca_") {
			continue
		}
		if f.GetHelp() == "" {
			t.Errorf("metric %q has empty Help text", name)
		}
	}
}
