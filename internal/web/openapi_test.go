package web

import (
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenAPICoversEveryAPIRoute is the actual fix for a spec that had drifted
// out of date: fourteen secret endpoints existed and were documented nowhere.
// Adding the missing paths once only fixes the symptom - this keeps them from
// going missing again, by measuring the real route table rather than a list
// someone has to remember to update.
func TestOpenAPICoversEveryAPIRoute(t *testing.T) {
	h := newHarness(t)

	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapiSpec, &spec); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("openapi.yaml declares no paths")
	}

	// The spec is served under a /api/v1 server URL, so its keys are relative
	// to that. Normalise both sides to a "METHOD /api/v1/..." shape.
	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method := range ops {
			switch strings.ToLower(method) {
			case "get", "post", "put", "patch", "delete", "head", "options":
				documented[strings.ToUpper(method)+" /api/v1"+path] = true
			}
		}
	}

	var missing []string
	for _, pattern := range h.srv.routePatterns() {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || !strings.HasPrefix(path, "/api/v1/") {
			continue // portal pages and the ACME wire protocol are out of scope
		}
		if path == "/api/v1/health" {
			continue // documented separately as the unauthenticated probe
		}
		if !documented[method+" "+normalizeAPIPath(path)] {
			missing = append(missing, pattern)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d API route(s) are registered but absent from internal/web/openapi.yaml:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// normalizeAPIPath rewrites Go's {id} wildcards into the same spelling the
// spec uses, so the two can be compared literally.
func normalizeAPIPath(p string) string {
	// Go 1.22 patterns may carry a trailing "..." on a wildcard.
	p = strings.ReplaceAll(p, "...", "")
	return p
}

// TestOpenAPIDocumentsNoPhantomRoutes is the other direction: a documented
// endpoint that does not exist sends people chasing 404s.
func TestOpenAPIDocumentsNoPhantomRoutes(t *testing.T) {
	h := newHarness(t)

	registered := map[string]bool{}
	for _, pattern := range h.srv.routePatterns() {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			continue
		}
		registered[method+" "+normalizeAPIPath(path)] = true
	}

	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openapiSpec, &spec); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}

	var phantom []string
	for path, ops := range spec.Paths {
		for method := range ops {
			switch strings.ToLower(method) {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			full := strings.ToUpper(method) + " /api/v1" + path
			if !registered[full] {
				phantom = append(phantom, full)
			}
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%d endpoint(s) are documented in openapi.yaml but not registered:\n  %s",
			len(phantom), strings.Join(phantom, "\n  "))
	}
}
