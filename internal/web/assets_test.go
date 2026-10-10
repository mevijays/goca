package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every static asset a template links must go through {{asset ...}}: an
// unversioned /static/ URL is cached for an hour, so after an upgrade the
// browser pairs the new templates with the previous release's app.js - and
// the confirmations and toggles that live in app.js silently stop working.
func TestTemplatesLinkStaticAssetsThroughAsset(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("templates", "*.html"))
	raw := regexp.MustCompile(`(src|href)="/static/`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if raw.MatchString(line) {
				t.Errorf(`%s:%d links a static file without {{asset "..."}}: %s`, f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestAssetURLsAreVersionedAndServed(t *testing.T) {
	h := newHarness(t)
	u := assetURL("app.js")
	if !regexp.MustCompile(`^/static/app\.js\?v=[0-9a-f]{12}$`).MatchString(u) {
		t.Fatalf("assetURL(app.js) = %q, want a content-hash version", u)
	}
	rec := h.do(httptest.NewRequest(http.MethodGet, u, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data-confirm") {
		t.Fatalf("versioned app.js not served: %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("versioned asset Cache-Control = %q, want immutable", cc)
	}
	// And the login page actually uses it.
	page := h.do(httptest.NewRequest(http.MethodGet, "/login", nil)).Body.String()
	if !strings.Contains(page, u) {
		t.Fatalf("login page does not reference %s", u)
	}
}
