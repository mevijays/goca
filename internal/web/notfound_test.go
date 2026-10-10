package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Unknown pages used to get net/http's bare "404 page not found" text with
// none of the portal's styling or navigation, despite an error.html template
// existing for exactly this. The routeMux wrapper that fixes it must not
// also turn net/http's 405 into a 404.
func TestUnknownRoutesGetGocaNotFound(t *testing.T) {
	h := newHarness(t)

	rec := h.do(httptest.NewRequest(http.MethodGet, "/no-such-page", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	if strings.TrimSpace(body) == "404 page not found" || !strings.Contains(body, "Page not found") {
		t.Fatalf("unknown page did not render goca's error page:\n%s", body)
	}
	if !strings.Contains(body, "/static/app.css") {
		t.Fatal("404 page is not using the portal layout")
	}

	rec = h.do(httptest.NewRequest(http.MethodGet, "/api/v1/no-such-thing", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Fatalf("unknown API path: status %d, content-type %q, want a JSON 404", rec.Code, rec.Header().Get("Content-Type"))
	}

	// Wrong method on a real route stays a 405 (and keeps its Allow header).
	rec = h.do(httptest.NewRequest(http.MethodDelete, "/acme/new-order", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: status %d, want 405", rec.Code)
	}
	if rec.Header().Get("Allow") == "" {
		t.Fatal("405 lost its Allow header")
	}
}
