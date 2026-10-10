package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mevijays/goca/internal/acme"
)

// Show-once secrets used to travel through URLs: creating an API token in the
// portal redirected to /settings?token=<plaintext>, creating an EAB credential
// to /settings/acme?key_id=...&secret=<HMAC key>, and the PKCS#12 export form
// was method="get", so its password became ?password=... . goca's own request
// log records only the path, but reverse-proxy access logs and browser
// history record full URLs - so each was a working credential sitting in a
// log. These pin the fixed behaviour: the secret is rendered into the POST's
// own response, uncached, and never appears in a Location header.

func (h *harness) postForm(path string, cookies []*http.Cookie, csrf string, form url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	form.Set("csrf_token", csrf)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return h.do(req)
}

func assertRevealedInBody(t *testing.T, rec *httptest.ResponseRecorder, secret string) {
	t.Helper()
	if loc := rec.Header().Get("Location"); loc != "" {
		if strings.Contains(loc, secret) || strings.Contains(loc, url.QueryEscape(secret)) {
			t.Fatalf("the secret is in the redirect URL: %s", loc)
		}
		t.Fatalf("expected the secret to be rendered directly, got a redirect to %s", loc)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the one-time secret is not shown on the page")
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store on a page that reveals a secret", cc)
	}
}

func TestPortalTokenCreateKeepsTokenOutOfURL(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()
	rec := h.postForm("/settings/tokens", cookies, csrf, url.Values{"name": {"ci"}, "role": {"admin"}, "days": {"30"}})

	// The plaintext is the "goca_..." string on the page; find it, then check
	// it is a working token and that it was not routed through a URL.
	tok := regexp.MustCompile(`goca_[A-Za-z0-9_\-]{20,}`).FindString(rec.Body.String())
	if tok == "" {
		t.Fatalf("no token on the page (status %d, Location %q)", rec.Code, rec.Header().Get("Location"))
	}
	assertRevealedInBody(t, rec, tok)
	if r, _ := h.apiJSON("GET", "/api/v1/me", "", tok); r.Code != http.StatusOK {
		t.Fatalf("the revealed token does not work: %d", r.Code)
	}
}

func TestPortalEABCreateKeepsHMACKeyOutOfURL(t *testing.T) {
	h := newHarness(t)
	cookies, csrf := h.session()
	rec := h.postForm("/settings/acme/eab", cookies, csrf, url.Values{
		"name": {"cluster-a"}, "profile": {"server"}, "allowed_domains": {"*.cluster-a.internal"},
	})
	creds, err := acme.New(h.svc).ListEAB(context.Background())
	if err != nil || len(creds) != 1 {
		t.Fatalf("credential not created (%d, %v); status %d, Location %q", len(creds), err, rec.Code, rec.Header().Get("Location"))
	}
	body := rec.Body.String()
	at := strings.Index(body, creds[0].KeyID)
	if at < 0 {
		t.Fatalf("the new credential is not revealed on the page (status %d, Location %q)",
			rec.Code, rec.Header().Get("Location"))
	}
	// The HMAC key is 32 random bytes, base64url - 43 characters.
	key := regexp.MustCompile(`[A-Za-z0-9_\-]{43}`).FindString(body[at:])
	if key == "" {
		t.Fatal("no HMAC key on the page")
	}
	assertRevealedInBody(t, rec, key)
}

func TestPortalP12FormDoesNotUseGET(t *testing.T) {
	b, err := os.ReadFile("templates/cert_detail.html")
	if err != nil {
		t.Fatal(err)
	}
	form := regexp.MustCompile(`(?s)<form[^>]*bundle\.p12[^>]*>`).FindString(string(b))
	if form == "" {
		t.Fatal("PKCS#12 form not found")
	}
	if !strings.Contains(form, `method="post"`) {
		t.Fatalf("the PKCS#12 form must POST, or its export password lands in the URL: %s", form)
	}
}

func TestPortalP12DownloadByPOST(t *testing.T) {
	h := newHarness(t)
	rec, out := h.apiJSON("POST", "/api/v1/certificates",
		`{"mode":"generate","subject":{"common_name":"p12.internal"},"sans":["p12.internal"],"key_type":"ec-p256"}`,
		h.token("admin"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: %s", rec.Body)
	}
	id := int(out["certificate"].(map[string]any)["id"].(float64))
	cookies, csrf := h.session()
	rec = h.postForm("/certificates/"+strconv.Itoa(id)+"/download/bundle.p12", cookies, csrf, url.Values{"password": {"s3cret-export"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST p12 download: status %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), ".p12") {
		t.Fatalf("not a .p12 download: %v", rec.Header())
	}
}
