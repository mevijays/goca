package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The portal's Content-Security-Policy is script-src 'self', which blocks
// inline event handlers and javascript: URLs outright - not with an error the
// user sees, but by silently not running them. Two shipped that way: the
// confirmation before downloading a CA private key in cleartext (so the key
// downloaded with no warning), and the toggle that reveals the certificate
// picker when creating a certificate-type secret (so that secret type could
// not be created from the portal at all). Both now go through static/app.js
// (data-confirm, data-show-when); this keeps any new one from shipping.
var inlineScript = regexp.MustCompile(`(?i)(\son[a-z]+\s*=|javascript:|<script(\s[^>]*)?>[^<\s])`)

func TestTemplatesHaveNoInlineScript(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no templates found - is the test running from internal/web?")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if m := inlineScript.FindString(line); m != "" {
				t.Errorf("%s:%d: %q is blocked by the CSP (script-src 'self') and will silently never run; "+
					"use data-confirm / data-show-when in static/app.js instead:\n    %s",
					f, i+1, strings.TrimSpace(m), strings.TrimSpace(line))
			}
		}
	}
}

// Doc links in the portal used to point at repo-root files (ACME-EAB.md,
// SECRETS.md, USAGE.md) that moved into docs/ when the mkdocs site was set
// up, so every one of them was a GitHub 404. Resolve each docs-site link
// against docs/ so a moved or renamed page fails here, not for a user.
func TestTemplateDocLinksResolve(t *testing.T) {
	const site = "https://mevijays.github.io/goca/"
	files, _ := filepath.Glob(filepath.Join("templates", "*.html"))
	link := regexp.MustCompile(`href="(https://[^"]*mevijays[^"]*)"`)
	found := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAllStringSubmatch(string(b), -1) {
			u := m[1]
			if !strings.HasPrefix(u, site) {
				t.Errorf("%s links %s; link the docs site (%s...) so the target is checkable", f, u, site)
				continue
			}
			page := strings.Trim(strings.TrimPrefix(u, site), "/")
			if page == "" {
				page = "index"
			}
			if _, err := os.Stat(filepath.Join("..", "..", "docs", page+".md")); err != nil {
				t.Errorf("%s links %s, but docs/%s.md does not exist", f, u, page)
			}
			found++
		}
	}
	if found == 0 {
		t.Fatal("no docs links found; the pattern is probably wrong")
	}
}
