package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// openapiSpec is the API reference served at /settings/api-docs, rendered
// with the Swagger UI assets embedded under static/swagger.
//
//go:embed openapi.yaml
var openapiSpec []byte

// templates holds one parsed template set per page.
type templates struct {
	pages map[string]*template.Template
}

// assetVersions maps each embedded static file to a short hash of its
// content, so asset URLs change exactly when the file does.
var assetVersions = func() map[string]string {
	out := map[string]string{}
	_ = fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[strings.TrimPrefix(p, "static/")] = hex.EncodeToString(sum[:6])
		return nil
	})
	return out
}()

// assetURL returns a cache-busting URL for an embedded static file.
//
// Static files used to be linked as plain /static/app.js with an hour of
// caching, so after every upgrade browsers kept running the previous
// release's app.js and app.css against the new release's templates for up
// to an hour. That is not cosmetic here: confirmations and form toggles live
// in app.js, so new markup paired with an old script silently loses them.
func assetURL(name string) string {
	if v, ok := assetVersions[name]; ok {
		return "/static/" + name + "?v=" + v
	}
	return "/static/" + name
}

var funcMap = template.FuncMap{
	"asset": assetURL,
	"fmtTime": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"fmtDate": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("2006-01-02")
	},
	"fmtTimePtr": func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04")
	},
	"since": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			return fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	},
	"join":     strings.Join,
	"lower":    strings.ToLower,
	"contains": strings.Contains,
	"truncate": func(n int, s string) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"seq": func(from, to int) []int {
		var out []int
		for i := from; i <= to; i++ {
			out = append(out, i)
		}
		return out
	},
	"keyTypes": func() []pki.KeyType { return pki.KeyTypes },
	"profiles": func() []pki.Profile { return pki.Profiles },
	"profileDesc": func(p pki.Profile) string {
		return pki.ProfileDescriptions[p]
	},
	"reasonName": pki.ReasonName,
	"reasonCodes": func() []int {
		return []int{pki.ReasonUnspecified, pki.ReasonKeyCompromise, pki.ReasonCACompromise,
			pki.ReasonAffiliationChanged, pki.ReasonSuperseded, pki.ReasonCessationOfOperation,
			pki.ReasonCertificateHold, pki.ReasonPrivilegeWithdrawn}
	},
	"statusClass": func(status string) string {
		switch status {
		case store.StatusActive:
			return "ok"
		case store.StatusRevoked:
			return "danger"
		case store.StatusExpired:
			return "warn"
		default:
			return "muted"
		}
	},
	"expiryClass": func(days int) string {
		switch {
		case days < 0:
			return "danger"
		case days <= 14:
			return "danger"
		case days <= 30:
			return "warn"
		default:
			return "ok"
		}
	},
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			key, ok := kv[i].(string)
			if !ok {
				continue
			}
			m[key] = kv[i+1]
		}
		return m
	},
	"pct": func(part, total int) int {
		if total == 0 {
			return 0
		}
		return part * 100 / total
	},
}

func loadTemplates() (*templates, error) {
	entries, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	t := &templates{pages: map[string]*template.Template{}}
	for _, e := range entries {
		name := strings.TrimPrefix(e, "templates/")
		if name == "layout.html" {
			continue
		}
		tpl, err := template.New("layout.html").Funcs(funcMap).
			ParseFS(templateFS, "templates/layout.html", e)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		t.pages[name] = tpl
	}
	if len(t.pages) == 0 {
		return nil, fmt.Errorf("no templates were embedded")
	}
	return t, nil
}

// viewData is the root object every page template receives.
type viewData struct {
	Title    string
	Nav      string
	User     *store.User
	Flash    *flashMessage
	CSRF     string
	Version  string
	BaseURL  string
	AuthMode string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, vd viewData) {
	tpl, ok := s.tpl.pages[page]
	if !ok {
		s.log.Error("unknown template", "page", page)
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	vd.User = currentUser(r)
	if vd.Flash == nil {
		vd.Flash = s.takeFlash(w, r)
	}
	vd.CSRF = s.csrfToken(w, r)
	vd.Version = Version
	vd.BaseURL = s.cfg.Server.BaseURL
	vd.AuthMode = string(s.cfg.Auth.Mode)
	if vd.Title == "" {
		vd.Title = "goca"
	}

	// Render to a buffer so a template error cannot produce a half-written page.
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layout.html", vd); err != nil {
		s.log.Error("render failed", "page", page, "error", err)
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, errMsg, next string) {
	tpl, ok := s.tpl.pages["login.html"]
	if !ok {
		http.Error(w, "login template missing", http.StatusInternalServerError)
		return
	}
	vd := viewData{
		Title:    "Sign in",
		CSRF:     s.csrfToken(w, r),
		Version:  Version,
		AuthMode: string(s.cfg.Auth.Mode),
		Data: map[string]any{
			"Error":        errMsg,
			"Next":         next,
			"LDAP":         s.auth.LDAPEnabled(),
			"Local":        s.auth.LocalEnabled(),
			"OIDC":         s.auth.OIDCEnabled(),
			"OIDCLoginURL": oidcLoginURL(next),
			"AuthMode":     string(s.cfg.Auth.Mode),
			"ServerName":   s.cfg.Server.BaseURL,
		},
	}
	var buf bytes.Buffer
	if err := tpl.ExecuteTemplate(&buf, "layout.html", vd); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, code int, title, detail string) {
	if isAPI(r) {
		writeJSON(w, code, map[string]string{"error": title, "detail": detail})
		return
	}
	w.WriteHeader(code)
	s.render(w, r, "error.html", viewData{
		Title: title,
		Data:  map[string]any{"Code": code, "Title": title, "Detail": detail},
	})
}

// noStore marks a response as never to be cached or kept in the back/forward
// cache - for pages that reveal a secret exactly once.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// staticHandler serves the embedded CSS/JS with long-lived caching.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") != "" {
			// A versioned URL's content can never change (see assetURL).
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		fileServer.ServeHTTP(w, r)
	}))
}
