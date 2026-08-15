package web

import "net/http"

// This file serves the interactive REST API reference: an embedded OpenAPI
// spec (openapi.yaml, kept in sync by hand with server.go's route table) and
// the Swagger UI assets under static/swagger, all vendored - nothing here
// ever contacts a CDN, matching the portal's own strict Content-Security-
// Policy (script-src 'self').
//
// The page is admin-only, gated the same way as Settings/Audit/ACME: a
// signed-in portal session, not a bearer token. "Try it out" from the page
// itself still needs a bearer token pasted into Swagger UI's Authorize
// dialog for anything beyond a GET, since state-changing session calls also
// require a CSRF header this static page has no way to supply.

func (s *Server) handleAPIDocsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "api_docs.html", viewData{
		Title: "API reference",
		Nav:   "api-docs",
	})
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openapiSpec)
}
