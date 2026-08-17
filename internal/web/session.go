package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/store"
)

type ctxKey string

const (
	ctxUser  ctxKey = "goca.user"
	ctxToken ctxKey = "goca.token"
)

// Cookie names.
const (
	sessionCookie = "goca_session"
	csrfCookie    = "goca_csrf"
	flashCookie   = "goca_flash"
)

func (s *Server) secureCookies(r *http.Request) bool {
	return s.cfg.Security.SecureCookies || r.TLS != nil ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   s.secureCookies(r),
		SameSite: http.SameSiteLaxMode,
	})
}

//
// ---------- session middleware ----------
//

// requireUser wraps a page handler so only authenticated users reach it.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, token := s.userFromRequest(r)
		if u == nil {
			dest := r.URL.RequestURI()
			http.Redirect(w, r, "/login?next="+url.QueryEscape(dest), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.checkCSRF(r) {
				s.flash(w, r, "error", "Your session token expired. Please try that again.")
				http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxToken, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// optionalUser wraps a page handler that must work for anonymous visitors:
// a valid session is attached to the request context when present, exactly
// like requireUser, but an absent or invalid one does not redirect or block
// - the handler runs either way. Used for pages that are useful without an
// account (the SSL utility) but should still show the logged-in chrome and
// active nav item for a user who reaches them while signed in.
func (s *Server) optionalUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if u, token := s.userFromRequest(r); u != nil {
			ctx = context.WithValue(ctx, ctxUser, u)
			ctx = context.WithValue(ctx, ctxToken, token)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin additionally enforces the admin role.
func (s *Server) requireAdmin(next http.HandlerFunc) http.Handler {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if !u.IsAdmin() {
			s.renderError(w, r, http.StatusForbidden,
				"Administrator access required",
				"This action is restricted to administrators. Ask a CA administrator to grant your account the admin role.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) userFromRequest(r *http.Request) (*store.User, string) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, ""
	}
	u, err := s.auth.UserFromSession(r.Context(), c.Value)
	if err != nil {
		return nil, ""
	}
	return u, c.Value
}

//
// ---------- CSRF (double submit cookie) ----------
//

func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 16 {
		return c.Value
	}
	tok, err := randomURLSafeToken(24)
	if err != nil {
		return ""
	}
	// Readable by JS so the portal's fetch() calls can echo it back.
	s.setCookie(w, r, csrfCookie, tok, 12*3600, false)
	return tok
}

// randomURLSafeToken returns n random bytes, base64url-encoded. Used for
// CSRF tokens and the OIDC login flow's state/nonce values.
func randomURLSafeToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	sent := r.Header.Get("X-CSRF-Token")
	if sent == "" {
		sent = r.FormValue("csrf_token")
	}
	return sent != "" && auth.ConstantTimeEqual(sent, c.Value)
}

//
// ---------- flash messages ----------
//

type flashMessage struct {
	Kind string // success | error | info
	Text string
}

func (s *Server) flash(w http.ResponseWriter, r *http.Request, kind, text string) {
	v := base64.RawURLEncoding.EncodeToString([]byte(kind + "|" + text))
	s.setCookie(w, r, flashCookie, v, 30, true)
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) *flashMessage {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	s.setCookie(w, r, flashCookie, "", -1, true)
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return nil
	}
	return &flashMessage{Kind: parts[0], Text: parts[1]}
}

//
// ---------- login / logout ----------
//

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if u, _ := s.userFromRequest(r); u != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, "", r.URL.Query().Get("next"))
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, "Malformed login form.", "")
		return
	}
	if !s.checkCSRF(r) {
		s.renderLogin(w, r, "Your login form expired. Please try again.", r.FormValue("next"))
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := r.FormValue("next")

	// Throttled on the same counters as the API login endpoint, so an
	// attacker cannot sidestep the limit by switching between the two.
	if wait := s.loginThrottle(username, clientIP(r)); wait > 0 {
		s.svc.AuditWithIP(r.Context(), username, "auth.login_throttled", username, "via=form", clientIP(r))
		s.renderLogin(w, r, fmt.Sprintf(
			"Too many failed sign-in attempts. Please try again in %d seconds.", int(wait.Seconds())+1), next)
		return
	}

	u, err := s.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		s.loginFailed(username, clientIP(r))
		msg := "Invalid username or password."
		switch {
		case errors.Is(err, auth.ErrDisabled):
			msg = "This account is disabled."
		case !errors.Is(err, auth.ErrInvalidCredentials):
			// Surface directory/connection problems: they are operational, not
			// a credential leak.
			msg = "Sign-in failed: " + err.Error()
		}
		s.log.Warn("login failed", "user", username, "remote", clientIP(r), "error", err)
		s.svc.AuditWithIP(r.Context(), username, "auth.login_failed", username, err.Error(), clientIP(r))
		s.renderLogin(w, r, msg, next)
		return
	}
	s.loginSucceeded(username, clientIP(r))

	s.finishLogin(w, r, u, next)
}

// finishLogin creates a session for an already-authenticated user, sets the
// session and CSRF cookies, audits the sign-in, and redirects to next (or /
// when next is empty or not a safe same-site path). Shared by local login
// and the OIDC callback.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, u *store.User, next string) {
	token, _, err := s.auth.CreateSession(r.Context(), u, clientIP(r), r.UserAgent())
	if err != nil {
		s.renderLogin(w, r, "Could not start a session: "+err.Error(), next)
		return
	}
	s.setCookie(w, r, sessionCookie, token, int(s.cfg.Security.SessionTTL.Seconds()), true)
	s.csrfToken(w, r)
	s.svc.AuditWithIP(r.Context(), u.Username, "auth.login", u.Username,
		"source="+u.Source+" role="+u.Role, clientIP(r))
	s.log.Info("login", "user", u.Username, "role", u.Role, "source", u.Source)

	dest := "/"
	if next != "" && strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		dest = next
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if u, _ := s.userFromRequest(r); u != nil {
			s.svc.AuditWithIP(r.Context(), u.Username, "auth.logout", u.Username, "", clientIP(r))
		}
		_ = s.auth.DestroySession(r.Context(), c.Value)
	}
	s.setCookie(w, r, sessionCookie, "", -1, true)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
