package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/oidcauth"
)

// oidcStateCookie carries the login attempt's CSRF state, the ID token
// nonce, and where to send the browser back to, across the redirect to the
// provider and back. It never leaves the browser<->goca round trip.
const oidcStateCookie = "goca_oidc_state"

type oidcState struct {
	State string `json:"s"`
	Nonce string `json:"n"`
	Next  string `json:"x,omitempty"`
}

// handleOIDCLogin starts a sign-in: mint state/nonce, stash them in a
// short-lived cookie, and redirect the browser to the provider's
// authorization endpoint.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}
	state, err1 := randomURLSafeToken(24)
	nonce, err2 := randomURLSafeToken(24)
	if err1 != nil || err2 != nil {
		s.renderLogin(w, r, "Could not start SSO sign-in.", "")
		return
	}
	next := r.URL.Query().Get("next")
	if next != "" && (!strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//")) {
		next = "" // only ever redirect back into goca itself
	}

	raw, err := json.Marshal(oidcState{State: state, Nonce: nonce, Next: next})
	if err != nil {
		s.renderLogin(w, r, "Could not start SSO sign-in.", "")
		return
	}
	// 10 minutes: long enough for a user to actually authenticate at the
	// provider (MFA, a consent screen, ...), short enough that a stale
	// attempt can't be replayed much later.
	s.setCookie(w, r, oidcStateCookie, base64.RawURLEncoding.EncodeToString(raw), 600, true)

	authURL, err := s.auth.OIDC().AuthCodeURL(r.Context(), state, nonce)
	if err != nil {
		s.log.Error("oidc: build authorization URL", "error", err)
		s.renderLogin(w, r, "Could not reach the SSO provider. Try again shortly, or use another sign-in method.", next)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes a sign-in: verifies the state and ID token,
// provisions/refreshes the local user record from its claims, and starts a
// session exactly like a successful local or LDAP login would.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.auth.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}

	sv, ok := s.takeOIDCState(w, r)
	if !ok {
		s.renderLogin(w, r, "Your sign-in attempt expired or could not be verified. Please try again.", "")
		return
	}

	if provErr := r.URL.Query().Get("error"); provErr != "" {
		desc := firstNonEmpty(r.URL.Query().Get("error_description"), provErr)
		s.log.Warn("oidc: provider returned an error", "error", provErr, "description", desc)
		s.renderLogin(w, r, "Sign-in was cancelled or failed: "+desc, sv.Next)
		return
	}
	gotState := r.URL.Query().Get("state")
	if gotState == "" || !auth.ConstantTimeEqual(gotState, sv.State) {
		s.renderLogin(w, r, "Your sign-in attempt could not be verified. Please try again.", "")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.renderLogin(w, r, "The SSO provider did not return an authorization code.", "")
		return
	}

	id, err := s.auth.OIDC().Exchange(r.Context(), code, sv.Nonce)
	if err != nil {
		msg := "Sign-in failed."
		if errors.Is(err, oidcauth.ErrNotAllowed) {
			msg = "Your account is not a member of any group permitted to sign in here."
		} else {
			s.log.Warn("oidc: callback exchange failed", "error", err)
		}
		s.svc.AuditWithIP(r.Context(), "", "auth.oidc_failed", "", err.Error(), s.clientIP(r))
		s.renderLogin(w, r, msg, "")
		return
	}

	u, err := s.auth.SyncOIDCUser(r.Context(), id)
	if err != nil {
		msg := "Sign-in failed: " + err.Error()
		if errors.Is(err, auth.ErrDisabled) {
			msg = "This account is disabled."
		} else {
			s.log.Error("oidc: provisioning the user failed", "error", err)
		}
		s.renderLogin(w, r, msg, "")
		return
	}

	s.finishLogin(w, r, u, sv.Next)
}

// takeOIDCState reads and clears the state cookie, decoding it if present.
// The cookie is deleted unconditionally so a callback is never replayable,
// successful or not.
func (s *Server) takeOIDCState(w http.ResponseWriter, r *http.Request) (oidcState, bool) {
	c, err := r.Cookie(oidcStateCookie)
	s.setCookie(w, r, oidcStateCookie, "", -1, true)
	if err != nil || c.Value == "" {
		return oidcState{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return oidcState{}, false
	}
	var sv oidcState
	if err := json.Unmarshal(raw, &sv); err != nil || sv.State == "" || sv.Nonce == "" {
		return oidcState{}, false
	}
	return sv, true
}

// oidcLoginURL builds the link the login page's "Sign in with SSO" button
// points at, preserving ?next= so a bookmarked deep link still works after
// SSO.
func oidcLoginURL(next string) string {
	if next == "" {
		return "/auth/oidc/login"
	}
	return "/auth/oidc/login?next=" + url.QueryEscape(next)
}
