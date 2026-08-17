package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/store"
)

// POST /api/v1/auth/login exchanges a username and password for an API token.
//
// It exists to break a bootstrap deadlock: every other /api/v1 endpoint needs
// a bearer token, and the endpoint that mints tokens is itself one of them, so
// before this the only ways to obtain a token were `goca token create` on the
// server host or a browser session. Neither is available to someone
// administering the server remotely, which is what gocactl does.
//
// This is the one authenticated-by-password endpoint in the API, so it is also
// the one that needs throttling - see ratelimit.go.

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// TokenName labels the minted token so it is identifiable in
	// `goca token list`; gocactl sends "gocactl@<hostname>".
	TokenName string `json:"token_name"`
	// Days requests a lifetime. Omitted or zero means the server's default;
	// it can never mean "never expires" - see apiAuthLogin.
	Days int `json:"days"`
}

type loginResponse struct {
	Token         string      `json:"token"`
	TokenID       int64       `json:"token_id"`
	TokenName     string      `json:"token_name"`
	ExpiresAt     *time.Time  `json:"expires_at"`
	Role          string      `json:"role"`
	User          *store.User `json:"user"`
	ServerVersion string      `json:"server_version"`
}

// maxTokenNameLen bounds a caller-supplied token name so it stays readable in
// `goca token list` and cannot be used to bloat the database.
const maxTokenNameLen = 64

func (s *Server) apiAuthLogin(w http.ResponseWriter, r *http.Request) error {
	var in loginRequest
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	username := strings.TrimSpace(in.Username)
	ip := clientIP(r)

	if username == "" || in.Password == "" {
		return &apiError{Status: http.StatusBadRequest, Msg: "username and password are required"}
	}
	if !s.auth.LocalEnabled() && !s.auth.LDAPEnabled() {
		// An OIDC-only server has no password to check. Say so plainly rather
		// than returning a misleading "invalid credentials".
		return &apiError{Status: http.StatusBadRequest, Msg: "password login is disabled on this server; " +
			"sign in to the portal with SSO and create an API token under Settings instead"}
	}

	if wait := s.loginThrottle(username, ip); wait > 0 {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprint(secs))
		s.svc.AuditWithIP(r.Context(), username, "auth.login_throttled", username, "via=api", ip)
		return &apiError{Status: http.StatusTooManyRequests,
			Msg: fmt.Sprintf("too many failed sign-in attempts; try again in %ds", secs)}
	}

	ttl, err := s.loginTokenTTL(in.Days)
	if err != nil {
		return err
	}

	u, err := s.auth.Authenticate(r.Context(), username, in.Password)
	if err != nil {
		s.loginFailed(username, ip)
		s.log.Warn("api login failed", "user", username, "remote", ip, "error", err)
		s.svc.AuditWithIP(r.Context(), username, "auth.login_failed", username, "via=api "+err.Error(), ip)
		switch {
		case errors.Is(err, auth.ErrDisabled):
			return &apiError{Status: http.StatusForbidden, Msg: "this account is disabled"}
		case errors.Is(err, auth.ErrInvalidCredentials):
			// Deliberately identical for an unknown user and a wrong
			// password, so the endpoint cannot be used to enumerate accounts.
			return &apiError{Status: http.StatusUnauthorized, Msg: "invalid username or password"}
		default:
			// A directory that is down is an operational fault, not a
			// statement about the credential.
			return &apiError{Status: http.StatusBadGateway, Msg: "the directory could not be reached", Err: err}
		}
	}
	s.loginSucceeded(username, ip)

	name := strings.TrimSpace(in.TokenName)
	if name == "" {
		name = "gocactl login"
	}
	if len(name) > maxTokenNameLen {
		name = name[:maxTokenNameLen]
	}

	plaintext, rec, err := s.auth.IssueAPIToken(r.Context(), u, name, u.Role, ttl)
	if err != nil {
		return err
	}

	s.svc.AuditWithIP(r.Context(), u.Username, "auth.login", u.Username,
		"via=api source="+u.Source+" role="+u.Role, ip)
	s.svc.AuditWithIP(r.Context(), u.Username, "token.create", rec.Name,
		"role="+rec.Role+" via=login", ip)

	writeJSON(w, http.StatusOK, loginResponse{
		Token:         plaintext,
		TokenID:       rec.ID,
		TokenName:     rec.Name,
		ExpiresAt:     rec.ExpiresAt,
		Role:          rec.Role,
		User:          u,
		ServerVersion: Version,
	})
	return nil
}

// loginTokenTTL turns a requested lifetime in days into a duration, and is the
// single place that guarantees a password grant can never mint a non-expiring
// token. auth.IssueAPIToken treats a zero TTL as "never expires", so this must
// never return zero.
func (s *Server) loginTokenTTL(days int) (time.Duration, error) {
	if days < 0 {
		return 0, &apiError{Status: http.StatusBadRequest, Msg: "days cannot be negative"}
	}
	maxDays := s.cfg.Security.APILoginTokenMaxDays
	if days == 0 {
		ttl := s.cfg.Security.APILoginTokenTTL
		if ttl <= 0 {
			ttl = 30 * 24 * time.Hour // belt and braces; Validate() defaults this
		}
		return ttl, nil
	}
	if maxDays > 0 && days > maxDays {
		return 0, &apiError{Status: http.StatusBadRequest,
			Msg: fmt.Sprintf("days is %d, which exceeds this server's maximum of %d", days, maxDays)}
	}
	return time.Duration(days) * 24 * time.Hour, nil
}
