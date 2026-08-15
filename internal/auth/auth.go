// Package auth ties credential verification (local bcrypt or LDAP) to the
// portal's sessions, API tokens and role model.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/ldapauth"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

// ErrInvalidCredentials is returned for any failed login, regardless of cause,
// so the response cannot be used to enumerate accounts.
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrDisabled is returned when a known account has been disabled locally.
var ErrDisabled = errors.New("this account is disabled")

// TokenPrefix marks goca API tokens.
const TokenPrefix = "goca_"

// Manager performs authentication and session/token management.
type Manager struct {
	cfg  *config.Config
	st   *store.Store
	ldap *ldapauth.Client
}

// NewManager wires the auth manager, decrypting the LDAP bind password.
func NewManager(cfg *config.Config, st *store.Store, box *secret.Box) (*Manager, error) {
	m := &Manager{cfg: cfg, st: st}
	if cfg.Auth.LDAP.Enabled {
		pw, err := box.DecryptString(cfg.Auth.LDAP.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("decrypt LDAP bind password: %w", err)
		}
		m.ldap = ldapauth.New(cfg.Auth.LDAP, pw)
	}
	return m, nil
}

// LDAP exposes the directory client (nil when LDAP is disabled).
func (m *Manager) LDAP() *ldapauth.Client { return m.ldap }

// LDAPEnabled reports whether directory login is available.
func (m *Manager) LDAPEnabled() bool { return m.ldap != nil && m.ldap.Enabled() }

// LocalEnabled reports whether local password login is available.
func (m *Manager) LocalEnabled() bool {
	return m.cfg.Auth.Mode == config.AuthModeLocal || m.cfg.Auth.Mode == config.AuthModeBoth
}

// EnsureLocalAdmin mirrors the config's break-glass admin into the database so
// that all authentication can read from a single place.
func (m *Manager) EnsureLocalAdmin(ctx context.Context) error {
	la := m.cfg.Auth.LocalAdmin
	if la.Username == "" || la.PasswordHash == "" {
		return nil
	}
	u, err := m.st.GetUserByName(ctx, la.Username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		_, err = m.st.UpsertUser(ctx, &store.User{
			Username:    la.Username,
			Source:      store.SourceLocal,
			DisplayName: "Local administrator",
			Role:        store.RoleAdmin,
			PassHash:    la.PasswordHash,
		})
		return err
	case err != nil:
		return err
	default:
		// Keep the stored hash in step with the config if an operator edited it.
		if u.PassHash != la.PasswordHash {
			if err := m.st.SetUserPassword(ctx, u.ID, la.PasswordHash); err != nil {
				return err
			}
		}
		if u.Role != store.RoleAdmin {
			return m.st.SetUserRole(ctx, u.ID, store.RoleAdmin)
		}
		return nil
	}
}

// Authenticate verifies credentials against the configured sources and returns
// the (created or refreshed) user record.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*store.User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	// Local first: it is cheap and covers the break-glass admin even when the
	// directory is unreachable.
	if m.LocalEnabled() {
		u, err := m.st.GetUserByName(ctx, username)
		if err == nil && u.Source == store.SourceLocal && u.PassHash != "" {
			if u.Disabled {
				return nil, ErrDisabled
			}
			if bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(password)) == nil {
				_ = m.st.TouchLogin(ctx, u.ID)
				return u, nil
			}
			return nil, ErrInvalidCredentials
		}
	}

	if m.LDAPEnabled() {
		id, err := m.ldap.Authenticate(ctx, username, password)
		if err != nil {
			if errors.Is(err, ldapauth.ErrInvalidCredentials) {
				return nil, ErrInvalidCredentials
			}
			return nil, err
		}
		role := store.RoleUser
		if id.IsAdmin {
			role = store.RoleAdmin
		}
		// A user promoted to admin locally keeps that role even if the
		// directory does not grant it.
		if existing, err := m.st.GetUserByName(ctx, id.Username); err == nil {
			if existing.Disabled {
				return nil, ErrDisabled
			}
			if existing.Role == store.RoleAdmin {
				role = store.RoleAdmin
			}
		}
		u, err := m.st.UpsertUser(ctx, &store.User{
			Username:    id.Username,
			Source:      store.SourceLDAP,
			DisplayName: id.DisplayName,
			Email:       id.Email,
			Role:        role,
		})
		if err != nil {
			return nil, err
		}
		_ = m.st.TouchLogin(ctx, u.ID)
		return u, nil
	}

	return nil, ErrInvalidCredentials
}

//
// ---------- sessions ----------
//

// CreateSession issues a session token for a user.
func (m *Manager) CreateSession(ctx context.Context, u *store.User, ip, ua string) (string, time.Time, error) {
	tok, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(m.cfg.Security.SessionTTL)
	err = m.st.CreateSession(ctx, &store.Session{
		UserID:    u.ID,
		TokenHash: HashToken(tok),
		ExpiresAt: exp,
		IP:        ip,
		UserAgent: ua,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// UserFromSession resolves a session cookie value to a user.
func (m *Manager) UserFromSession(ctx context.Context, token string) (*store.User, error) {
	if token == "" {
		return nil, store.ErrNotFound
	}
	u, err := m.st.SessionUser(ctx, HashToken(token))
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	return u, nil
}

// DestroySession logs a session out.
func (m *Manager) DestroySession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return m.st.DeleteSession(ctx, HashToken(token))
}

//
// ---------- API tokens ----------
//

// IssueAPIToken mints a bearer token. The plaintext is returned once and is
// never recoverable afterwards.
func (m *Manager) IssueAPIToken(ctx context.Context, u *store.User, name, role string, ttl time.Duration) (string, *store.APIToken, error) {
	if strings.TrimSpace(name) == "" {
		return "", nil, errors.New("a token name is required")
	}
	if role == "" {
		role = u.Role
	}
	if role == store.RoleAdmin && !u.IsAdmin() {
		return "", nil, errors.New("only admins can create admin tokens")
	}
	body, err := randomToken(24)
	if err != nil {
		return "", nil, err
	}
	// The prefix is stored in the clear so a token can be identified in the
	// UI without revealing it; hex keeps it a predictable 8 characters.
	prefixBytes := make([]byte, 4)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", nil, err
	}
	prefix := hex.EncodeToString(prefixBytes)
	plaintext := TokenPrefix + prefix + "_" + body

	rec := &store.APIToken{
		UserID:    u.ID,
		Name:      name,
		Prefix:    prefix,
		TokenHash: HashToken(plaintext),
		Role:      role,
	}
	// Only a zero TTL means "never expires". A negative one would otherwise
	// silently produce an immortal token instead of the expiry it asked for.
	if ttl != 0 {
		exp := time.Now().Add(ttl)
		rec.ExpiresAt = &exp
	}
	saved, err := m.st.CreateAPIToken(ctx, rec)
	if err != nil {
		return "", nil, err
	}
	return plaintext, saved, nil
}

// UserFromAPIToken resolves a bearer token to its owner. The token's own role
// caps the effective role, so a user-scoped token cannot act as admin.
func (m *Manager) UserFromAPIToken(ctx context.Context, token string) (*store.User, *store.APIToken, error) {
	token = strings.TrimSpace(token)
	if token == "" || !strings.HasPrefix(token, TokenPrefix) {
		return nil, nil, store.ErrNotFound
	}
	rec, u, err := m.st.LookupAPIToken(ctx, HashToken(token))
	if err != nil {
		return nil, nil, err
	}
	if u.Disabled {
		return nil, nil, ErrDisabled
	}
	effective := *u
	if rec.Role != store.RoleAdmin {
		effective.Role = rec.Role
	}
	return &effective, rec, nil
}

// ListAPITokens returns tokens, optionally scoped to one user.
func (m *Manager) ListAPITokens(ctx context.Context, userID int64) ([]*store.APIToken, error) {
	return m.st.ListAPITokens(ctx, userID)
}

// RevokeAPIToken disables a token.
func (m *Manager) RevokeAPIToken(ctx context.Context, id int64) error {
	return m.st.RevokeAPIToken(ctx, id)
}

//
// ---------- local users ----------
//

// CreateLocalUser adds a password-authenticated account.
func (m *Manager) CreateLocalUser(ctx context.Context, username, password, displayName, email, role string) (*store.User, error) {
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username is required")
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	if _, err := m.st.GetUserByName(ctx, username); err == nil {
		return nil, fmt.Errorf("user %q already exists", username)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	if role != store.RoleAdmin {
		role = store.RoleUser
	}
	return m.st.UpsertUser(ctx, &store.User{
		Username:    username,
		Source:      store.SourceLocal,
		DisplayName: displayName,
		Email:       email,
		Role:        role,
		PassHash:    hash,
	})
}

// SetPassword changes a local account's password.
func (m *Manager) SetPassword(ctx context.Context, u *store.User, password string) error {
	if u.Source != store.SourceLocal {
		return errors.New("passwords for directory accounts are managed in LDAP")
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := m.st.SetUserPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	// Keep the break-glass admin usable after a password change by writing
	// the new hash back to the config file.
	if strings.EqualFold(u.Username, m.cfg.Auth.LocalAdmin.Username) && m.cfg.Path != "" {
		m.cfg.Auth.LocalAdmin.PasswordHash = hash
		if err := m.cfg.Save(m.cfg.Path); err != nil {
			return fmt.Errorf("password changed, but writing %s failed: %w", m.cfg.Path, err)
		}
	}
	return nil
}

//
// ---------- helpers ----------
//

// HashPassword produces a bcrypt hash.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword verifies a bcrypt hash.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ValidatePassword enforces the minimum password policy.
func ValidatePassword(p string) error {
	if len(p) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if len(p) > 200 {
		return errors.New("password must be at most 200 characters")
	}
	return nil
}

// HashToken hashes a session or API token for storage.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking timing information.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GeneratePassword returns a random password for unattended setup.
func GeneratePassword(n int) (string, error) {
	if n < 12 {
		n = 12
	}
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^*-_=+"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out), nil
}
