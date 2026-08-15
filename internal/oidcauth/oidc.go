// Package oidcauth authenticates portal users against any standards-compliant
// OpenID Connect provider - Dex, Keycloak, Okta, Google, Azure Entra ID, or
// anything else that publishes OIDC discovery - and maps its claims onto
// goca's user and role model, mirroring internal/ldapauth.
package oidcauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mevijays/goca/internal/config"
)

// ErrNotAllowed is returned when a user authenticates but is not a member of
// any group listed in allowed_groups.
var ErrNotAllowed = errors.New("account is not a member of any permitted group")

// Identity is what a successful callback yields.
type Identity struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
	IsAdmin     bool
}

// Client talks to a configured OIDC provider. Building one (New) never
// touches the network - provider discovery happens lazily on first use (see
// ready), so an unreachable issuer never blocks unrelated CLI commands or
// `goca run web` startup, only an actual sign-in attempt.
type Client struct {
	cfg          config.OIDCConfig
	clientSecret string
	httpClient   *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// New builds a client. clientSecret is the already-decrypted OAuth2 client
// secret.
func New(cfg config.OIDCConfig, clientSecret string) *Client {
	httpClient := http.DefaultClient
	if cfg.InsecureSkipVerify {
		httpClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // opt-in, lab use only
		}
	}
	return &Client{cfg: cfg, clientSecret: clientSecret, httpClient: httpClient}
}

// Enabled reports whether OIDC is configured.
func (c *Client) Enabled() bool { return c != nil && c.cfg.Enabled && c.cfg.IssuerURL != "" }

// ready performs OIDC discovery (fetching <issuer>/.well-known/openid-configuration
// and its signing keys) on first use, and retries it on every call while it
// keeps failing - a provider that was briefly unreachable self-heals on the
// next sign-in attempt instead of staying broken until goca restarts.
func (c *Client) ready(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return nil
	}
	dctx := oidc.ClientContext(ctx, c.httpClient)
	provider, err := oidc.NewProvider(dctx, c.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("discover OIDC issuer %s: %w", c.cfg.IssuerURL, err)
	}
	c.provider = provider
	c.oauth2 = oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.clientSecret,
		RedirectURL:  c.cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopesOrDefault(c.cfg.Scopes),
	}
	c.verifier = provider.Verifier(&oidc.Config{ClientID: c.cfg.ClientID})
	return nil
}

func scopesOrDefault(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{oidc.ScopeOpenID, "profile", "email"}
	}
	for _, s := range scopes {
		if s == oidc.ScopeOpenID {
			return scopes
		}
	}
	// Every OIDC request requires it; add it rather than fail on an operator
	// omission that every other scope config wouldn't need to think about.
	return append([]string{oidc.ScopeOpenID}, scopes...)
}

// AuthCodeURL builds the URL that starts a login: the browser is redirected
// here. state and nonce should be freshly random per attempt and verified
// again in Exchange.
func (c *Client) AuthCodeURL(ctx context.Context, state, nonce string) (string, error) {
	if err := c.ready(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	cfg := c.oauth2
	c.mu.Unlock()
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce)), nil
}

// Exchange completes the callback: swaps the authorization code for tokens,
// verifies the ID token's signature, issuer, audience and nonce, and maps its
// claims (supplemented by the userinfo endpoint for anything missing) onto an
// Identity.
func (c *Client) Exchange(ctx context.Context, code, wantNonce string) (*Identity, error) {
	if err := c.ready(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	cfg := c.oauth2
	verifier := c.verifier
	provider := c.provider
	c.mu.Unlock()

	ctx = oidc.ClientContext(ctx, c.httpClient)
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("the provider's token response had no id_token")
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}
	if idToken.Nonce != wantNonce {
		return nil, errors.New("ID token nonce does not match this login attempt")
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode ID token claims: %w", err)
	}
	// Some providers only expose group membership (or other claims) from
	// userinfo, not the ID token itself; fill in anything the ID token didn't
	// already have. A userinfo failure is not fatal - the ID token alone is a
	// complete, valid identity per the OIDC core spec.
	if userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
		extra := map[string]any{}
		if err := userInfo.Claims(&extra); err == nil {
			for k, v := range extra {
				if _, exists := claims[k]; !exists {
					claims[k] = v
				}
			}
		}
	}

	id := &Identity{
		Username:    firstNonEmptyClaim(claims, firstNonEmpty(c.cfg.ClaimUsername, "preferred_username"), "email", "sub"),
		DisplayName: stringClaim(claims, firstNonEmpty(c.cfg.ClaimDisplayName, "name")),
		Email:       stringClaim(claims, firstNonEmpty(c.cfg.ClaimEmail, "email")),
		Groups:      stringSliceClaim(claims, firstNonEmpty(c.cfg.ClaimGroups, "groups")),
	}
	if id.Username == "" {
		return nil, errors.New("no usable username claim in the ID token or userinfo response")
	}
	id.IsAdmin = matchesAny(id.Groups, c.cfg.AdminGroups)
	if len(c.cfg.AllowedGroups) > 0 && !matchesAny(id.Groups, c.cfg.AllowedGroups) {
		return nil, ErrNotAllowed
	}
	return id, nil
}

func stringClaim(claims map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if s, ok := claims[key].(string); ok {
		return s
	}
	return ""
}

// stringSliceClaim reads a claim that may be a JSON array of strings (the
// common case for a groups claim) or, from providers that emit a single
// membership as a bare string, just a string.
func stringSliceClaim(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		return []string{v}
	}
	return nil
}

func firstNonEmptyClaim(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := stringClaim(claims, k); s != "" {
			return s
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// matchesAny reports whether any of have and want share a value, compared
// case-insensitively. Groups claims are flat strings (unlike LDAP's DNs), so
// unlike ldapauth's equivalent this needs no DN/CN normalisation.
func matchesAny(have, want []string) bool {
	if len(have) == 0 || len(want) == 0 {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, w := range want {
		if set[strings.ToLower(strings.TrimSpace(w))] {
			return true
		}
	}
	return false
}
