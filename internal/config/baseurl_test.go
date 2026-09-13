package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestNormalizeBaseURLRejectsWhatURLParseAccepts pins the specific laxness
// this helper exists for. net/url.Parse returns a nil error for every input
// in the reject list below - "ca.example.com" becomes a *path*, and
// "ca.example.com:8080" becomes a *scheme* - so the `url.Parse(base)` check
// this replaced passed them straight through into config.
func TestNormalizeBaseURLRejectsWhatURLParseAccepts(t *testing.T) {
	reject := []struct {
		in   string
		want string // substring of the expected message
	}{
		// The value that was actually live in production, and the reason
		// cert-manager could never talk to goca's ACME endpoint.
		{"ca.example.com", "missing a scheme"},
		{"ca.example.com:8080", "missing a scheme"},
		{"//ca.example.com", "missing a scheme"},
		{"ftp://ca.example.com", "only http and https"},
		{"https://", "missing a host"},
		{"https://ca.example.com?a=b", "query string or fragment"},
		{"https://ca.example.com#frag", "query string or fragment"},
		{"", "must not be empty"},
		{"   ", "must not be empty"},
	}
	for _, tc := range reject {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NormalizeBaseURL(tc.in)
			if err == nil {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want an error", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NormalizeBaseURL(%q) error = %q, want it to mention %q", tc.in, err, tc.want)
			}
		})
	}
}

func TestNormalizeBaseURLAcceptsAndTrims(t *testing.T) {
	accept := map[string]string{
		"https://ca.example.com":       "https://ca.example.com",
		"https://ca.example.com/":      "https://ca.example.com",
		"https://ca.example.com///":    "https://ca.example.com",
		"http://localhost:8080":        "http://localhost:8080",
		"  https://ca.example.com  ":   "https://ca.example.com",
		"https://ca.example.com:8443":  "https://ca.example.com:8443",
		"https://ca.example.com/goca/": "https://ca.example.com/goca",
	}
	for in, want := range accept {
		t.Run(in, func(t *testing.T) {
			got, err := NormalizeBaseURL(in)
			if err != nil {
				t.Fatalf("NormalizeBaseURL(%q): %v", in, err)
			}
			if got != want {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// validatableConfig is the smallest config Validate accepts, so each test
// below isolates base_url rather than tripping over an unrelated field.
func validatableConfig(t *testing.T) *Config {
	t.Helper()
	c := Default()
	c.DataDir = t.TempDir()
	c.DBPath = filepath.Join(c.DataDir, "goca.db")
	if err := c.GenerateSecrets(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateRejectsSchemelessBaseURL(t *testing.T) {
	c := validatableConfig(t)
	c.Server.BaseURL = "ca.example.com"

	err := c.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error for a scheme-less server.base_url")
	}
	// The operator has to be able to act on this without reading the source.
	for _, want := range []string{"server.base_url", "ca.example.com", "https://ca.example.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q, want it to mention %q", err, want)
		}
	}
}

func TestValidateNormalizesBaseURLInPlace(t *testing.T) {
	c := validatableConfig(t)
	c.Server.BaseURL = "https://ca.example.com/"

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	if c.Server.BaseURL != "https://ca.example.com" {
		t.Fatalf("base_url = %q, want the trailing slash trimmed", c.Server.BaseURL)
	}
}

// An empty base_url stays legal: installs that never serve ACME, OIDC or a
// public CRL have no use for one, and every consumer already guards on "".
func TestValidateAllowsEmptyBaseURL(t *testing.T) {
	c := validatableConfig(t)
	c.Server.BaseURL = ""

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() with an empty base_url: %v", err)
	}
	if c.Server.BaseURL != "" {
		t.Fatalf("base_url = %q, want it left empty", c.Server.BaseURL)
	}
}

// The OIDC redirect URL is derived from base_url by concatenation, so a bad
// base_url would otherwise be baked into it too.
func TestValidateDerivesOIDCRedirectFromAValidatedBaseURL(t *testing.T) {
	c := validatableConfig(t)
	c.Server.BaseURL = "https://ca.example.com/"
	c.Auth.OIDC.Enabled = true
	c.Auth.OIDC.RedirectURL = ""
	c.Auth.Mode = AuthModeLocal

	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	want := "https://ca.example.com/auth/oidc/callback"
	if c.Auth.OIDC.RedirectURL != want {
		t.Fatalf("oidc redirect = %q, want %q", c.Auth.OIDC.RedirectURL, want)
	}
}
