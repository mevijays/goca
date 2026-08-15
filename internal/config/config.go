// Package config holds the on-disk configuration for goca, produced by
// `goca setup` and consumed by every other sub-command.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvConfigPath overrides config discovery when set.
const EnvConfigPath = "GOCA_CONFIG"

// Config is the complete goca configuration file.
type Config struct {
	// Path is where this config was loaded from. Not serialised.
	Path string `yaml:"-"`

	DataDir  string         `yaml:"data_dir"`
	DBPath   string         `yaml:"db_path"`
	Database DatabaseConfig `yaml:"database"`
	Server   ServerConfig   `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	Auth     AuthConfig     `yaml:"auth"`
	CA       CAConfig       `yaml:"ca"`
}

// DatabaseDriver selects which backend the store package opens.
type DatabaseDriver string

const (
	DBDriverSQLite   DatabaseDriver = "sqlite"
	DBDriverPostgres DatabaseDriver = "postgres"
)

// DatabaseConfig selects and configures the storage backend. The zero value
// means SQLite at DBPath, which keeps every existing config file and test
// working unchanged.
type DatabaseConfig struct {
	Driver DatabaseDriver `yaml:"driver"`

	// PostgreSQL connection details; ignored for the sqlite driver.
	Host     string `yaml:"host,omitempty"`
	Port     int    `yaml:"port,omitempty"`
	Name     string `yaml:"name,omitempty"`
	User     string `yaml:"user,omitempty"`
	Password string `yaml:"password,omitempty"` // encrypted with the master key, like the LDAP bind password
	SSLMode  string `yaml:"sslmode,omitempty"`  // disable|require|verify-ca|verify-full
}

// IsPostgres reports whether the configured backend is PostgreSQL.
func (d DatabaseConfig) IsPostgres() bool { return d.Driver == DBDriverPostgres }

// DatabaseSummary describes the active storage backend for display - the
// SQLite file path, or a PostgreSQL connection summary with the password
// never included.
func (c *Config) DatabaseSummary() string {
	if !c.Database.IsPostgres() {
		return c.DBPath
	}
	d := c.Database
	return fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=%s", d.User, d.Host, d.Port, d.Name, d.SSLMode)
}

// ServerConfig controls the embedded web server.
type ServerConfig struct {
	Listen  string    `yaml:"listen"`
	Port    int       `yaml:"port"`
	BaseURL string    `yaml:"base_url"`
	TLS     TLSConfig `yaml:"tls"`
}

// TLSConfig optionally serves the portal over HTTPS.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// SecurityConfig holds the secrets used to protect data at rest and sessions.
type SecurityConfig struct {
	// MasterKey (base64, 32 bytes) encrypts private keys stored in SQLite.
	MasterKey string `yaml:"master_key"`
	// SessionKey (base64, 32 bytes) signs session cookies.
	SessionKey string        `yaml:"session_key"`
	SessionTTL time.Duration `yaml:"session_ttl"`
	// SecureCookies forces the Secure flag on cookies (enable behind TLS).
	SecureCookies bool `yaml:"secure_cookies"`
}

// AuthMode selects whether local password login is offered alongside
// whatever of LDAP/OIDC is enabled below. Unlike those two - each independently
// toggled by its own Enabled flag - Mode only ever gates local: "ldap" turns
// it off (directory-only, no break-glass fallback), "local" and "both" leave
// it on. This predates OIDC and keeps existing configs working unchanged;
// OIDC.Enabled composes with it exactly like LDAP.Enabled already does.
type AuthMode string

const (
	AuthModeLocal AuthMode = "local"
	AuthModeLDAP  AuthMode = "ldap"
	AuthModeBoth  AuthMode = "both"
)

// AuthConfig configures portal / API authentication.
type AuthConfig struct {
	Mode       AuthMode   `yaml:"mode"`
	LocalAdmin LocalAdmin `yaml:"local_admin"`
	LDAP       LDAPConfig `yaml:"ldap"`
	OIDC       OIDCConfig `yaml:"oidc"`
}

// LocalAdmin is the break-glass account created during setup.
type LocalAdmin struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

// LDAPConfig describes how to bind and search a directory server.
type LDAPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	StartTLS bool   `yaml:"start_tls"`
	// InsecureSkipVerify disables certificate verification (lab use only).
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CACertFile         string `yaml:"ca_cert_file"`

	// BindDN/BindPassword is the service account used to search for users.
	// Leave empty for anonymous search or pure DN-template binding.
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"` // encrypted with MasterKey (enc: prefix)

	BaseDN     string `yaml:"base_dn"`
	UserFilter string `yaml:"user_filter"` // e.g. (&(objectClass=person)(uid=%s))
	// UserDNTemplate is an alternative to searching, e.g. uid=%s,ou=people,dc=x
	UserDNTemplate string `yaml:"user_dn_template"`

	AttrUsername    string `yaml:"attr_username"`
	AttrDisplayName string `yaml:"attr_display_name"`
	AttrEmail       string `yaml:"attr_email"`

	GroupBaseDN string `yaml:"group_base_dn"`
	GroupFilter string `yaml:"group_filter"` // e.g. (&(objectClass=groupOfNames)(member=%s))
	AttrGroup   string `yaml:"attr_group"`

	// AdminGroups grants the admin role; AllowedGroups (if non-empty)
	// restricts login to members of at least one listed group.
	AdminGroups   []string `yaml:"admin_groups"`
	AllowedGroups []string `yaml:"allowed_groups"`

	Timeout time.Duration `yaml:"timeout"`
}

// OIDCConfig describes a single-sign-on provider (Dex, Keycloak, Okta, Azure
// Entra ID, Google, or anything else that speaks standard OpenID Connect
// discovery). goca is a confidential client: the client secret authenticates
// it to the provider, so the authorization code flow here does not need PKCE
// on top of that.
type OIDCConfig struct {
	Enabled bool `yaml:"enabled"`

	// IssuerURL is fetched at <issuer_url>/.well-known/openid-configuration
	// for the token/authorization endpoints and signing keys - e.g.
	// https://dex.example.com or https://login.microsoftonline.com/<tenant-id>/v2.0.
	IssuerURL string `yaml:"issuer_url"`
	ClientID  string `yaml:"client_id"`
	// ClientSecret is encrypted with MasterKey (enc: prefix), like the LDAP
	// bind password.
	ClientSecret string `yaml:"client_secret"`
	// RedirectURL defaults to "<server.base_url>/auth/oidc/callback" and must
	// match what's registered with the provider exactly.
	RedirectURL string `yaml:"redirect_url"`
	// Scopes defaults to {openid, profile, email}. "openid" is added
	// automatically if omitted - every OIDC request requires it.
	Scopes []string `yaml:"scopes"`

	// InsecureSkipVerify disables certificate verification talking to the
	// issuer (lab use only, e.g. a self-signed Dex instance).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	// Claim* name the ID token (or userinfo) claims mapped onto goca's user
	// model. Defaults match what most providers, including Dex and Entra ID,
	// emit out of the box.
	ClaimUsername    string `yaml:"claim_username,omitempty"`     // default preferred_username
	ClaimDisplayName string `yaml:"claim_display_name,omitempty"` // default name
	ClaimEmail       string `yaml:"claim_email,omitempty"`        // default email
	// ClaimGroups names the group-membership claim; blank uses the "groups"
	// default. There's no separate toggle to disable group-based mapping -
	// leaving AdminGroups and AllowedGroups both empty already has that
	// effect (every authenticated user gets the "user" role, nobody is
	// excluded). Entra ID needs an optional claim configured on the app
	// registration before it emits a groups claim at all.
	ClaimGroups string `yaml:"claim_groups,omitempty"` // default groups

	// AdminGroups grants the admin role; AllowedGroups (if non-empty)
	// restricts login to members of at least one listed group. Matched
	// case-insensitively against the groups claim's values.
	AdminGroups   []string `yaml:"admin_groups"`
	AllowedGroups []string `yaml:"allowed_groups"`
}

// CAConfig holds issuance defaults.
type CAConfig struct {
	DefaultCertDays  int      `yaml:"default_cert_days"`
	DefaultCADays    int      `yaml:"default_ca_days"`
	DefaultKeyType   string   `yaml:"default_key_type"`
	CRLDays          int      `yaml:"crl_days"`
	AllowUserRequest bool     `yaml:"allow_user_request"`
	OCSPServers      []string `yaml:"ocsp_servers"`
	CRLDistPoints    []string `yaml:"crl_distribution_points"`
}

// Default returns a config populated with sensible defaults for the current
// user. Secrets are left empty; call GenerateSecrets to fill them.
func Default() *Config {
	dataDir := DefaultDataDir()
	return &Config{
		DataDir:  dataDir,
		DBPath:   filepath.Join(dataDir, "goca.db"),
		Database: DatabaseConfig{Driver: DBDriverSQLite},
		Server: ServerConfig{
			Listen:  "0.0.0.0",
			Port:    8080,
			BaseURL: "http://localhost:8080",
		},
		Security: SecurityConfig{
			SessionTTL: 8 * time.Hour,
		},
		Auth: AuthConfig{
			Mode:       AuthModeLocal,
			LocalAdmin: LocalAdmin{Username: "admin"},
			LDAP: LDAPConfig{
				UserFilter:      "(&(objectClass=person)(uid=%s))",
				AttrUsername:    "uid",
				AttrDisplayName: "cn",
				AttrEmail:       "mail",
				GroupFilter:     "(&(objectClass=groupOfNames)(member=%s))",
				AttrGroup:       "cn",
				Timeout:         10 * time.Second,
			},
		},
		CA: CAConfig{
			DefaultCertDays:  397,
			DefaultCADays:    3650,
			DefaultKeyType:   "rsa-2048",
			CRLDays:          7,
			AllowUserRequest: true,
		},
	}
}

// DefaultDataDir picks /var/lib/goca for root and ~/.goca otherwise.
func DefaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/goca"
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".goca")
	}
	return ".goca"
}

// DefaultConfigPath returns where setup writes config.yaml by default.
func DefaultConfigPath() string {
	if p := os.Getenv(EnvConfigPath); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return "/etc/goca/config.yaml"
	}
	return filepath.Join(DefaultDataDir(), "config.yaml")
}

// Discover looks for a config in the explicit path, the env var, and then the
// standard locations, returning the first that exists.
func Discover(explicit string) (string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	if p := os.Getenv(EnvConfigPath); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates,
		filepath.Join(DefaultDataDir(), "config.yaml"),
		"/etc/goca/config.yaml",
	)
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	if explicit != "" {
		return "", fmt.Errorf("config not found at %s", explicit)
	}
	return "", errors.New("no goca config found; run `goca setup` first")
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	resolved, err := Discover(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", resolved, err)
	}
	cfg.Path = resolved
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config with 0600 permissions, creating parent directories.
func (c *Config) Save(path string) error {
	if path == "" {
		path = c.Path
	}
	if path == "" {
		return errors.New("no config path given")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	header := "# goca configuration - generated by `goca setup`\n" +
		"# This file contains secrets; keep it mode 0600.\n"
	if err := os.WriteFile(path, append([]byte(header), b...), 0o600); err != nil {
		return err
	}
	c.Path = path
	return nil
}

// Validate checks the invariants the rest of the program relies on.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.DBPath == "" {
		c.DBPath = filepath.Join(c.DataDir, "goca.db")
	}
	switch c.Database.Driver {
	case "", DBDriverSQLite:
		c.Database.Driver = DBDriverSQLite
	case DBDriverPostgres:
		if c.Database.Host == "" {
			return errors.New("database.host is required when database.driver is postgres")
		}
		if c.Database.Name == "" {
			return errors.New("database.name is required when database.driver is postgres")
		}
		if c.Database.User == "" {
			return errors.New("database.user is required when database.driver is postgres")
		}
		if c.Database.Port == 0 {
			c.Database.Port = 5432
		}
		if c.Database.SSLMode == "" {
			c.Database.SSLMode = "require"
		}
	default:
		return fmt.Errorf("database.driver %q must be sqlite or postgres", c.Database.Driver)
	}
	if c.Security.MasterKey == "" {
		return errors.New("security.master_key is missing; re-run `goca setup`")
	}
	if _, err := base64.StdEncoding.DecodeString(c.Security.MasterKey); err != nil {
		return fmt.Errorf("security.master_key is not valid base64: %w", err)
	}
	if c.Security.SessionKey == "" {
		return errors.New("security.session_key is missing; re-run `goca setup`")
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Security.SessionTTL == 0 {
		c.Security.SessionTTL = 8 * time.Hour
	}
	switch c.Auth.Mode {
	case AuthModeLocal, AuthModeLDAP, AuthModeBoth:
	case "":
		c.Auth.Mode = AuthModeLocal
	default:
		return fmt.Errorf("auth.mode %q must be local, ldap or both", c.Auth.Mode)
	}
	if c.Auth.Mode != AuthModeLocal && !c.Auth.LDAP.Enabled && !c.Auth.OIDC.Enabled {
		return errors.New("auth.mode requires LDAP or OIDC, but neither is enabled")
	}
	if c.Auth.OIDC.Enabled && c.Auth.OIDC.RedirectURL == "" {
		c.Auth.OIDC.RedirectURL = strings.TrimRight(c.Server.BaseURL, "/") + "/auth/oidc/callback"
	}
	if c.CA.DefaultCertDays <= 0 {
		c.CA.DefaultCertDays = 397
	}
	if c.CA.DefaultCADays <= 0 {
		c.CA.DefaultCADays = 3650
	}
	if c.CA.CRLDays <= 0 {
		c.CA.CRLDays = 7
	}
	return nil
}

// GenerateSecrets fills any missing cryptographic material.
func (c *Config) GenerateSecrets() error {
	if c.Security.MasterKey == "" {
		k, err := randomKey(32)
		if err != nil {
			return err
		}
		c.Security.MasterKey = k
	}
	if c.Security.SessionKey == "" {
		k, err := randomKey(32)
		if err != nil {
			return err
		}
		c.Security.SessionKey = k
	}
	return nil
}

func randomKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// MasterKeyBytes decodes the configured master key.
func (c *Config) MasterKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.Security.MasterKey)
}

// SessionKeyBytes decodes the configured session key.
func (c *Config) SessionKeyBytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.Security.SessionKey)
}

// Addr returns the host:port the web server binds to.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Listen, c.Server.Port)
}
