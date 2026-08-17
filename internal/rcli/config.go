package rcli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

// gocactl's own configuration: which servers it knows about and the token for
// each. Shaped like a kubeconfig because the job is the same one - point a
// command at one of several environments without retyping credentials.
//
// This is deliberately NOT the server's config.yaml and does not honour
// GOCA_CONFIG. That file holds security.master_key, which decrypts every CA
// private key in the database; writing a client token into it would be a nasty
// footgun, and the Dockerfile sets GOCA_CONFIG, so honouring it would make
// gocactl silently read the server's config inside the image.

// Context is one named server plus the credential for it.
type Context struct {
	Server string `yaml:"server" json:"server"`
	Token  string `yaml:"token,omitempty" json:"token,omitempty"`
	// TokenID lets `gocactl logout` revoke the token server-side rather than
	// just forgetting it locally.
	TokenID int64 `yaml:"token_id,omitempty" json:"token_id,omitempty"`

	// Cached from the login response so `whoami` and the expiry warning need
	// no round trip. Advisory only - the server remains authoritative.
	User      string     `yaml:"user,omitempty" json:"user,omitempty"`
	Role      string     `yaml:"role,omitempty" json:"role,omitempty"`
	ExpiresAt *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`

	CACert             string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`
}

// Config is the whole file.
type Config struct {
	CurrentContext string              `yaml:"current_context" json:"current_context"`
	Contexts       map[string]*Context `yaml:"contexts" json:"contexts"`

	// path is where this was loaded from, so Save writes back to the same
	// place. Not serialised.
	path string `yaml:"-"`
}

const configFileHeader = `# gocactl configuration.
#
# This file contains API tokens - keep it mode 0600. It is the client's own
# config and is unrelated to the goca server's config.yaml, which holds the
# master encryption key.
`

// configPath resolves where to read and write, first match winning:
//
//	--config / $GOCACTL_CONFIG
//	$XDG_CONFIG_HOME/gocactl/config.yaml
//	~/.config/gocactl/config.yaml     <- what `login` creates
//	~/.gocactl/config.yaml            <- only when it already exists
func configPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("GOCACTL_CONFIG"); p != "" {
		return p
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "gocactl", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "gocactl.yaml"
	}
	legacy := filepath.Join(home, ".gocactl", "config.yaml")
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return filepath.Join(home, ".config", "gocactl", "config.yaml")
}

// LoadConfig reads the config file. A missing file is not an error: a client
// driven purely by GOCACTL_SERVER + GOCACTL_TOKEN (CI, containers) must work
// with no file at all.
func LoadConfig(explicit string) (*Config, error) {
	path := configPath(explicit)
	cfg := &Config{Contexts: map[string]*Context{}, path: path}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
		// A warning, not a failure: Windows and some CI images cannot express
		// these bits, and refusing to run would be worse than saying so.
		termio.Warn("%s is readable by other users (mode %04o); it contains an API token", path, info.Mode().Perm())
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]*Context{}
	}
	cfg.path = path
	return cfg, nil
}

// Save writes the config atomically. A truncate-in-place that died halfway
// would leave a partial token behind and lock the user out of their own server.
func (c *Config) Save() error {
	if c.path == "" {
		c.path = configPath("")
	}
	if dir := filepath.Dir(c.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	body, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(configFileHeader), body...), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Path is where this config lives.
func (c *Config) Path() string { return c.path }

// ContextNames returns the configured context names, sorted - the map itself
// has no stable order.
func (c *Config) ContextNames() []string {
	names := make([]string, 0, len(c.Contexts))
	for name := range c.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Resolve layers the config, environment and flags into client options.
// Precedence, highest first: flags, environment, --context, current_context.
//
// It fails only when the *result* has no server or no token, so the
// no-config-file case works as long as the environment supplies both.
func (c *Config) Resolve() (gocaclient.Options, string, error) {
	name := flagContext
	if name == "" {
		name = os.Getenv("GOCACTL_CONTEXT")
	}
	if name == "" {
		name = c.CurrentContext
	}

	var ctx Context
	if name != "" {
		if found, ok := c.Contexts[name]; ok {
			ctx = *found
		} else if flagContext != "" || os.Getenv("GOCACTL_CONTEXT") != "" {
			// An explicitly named context that does not exist is a mistake
			// worth reporting, unlike a stale current_context.
			return gocaclient.Options{}, "", fmt.Errorf(
				"no context named %q in %s (try `gocactl config get-contexts`)", name, c.path)
		}
	}

	opts := gocaclient.Options{
		Server:             ctx.Server,
		Token:              ctx.Token,
		CACertFile:         ctx.CACert,
		InsecureSkipVerify: ctx.InsecureSkipVerify,
	}

	if v := os.Getenv("GOCACTL_SERVER"); v != "" {
		opts.Server = v
	}
	if v := os.Getenv("GOCACTL_TOKEN"); v != "" {
		opts.Token = v
	}
	if v := os.Getenv("GOCACTL_CA_CERT"); v != "" {
		opts.CACertFile = v
	}
	if v := os.Getenv("GOCACTL_INSECURE"); v == "1" || strings.EqualFold(v, "true") {
		opts.InsecureSkipVerify = true
	}

	if flagServer != "" {
		opts.Server = flagServer
	}
	if flagToken != "" {
		opts.Token = flagToken
	}
	if flagCACert != "" {
		opts.CACertFile = flagCACert
	}
	if flagInsecure {
		opts.InsecureSkipVerify = true
	}

	if opts.Server == "" {
		return opts, name, errors.New(
			"no goca server configured: run `gocactl login --server https://ca.example.com`, " +
				"or set GOCACTL_SERVER")
	}
	return opts, name, nil
}
