// Package rcli implements gocactl, the remote command line for a goca server.
//
// It is the counterpart to internal/cli: the same capabilities, reached over
// the REST API instead of by opening the database. That is the whole
// distinction - `goca` must run on the server host and holds the master key;
// `gocactl` runs anywhere, holds only an API token, and can do exactly what the
// signed-in account's role allows.
//
// Two commands stay entirely local and never contact the server: `csr new`
// generates a key, and `inspect` reads a certificate someone handed you.
// Routing either through an API would mean sending a private key or a
// third-party certificate to a server that has no need to see it.
package rcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

// Build information, overridden with -ldflags at release time. Kept separate
// from internal/cli's so the existing server ldflag paths keep working.
var (
	Version = "0.1.0"
	Commit  = ""
	Date    = ""
)

// Persistent flags.
var (
	flagConfig   string
	flagContext  string
	flagServer   string
	flagToken    string
	flagCACert   string
	flagInsecure bool
	flagJSON     bool
	flagVerbose  bool
)

// Execute runs gocactl.
func Execute() int {
	gocaclient.Version = Version
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// ctx returns a context cancelled on SIGINT/SIGTERM, so a long download stops
// promptly on Ctrl-C.
func cmdContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
}

// client builds an API client from the resolved configuration.
func client() (*gocaclient.Client, error) {
	cfg, err := LoadConfig(flagConfig)
	if err != nil {
		return nil, err
	}
	opts, _, err := cfg.Resolve()
	if err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("not signed in: run `gocactl login`, or set GOCACTL_TOKEN")
	}
	if opts.InsecureSkipVerify {
		termio.Warn("TLS certificate verification is disabled for %s", opts.Server)
	}
	return gocaclient.New(opts)
}

// NewRootCmd exposes the assembled command tree so that internal/cli's
// flag-parity test can compare gocactl's flags against goca's. Nothing else
// should need it; Execute is the entry point.
func NewRootCmd() *cobra.Command { return newRootCmd() }

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "gocactl",
		Short: "Manage a goca certificate authority over its REST API",
		Long: strings.TrimSpace(`
gocactl administers a goca server remotely. It never opens the database and
never needs the master key - it signs in with your own account and can do
whatever your role allows.

  gocactl login --server https://ca.example.com
  gocactl ca list
  gocactl cert issue --common-name app.internal.lan --san app.internal.lan

Two commands run entirely offline and never contact the server: ` + "`csr new`" + `
generates a key locally, and ` + "`inspect`" + ` decodes a certificate you already
have. Neither should ever hand material to a server that has no need for it.

Server-side work - ` + "`setup`" + `, ` + "`run web`" + `, ` + "`install web`" + ` - stays in the goca
binary, since it needs the database and the host itself.`),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       versionString(),
	}

	pf := root.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "",
		"path to the gocactl config (default: $GOCACTL_CONFIG, then ~/.config/gocactl/config.yaml)")
	pf.StringVar(&flagContext, "context", "", "use this named context instead of the current one")
	pf.StringVar(&flagServer, "server", "", "goca base URL, overriding the context")
	pf.StringVar(&flagToken, "token", "",
		"API token, overriding the context (prefer GOCACTL_TOKEN in automation - a flag is visible in ps)")
	pf.StringVar(&flagCACert, "ca-cert", "", "trust this CA when connecting (PEM file)")
	pf.BoolVar(&flagInsecure, "insecure-skip-verify", false, "skip TLS verification (lab use only)")
	pf.BoolVar(&flagJSON, "json", false, "emit the server's JSON instead of tables")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "verbose output")

	root.AddCommand(
		newLoginCmd(),
		newLogoutCmd(),
		newWhoamiCmd(),
		newConfigCmd(),
		newCACmd(),
		newCertCmd(),
		newCSRCmd(),
		newInspectCmd(),
		newSecretCmd(),
		newACMECmd(),
		newCsiAuthCmd(),
		newWebhookCmd(),
		newUserCmd(),
		newTokenCmd(),
		newAuditCmd(),
		newVersionCmd(),
	)
	return root
}

func versionString() string {
	s := Version
	if Commit != "" {
		s += " (" + Commit + ")"
	}
	if Date != "" {
		s += " built " + Date
	}
	return s
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the gocactl version, and the server's if reachable",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()

			out := map[string]string{"client": Version, "commit": Commit, "date": Date}
			// The server version is useful but optional - `gocactl version`
			// must work with no server configured at all.
			if c, err := client(); err == nil {
				if res, err := c.Health(ctx); err == nil {
					if v, ok := res.Value["version"].(string); ok {
						out["server"] = v
					}
					out["server_url"] = c.Server()
				}
			}
			if flagJSON {
				return termio.PrintJSON(out)
			}
			fmt.Println("gocactl " + versionString())
			if out["server"] != "" {
				fmt.Printf("server  %s (%s)\n", out["server"], out["server_url"])
			}
			return nil
		},
	}
}
