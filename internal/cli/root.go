// Package cli implements the goca command line, which exposes every
// capability the web portal and REST API expose.
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/web"
)

// Build information, overridden with -ldflags at release time.
var (
	Version = "0.1.0"
	Commit  = ""
	Date    = ""
)

// global flags
var (
	flagConfig  string
	flagJSON    bool
	flagVerbose bool
	flagActor   string
)

// app carries the loaded runtime for command implementations.
type app struct {
	cfg  *config.Config
	st   *store.Store
	svc  *ca.Service
	auth *auth.Manager
	log  *slog.Logger
}

func (a *app) Close() {
	if a.st != nil {
		_ = a.st.Close()
	}
}

// actor returns the name recorded in the audit log for CLI actions.
func (a *app) actor() string {
	if flagActor != "" {
		return flagActor
	}
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u + " (cli)"
	}
	if u := os.Getenv("USER"); u != "" {
		return u + " (cli)"
	}
	return "cli"
}

// open loads the config, opens the database and builds the service layer.
func open() (*app, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, err
	}
	st, err := openStore(cfg)
	if err != nil {
		return nil, err
	}
	svc, err := ca.New(cfg, st)
	if err != nil {
		st.Close()
		return nil, err
	}
	mgr, err := auth.NewManager(cfg, st, svc.Box())
	if err != nil {
		st.Close()
		return nil, err
	}
	if err := mgr.EnsureLocalAdmin(context.Background()); err != nil {
		st.Close()
		return nil, err
	}
	return &app{cfg: cfg, st: st, svc: svc, auth: mgr, log: newLogger()}, nil
}

// openStore opens the configured storage backend: SQLite (the default) at
// cfg.DBPath, or PostgreSQL when cfg.Database.Driver selects it. The
// PostgreSQL password is stored encrypted (like the LDAP bind password) and
// is decrypted here, right before connecting.
func openStore(cfg *config.Config) (*store.Store, error) {
	if !cfg.Database.IsPostgres() {
		return store.Open(cfg.DBPath)
	}
	d := cfg.Database
	password := d.Password
	if secret.IsEncrypted(password) {
		key, err := cfg.MasterKeyBytes()
		if err != nil {
			return nil, err
		}
		box, err := secret.NewBox(key)
		if err != nil {
			return nil, err
		}
		password, err = box.DecryptString(password)
		if err != nil {
			return nil, fmt.Errorf("decrypt database.password: %w", err)
		}
	}
	return store.OpenPostgres(store.PostgresParams{
		Host:     d.Host,
		Port:     d.Port,
		Name:     d.Name,
		User:     d.User,
		Password: password,
		SSLMode:  d.SSLMode,
	})
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if flagVerbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// Execute runs the goca command line.
func Execute() int {
	web.Version = Version
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "goca",
		Short: "Self-hosted certificate authority with a web portal, REST API and CLI",
		Long: strings.TrimSpace(`
goca is a single-binary certificate authority.

It stores CAs, issued certificates and (optionally) their private keys in a
database (SQLite by default, or PostgreSQL), serves an embedded web portal
with LDAP or local login, and exposes the same capabilities over a REST API
and this command line.

Getting started:
  goca setup                    generate configuration, database and admin account
  goca ca create --wizard       create your first certificate authority
  goca run web --port=8080      serve the portal
  goca install web --port=8080  install a systemd/launchd service for it`),
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       versionString(),
	}

	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "",
		"path to config.yaml (default: $GOCA_CONFIG, ~/.goca/config.yaml, /etc/goca/config.yaml)")
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "emit JSON instead of tables")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose logging")
	root.PersistentFlags().StringVar(&flagActor, "actor", "",
		"name recorded in the audit log for this action")

	root.AddCommand(
		newSetupCmd(),
		newRunCmd(),
		newInstallCmd(),
		newUninstallCmd(),
		newCACmd(),
		newCertCmd(),
		newCSRCmd(),
		newInspectCmd(),
		newUserCmd(),
		newTokenCmd(),
		newLDAPCmd(),
		newACMECmd(),
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
		Short: "Print the goca version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if flagJSON {
				return printJSON(map[string]string{
					"version": Version, "commit": Commit, "date": Date,
				})
			}
			cmd.Println("goca " + versionString())
			return nil
		},
	}
}
