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
	st, err := store.Open(cfg.DBPath)
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
SQLite database, serves an embedded web portal with LDAP or local login, and
exposes the same capabilities over a REST API and this command line.

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
