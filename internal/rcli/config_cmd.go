package rcli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/mevijays/goca/internal/termio"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage gocactl's own contexts and credentials",
		Long: strings.TrimSpace(`
A context is one goca server plus the token for it. Several can be configured
at once - a lab and a production CA, say - and switched between without
re-authenticating.

This is gocactl's own configuration. It is unrelated to the server's
config.yaml, and deliberately does not read GOCA_CONFIG, which points at the
file holding the master encryption key.`),
	}
	cmd.AddCommand(
		newConfigGetContextsCmd(),
		newConfigCurrentContextCmd(),
		newConfigUseContextCmd(),
		newConfigSetContextCmd(),
		newConfigDeleteContextCmd(),
		newConfigViewCmd(),
	)
	return cmd
}

func newConfigGetContextsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "get-contexts",
		Aliases: []string{"list"},
		Short:   "List configured contexts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			if flagJSON {
				// Redacted, matching the table: this command lists contexts, and
				// nobody adding --json to a listing expects it to start printing
				// credentials. `config view --show-token` is the deliberate way
				// to get a token back out.
				for _, c := range cfg.Contexts {
					if c.Token != "" {
						c.Token = redactToken(c.Token)
					}
				}
				return termio.PrintJSON(cfg)
			}
			names := cfg.ContextNames()
			if len(names) == 0 {
				fmt.Println("No contexts yet. Sign in with `gocactl login --server https://ca.example.com`.")
				return nil
			}
			t := termio.NewTable("current", "name", "server", "user", "role", "token expires")
			for _, name := range names {
				c := cfg.Contexts[name]
				marker := ""
				if name == cfg.CurrentContext {
					marker = "*"
				}
				expires := "-"
				if c.ExpiresAt != nil {
					expires = c.ExpiresAt.Local().Format("2006-01-02")
				}
				t.Row(marker, name, c.Server, dash(c.User), dash(c.Role), expires)
			}
			t.Flush()
			return nil
		},
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newConfigCurrentContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "current-context",
		Short: "Print the current context's name",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			if cfg.CurrentContext == "" {
				return fmt.Errorf("no current context is set")
			}
			fmt.Println(cfg.CurrentContext)
			return nil
		},
	}
}

func newConfigUseContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "use-context <name>",
		Short: "Switch the current context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			if _, ok := cfg.Contexts[args[0]]; !ok {
				return fmt.Errorf("no context named %q (see `gocactl config get-contexts`)", args[0])
			}
			cfg.CurrentContext = args[0]
			if err := cfg.Save(); err != nil {
				return err
			}
			termio.OK("switched to %q (%s)", args[0], cfg.Contexts[args[0]].Server)
			return nil
		},
	}
}

func newConfigSetContextCmd() *cobra.Command {
	var (
		server   string
		token    string
		caCert   string
		insecure bool
	)
	cmd := &cobra.Command{
		Use:   "set-context <name>",
		Short: "Create or update a context without signing in",
		Long: strings.TrimSpace(`
Useful for scripting, or for pointing an existing context at a new address.
To obtain a token interactively, use ` + "`gocactl login`" + ` instead.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			entry := cfg.Contexts[args[0]]
			if entry == nil {
				entry = &Context{}
				cfg.Contexts[args[0]] = entry
			}
			if server != "" {
				entry.Server = server
			}
			if token != "" {
				// A token set by hand tells us nothing about its identity or
				// id; clear the cached values rather than leave stale ones.
				entry.Token, entry.TokenID, entry.User, entry.Role, entry.ExpiresAt = token, 0, "", "", nil
			}
			if caCert != "" {
				entry.CACert = caCert
			}
			if cmd.Flags().Changed("insecure-skip-verify") {
				entry.InsecureSkipVerify = insecure
			}
			if entry.Server == "" {
				return fmt.Errorf("--server is required for a new context")
			}
			if cfg.CurrentContext == "" {
				cfg.CurrentContext = args[0]
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			termio.OK("context %q saved", args[0])
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&server, "server", "", "goca base URL")
	fl.StringVar(&token, "token", "", "API token")
	fl.StringVar(&caCert, "ca-cert", "", "trust this CA (PEM file)")
	fl.BoolVar(&insecure, "insecure-skip-verify", false, "skip TLS verification (lab use only)")
	return cmd
}

func newConfigDeleteContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete-context <name>",
		Aliases: []string{"rm"},
		Short:   "Remove a context",
		Long: strings.TrimSpace(`
Forgets the context locally. The token stays valid on the server - use
` + "`gocactl logout`" + ` to revoke it as well.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			if _, ok := cfg.Contexts[args[0]]; !ok {
				return fmt.Errorf("no context named %q", args[0])
			}
			delete(cfg.Contexts, args[0])
			if cfg.CurrentContext == args[0] {
				cfg.CurrentContext = ""
				for _, other := range cfg.ContextNames() {
					cfg.CurrentContext = other
					break
				}
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			termio.OK("removed %q (its token is still valid on the server; `gocactl logout` revokes)", args[0])
			return nil
		},
	}
}

func newConfigViewCmd() *cobra.Command {
	var showToken bool
	cmd := &cobra.Command{
		Use:   "view",
		Short: "Print the configuration, with tokens redacted",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			if !showToken {
				// The prefix is already public (it identifies the token in
				// `goca token list`); the body is the credential.
				for _, c := range cfg.Contexts {
					if c.Token != "" {
						c.Token = redactToken(c.Token)
					}
				}
			}
			if flagJSON {
				return termio.PrintJSON(cfg)
			}
			// YAML, not JSON: this prints the file the user edits, so it should
			// look like that file rather than like a Go struct dump.
			out, err := yaml.Marshal(cfg)
			if err != nil {
				return err
			}
			fmt.Printf("# %s\n", cfg.Path())
			fmt.Print(string(out))
			return nil
		},
	}
	cmd.Flags().BoolVar(&showToken, "show-token", false, "print tokens in full")
	return cmd
}

// redactToken keeps a goca token's public prefix and hides the secret body.
func redactToken(tok string) string {
	parts := strings.SplitN(tok, "_", 3)
	if len(parts) == 3 {
		return parts[0] + "_" + parts[1] + "_" + "…"
	}
	return "…"
}
