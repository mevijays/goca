package rcli

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

func newLoginCmd() *cobra.Command {
	var (
		server        string
		username      string
		passwordStdin bool
		token         string
		contextName   string
		days          int
		tokenName     string
		caCert        string
		insecure      bool
		setCurrent    bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to a goca server and save the credential",
		Long: strings.TrimSpace(`
Exchanges your username and password for an API token and saves it, so later
commands need no credentials. The token expires - the server sets the default
and the cap - and can be revoked at any time with ` + "`gocactl logout`" + `, from
the portal, or with ` + "`goca token list`" + ` on the server.

With --token, an existing token (from ` + "`goca token create`" + ` or the portal) is
saved instead of signing in. This is the path for an SSO-only server, where
there is no password to exchange.

There is deliberately no --password flag: it would be visible in ps output and
recorded in shell history. Type it at the prompt, or pipe it with
--password-stdin.`),
		Example: strings.TrimSpace(`
  gocactl login --server https://ca.example.com
  gocactl login --server https://ca.example.com --username alice --context prod
  printf '%s' "$PASSWORD" | gocactl login --server https://ca.example.com -u alice --password-stdin
  gocactl login --server https://ca.example.com --token goca_xxxxxxxx_...`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()

			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}

			// An existing context supplies the server when --server is omitted,
			// so `gocactl login` alone re-authenticates where you were.
			name := contextName
			if name == "" {
				name = flagContext
			}
			if server == "" && name != "" && cfg.Contexts[name] != nil {
				server = cfg.Contexts[name].Server
			}
			if server == "" && cfg.CurrentContext != "" && cfg.Contexts[cfg.CurrentContext] != nil {
				server = cfg.Contexts[cfg.CurrentContext].Server
				if name == "" {
					name = cfg.CurrentContext
				}
			}
			if server == "" {
				return fmt.Errorf("--server is required the first time (e.g. --server https://ca.example.com)")
			}
			if name == "" {
				name = contextNameFor(server)
			}

			c, err := gocaclient.New(gocaclient.Options{
				Server:             server,
				Token:              token,
				CACertFile:         caCert,
				InsecureSkipVerify: insecure,
			})
			if err != nil {
				return err
			}
			if insecure {
				termio.Warn("TLS certificate verification is disabled for %s", c.Server())
			}

			entry := &Context{
				Server:             c.Server(),
				CACert:             caCert,
				InsecureSkipVerify: insecure,
			}

			if token != "" {
				// Validate the pasted token rather than saving something that
				// silently fails on the next command, and pick up the identity
				// and expiry while we are there.
				res, err := c.Me(ctx)
				if err != nil {
					return fmt.Errorf("that token was not accepted by %s: %w", c.Server(), err)
				}
				entry.Token = token
				entry.User = res.Value.Username
				entry.Role = res.Value.Auth.Role
				entry.TokenID = res.Value.Auth.TokenID
				entry.ExpiresAt = res.Value.Auth.ExpiresAt
			} else {
				password, err := readPassword(passwordStdin)
				if err != nil {
					return err
				}
				if username == "" {
					if !termio.Interactive() {
						return fmt.Errorf("--username is required when stdin is not a terminal")
					}
					username = termio.AskRequired("Username", "")
				}
				if tokenName == "" {
					tokenName = defaultTokenName()
				}
				res, err := c.Login(ctx, gocaclient.LoginInput{
					Username:  username,
					Password:  password,
					TokenName: tokenName,
					Days:      days,
				})
				if err != nil {
					return err
				}
				entry.Token = res.Value.Token
				entry.TokenID = res.Value.TokenID
				entry.User = res.Value.User.Username
				entry.Role = res.Value.Role
				entry.ExpiresAt = res.Value.ExpiresAt
			}

			cfg.Contexts[name] = entry
			if setCurrent || cfg.CurrentContext == "" {
				cfg.CurrentContext = name
			}
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("save %s: %w", cfg.Path(), err)
			}

			termio.OK("signed in to %s as %s (%s)", entry.Server, entry.User, entry.Role)
			termio.Info("context %q saved to %s", name, cfg.Path())
			if entry.ExpiresAt != nil {
				termio.Info("token expires %s", entry.ExpiresAt.Local().Format("2006-01-02 15:04"))
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&server, "server", "", "goca base URL, e.g. https://ca.example.com")
	fl.StringVarP(&username, "username", "u", "", "account to sign in as")
	fl.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin instead of prompting")
	fl.StringVar(&token, "token", "", "save an existing API token instead of signing in with a password")
	fl.StringVar(&contextName, "context", "", "name for this context (default: derived from the server host)")
	fl.IntVar(&days, "days", 0, "token lifetime in days (0 = the server's default; the server also caps it)")
	fl.StringVar(&tokenName, "name", "", "label for the token (default: gocactl@<hostname>)")
	fl.StringVar(&caCert, "ca-cert", "", "trust this CA when connecting (PEM file)")
	fl.BoolVar(&insecure, "insecure-skip-verify", false, "skip TLS verification (lab use only)")
	fl.BoolVar(&setCurrent, "set-current", true, "make this the current context")
	return cmd
}

// readPassword takes the password from stdin or an interactive prompt. It is
// never a flag - see the command's long help.
func readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		pw, err := termio.ReadPasswordStdin()
		if err != nil {
			return "", err
		}
		if pw == "" {
			return "", fmt.Errorf("no password on stdin")
		}
		return pw, nil
	}
	if !termio.Interactive() {
		return "", fmt.Errorf("stdin is not a terminal: pass --password-stdin, or --token")
	}
	return termio.AskPassword("Password", false)
}

// contextNameFor derives a short context name from a server URL, so the common
// case needs no --context.
func contextNameFor(server string) string {
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return "default"
	}
	return u.Hostname()
}

// defaultTokenName labels the token with where it was created, so it is
// identifiable later in `goca token list`.
func defaultTokenName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "gocactl login"
	}
	return "gocactl@" + host
}

func newLogoutCmd() *cobra.Command {
	var keepToken bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke this context's token and forget it",
		Long: strings.TrimSpace(`
Revokes the token server-side and then removes it from the local config, so
signing out actually invalidates the credential rather than just forgetting
where it was written. With --keep-token the token is left valid on the server
and only removed locally.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()

			cfg, err := LoadConfig(flagConfig)
			if err != nil {
				return err
			}
			_, name, err := cfg.Resolve()
			if err != nil {
				return err
			}
			entry := cfg.Contexts[name]
			if entry == nil || entry.Token == "" {
				return fmt.Errorf("not signed in to any context")
			}

			if !keepToken && entry.TokenID != 0 {
				c, err := client()
				if err != nil {
					return err
				}
				if err := c.RevokeToken(ctx, entry.TokenID); err != nil {
					// Worth continuing: an already-expired or already-revoked
					// token still needs clearing from the local config.
					termio.Warn("could not revoke the token server-side: %v", err)
				} else {
					termio.OK("revoked token %d on %s", entry.TokenID, entry.Server)
				}
			}

			delete(cfg.Contexts, name)
			if cfg.CurrentContext == name {
				cfg.CurrentContext = ""
				for _, other := range cfg.ContextNames() {
					cfg.CurrentContext = other
					break
				}
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			termio.OK("removed context %q", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&keepToken, "keep-token", false, "leave the token valid on the server; only forget it locally")
	return cmd
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show who this client is signed in as, and with what",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()

			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.Me(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			me := res.Value
			termio.Section(me.Username)
			termio.KV("server", c.Server())
			// me.Role arrives already capped to the token's role, so the account's
			// own role has to come from the auth block or it would read as "user"
			// for an administrator holding a scoped token.
			accountRole := me.Auth.AccountRole
			if accountRole == "" {
				accountRole = me.Role
			}
			termio.KV("account role", accountRole)
			termio.KV("source", me.Source)
			if me.DisplayName != "" {
				termio.KV("display name", me.DisplayName)
			}
			if me.Email != "" {
				termio.KV("email", me.Email)
			}
			termio.KV("authenticated by", me.Auth.Method)
			// The effective role is what actually governs this session: an
			// admin using a user-scoped token is a user until they use another.
			termio.KV("effective role", me.Auth.Role)
			if me.Auth.TokenName != "" {
				termio.KV("token", fmt.Sprintf("%s (#%d)", me.Auth.TokenName, me.Auth.TokenID))
			}
			if me.Auth.ExpiresAt != nil {
				left := time.Until(*me.Auth.ExpiresAt)
				termio.KV("token expires", fmt.Sprintf("%s (%d days)",
					me.Auth.ExpiresAt.Local().Format("2006-01-02 15:04"), int(left.Hours()/24)))
				if left < 7*24*time.Hour {
					termio.Warn("this token expires in under a week; run `gocactl login` to renew it")
				}
			}
			if me.Auth.Role != accountRole {
				termio.Info("this token is scoped below your account role, so admin actions will be refused")
			}
			return nil
		},
	}
}
