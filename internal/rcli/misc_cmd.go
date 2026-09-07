package rcli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

//
// ---------- users ----------
//

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user",
		Short:   "Manage portal accounts",
		Aliases: []string{"users"},
	}
	cmd.AddCommand(
		newUserListCmd(), newUserAddCmd(), newUserRoleCmd(),
		newUserPasswdCmd(), newUserDisableCmd(), newUserDeleteCmd(),
	)
	return cmd
}

func newUserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List portal accounts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListUsers(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			t := termio.NewTable("id", "username", "name", "email", "source", "role", "state", "last login")
			for _, u := range res.Value {
				state := "enabled"
				if u.Disabled {
					state = "disabled"
				}
				last := "-"
				if u.LastLogin != nil {
					last = u.LastLogin.Local().Format("2006-01-02 15:04")
				}
				t.Row(u.ID, u.Username, u.DisplayName, u.Email, u.Source, u.Role, state, last)
			}
			t.Flush()
			return nil
		},
	}
}

func newUserAddCmd() *cobra.Command {
	var (
		role, displayName, email string
		password                 string
		passwordStdin            bool
	)
	cmd := &cobra.Command{
		Use:   "add <username>",
		Short: "Create a local (password) account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			pw := password
			if pw == "" {
				var err error
				if pw, err = readPassword(passwordStdin); err != nil {
					return err
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateUser(ctx, args[0], pw, role, displayName, email)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created %s (%s)", res.Value.Username, res.Value.Role)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&role, "role", "user", "user or admin")
	fl.StringVar(&displayName, "display-name", "", "display name")
	fl.StringVar(&email, "email", "", "email address")
	fl.StringVar(&password, "password", "", "set the password non-interactively (visible in ps; prefer --password-stdin)")
	fl.BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	return cmd
}

func newUserRoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "role <username> <user|admin>",
		Short: "Change a user's role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if _, err := c.PatchUser(ctx, args[0], map[string]any{"role": args[1]}); err != nil {
				return err
			}
			termio.OK("%s is now %s", args[0], args[1])
			return nil
		},
	}
}

func newUserPasswdCmd() *cobra.Command {
	var passwordStdin bool
	cmd := &cobra.Command{
		Use:   "passwd <username>",
		Short: "Set a local account's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			pw, err := readPassword(passwordStdin)
			if err != nil {
				return err
			}
			c, err := client()
			if err != nil {
				return err
			}
			if _, err := c.PatchUser(ctx, args[0], map[string]any{"password": pw}); err != nil {
				return err
			}
			termio.OK("password updated for %s", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	return cmd
}

func newUserDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <username>",
		Short: "Disable (or with --enable, re-enable) an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if _, err := c.PatchUser(ctx, args[0], map[string]any{"disabled": !enable}); err != nil {
				return err
			}
			if enable {
				termio.OK("%s is enabled", args[0])
			} else {
				termio.OK("%s is disabled", args[0])
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable instead of disabling")
	return cmd
}

func newUserDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <username>",
		Aliases: []string{"rm"},
		Short:   "Delete a portal account",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", args[0])
				}
				if !termio.AskYesNo(fmt.Sprintf("Delete account %q?", args[0]), false) {
					return nil
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.DeleteUser(ctx, args[0]); err != nil {
				return err
			}
			termio.OK("deleted %s", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

//
// ---------- API tokens ----------
//

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token",
		Short:   "Manage API tokens",
		Aliases: []string{"tokens"},
	}
	cmd.AddCommand(newTokenListCmd(), newTokenCreateCmd(), newTokenRevokeCmd())
	return cmd
}

func newTokenListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List your API tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListTokens(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			t := termio.NewTable("id", "name", "prefix", "owner", "role", "expires", "last used", "state")
			for _, tok := range res.Value {
				exp := "never"
				if tok.ExpiresAt != nil {
					exp = tok.ExpiresAt.Format("2006-01-02")
				}
				last := "-"
				if tok.LastUsedAt != nil {
					last = tok.LastUsedAt.Local().Format("2006-01-02 15:04")
				}
				state := "active"
				if tok.Revoked {
					state = "revoked"
				}
				t.Row(tok.ID, tok.Name, "goca_"+tok.Prefix, tok.Username, tok.Role, exp, last, state)
			}
			t.Flush()
			return nil
		},
	}
}

func newTokenCreateCmd() *cobra.Command {
	var (
		role string
		days int
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint an API token",
		Long: strings.TrimSpace(`
The plaintext is printed once and only its hash is stored, so it cannot be
recovered later. A token's own role caps what it can do: an admin can mint a
user-scoped token for automation that should not administer anything.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateToken(ctx, args[0], role, days)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created token %q", args[0])
			fmt.Println()
			fmt.Printf("  \033[1m%v\033[0m\n", res.Value["token"])
			fmt.Println()
			termio.Warn("this token is shown once; store it now")
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&role, "role", "", "user or admin (default: your own role)")
	fl.IntVar(&days, "days", 365, "lifetime in days; 0 never expires")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a token id", args[0])
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.RevokeToken(ctx, id); err != nil {
				return err
			}
			termio.OK("revoked token %d", id)
			return nil
		},
	}
}

//
// ---------- audit ----------
//

func newAuditCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListAudit(ctx, limit)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("The audit log is empty.")
				return nil
			}
			t := termio.NewTable("when", "actor", "action", "target", "detail", "ip")
			for _, e := range res.Value {
				t.Row(e.TS.Local().Format("2006-01-02 15:04"), e.Actor, e.Action,
					truncate(e.Target, 30), truncate(e.Detail, 40), e.IP)
			}
			t.Flush()
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum entries")
	cmd.AddCommand(newAuditExportCmd())
	return cmd
}

// newAuditExportCmd streams the entire audit log (following cursor
// pagination) to stdout or a file as JSON or CSV, for off-box analysis and
// SIEM ingestion.
func newAuditExportCmd() *cobra.Command {
	var (
		format string
		out    string
		page   int
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the full audit log as JSON or CSV",
		Long: "Export the entire audit log, following cursor pagination, to stdout or a file.\n" +
			"Use --format json for a machine-readable array, or --format csv for a flat table.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if page <= 0 {
				page = 500
			}
			var all []gocaclient.AuditEntry
			cursor := ""
			for {
				res, err := c.ListAuditPage(ctx, cursor, page)
				if err != nil {
					return err
				}
				all = append(all, res.Value.Entries...)
				if res.Value.NextCursor == "" {
					break
				}
				cursor = res.Value.NextCursor
			}

			var w *os.File
			if out != "" {
				w, err = os.Create(out)
				if err != nil {
					return err
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			switch format {
			case "csv":
				cw := csv.NewWriter(w)
				if err := cw.Write([]string{"id", "ts", "actor", "action", "target", "detail", "ip"}); err != nil {
					return err
				}
				for _, e := range all {
					if err := cw.Write([]string{
						strconv.FormatInt(e.ID, 10),
						e.TS.UTC().Format("2006-01-02T15:04:05Z07:00"),
						e.Actor, e.Action, e.Target, e.Detail, e.IP,
					}); err != nil {
						return err
					}
				}
				cw.Flush()
				return cw.Error()
			case "json", "":
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				if err := enc.Encode(all); err != nil {
					return err
				}
				return nil
			default:
				return fmt.Errorf("unknown format %q (want json or csv)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "output format: json or csv")
	cmd.Flags().StringVarP(&out, "output", "o", "", "write to this file instead of stdout")
	cmd.Flags().IntVar(&page, "page-size", 500, "entries per page when paginating")
	return cmd
}

//
// ---------- ACME ----------
//

func newACMECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "Manage ACME access (External Account Binding credentials)",
	}
	cmd.AddCommand(newACMEEABCmd(), newACMEAccountsCmd(), newACMEStatusCmd())
	return cmd
}

func newACMEEABCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "eab",
		Short:   "Manage External Account Binding credentials",
		Aliases: []string{"credential", "credentials"},
	}
	cmd.AddCommand(newACMEEABCreateCmd(), newACMEEABListCmd(), newACMEEABDisableCmd(), newACMEEABDeleteCmd())
	return cmd
}

func newACMEEABCreateCmd() *cobra.Command {
	var (
		caRef, profile string
		days           int
		allowedDomains []string
		maxAccounts    int
		expiresInDays  int
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an EAB credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateEAB(ctx, gocaclient.CreateEABInput{
				Name: args[0], CARef: caRef, Profile: profile, Days: days,
				AllowedDomains: allowedDomains, MaxAccounts: maxAccounts,
				ExpiresInDays: expiresInDays,
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.Section("EAB credential created")
			termio.KV("name", res.Value.Cred.Name)
			termio.KV("key id", res.Value.Cred.KeyID)
			if len(res.Value.Cred.AllowedDomains) > 0 {
				termio.KV("allowed domains", strings.Join(res.Value.Cred.AllowedDomains, ", "))
			} else {
				termio.KV("allowed domains", "any (unrestricted)")
			}
			fmt.Println()
			fmt.Printf("  \033[1mHMAC key: %s\033[0m\n", res.Value.HMACKeyB64)
			fmt.Println()
			termio.Warn("this key is shown once; store it in your cert-manager Secret now")
			termio.Info("directory URL: %s", c.ACMEDirectoryURL())
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&caRef, "ca", "", "authority accounts issue from")
	fl.StringVar(&profile, "profile", "server", "certificate profile")
	fl.IntVar(&days, "days", 0, "certificate validity in days")
	fl.StringSliceVar(&allowedDomains, "allowed-domain", nil, "glob pattern an order must match (repeatable)")
	fl.IntVar(&maxAccounts, "max-accounts", 0, "cap on accounts bootstrapped with it (0 = unlimited)")
	fl.IntVar(&expiresInDays, "expires-in-days", 0, "auto-disable after N days (0 = never)")
	return cmd
}

func newACMEEABListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List EAB credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListEAB(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No EAB credentials yet. Create one with `gocactl acme eab create <name>`.")
				return nil
			}
			t := termio.NewTable("id", "name", "key id", "authority", "profile", "domains", "accounts", "state")
			for _, e := range res.Value {
				ca := "default"
				if e.CAID != nil {
					ca = fmt.Sprint(*e.CAID)
				}
				domains := "any"
				if len(e.AllowedDomains) > 0 {
					domains = strings.Join(e.AllowedDomains, ",")
				}
				accounts := fmt.Sprint(e.AccountCount)
				if e.MaxAccounts > 0 {
					accounts = fmt.Sprintf("%d/%d", e.AccountCount, e.MaxAccounts)
				}
				state := "active"
				if e.Disabled {
					state = "disabled"
				} else if !e.Usable() {
					state = "expired"
				}
				t.Row(e.ID, e.Name, e.KeyID, ca, e.Profile, truncate(domains, 30), accounts, state)
			}
			t.Flush()
			return nil
		},
	}
}

func newACMEEABDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable (or with --enable, re-enable) an EAB credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a credential id", args[0])
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.SetEABDisabled(ctx, id, !enable); err != nil {
				return err
			}
			termio.OK("credential %d is now %s", id, map[bool]string{true: "enabled", false: "disabled"}[enable])
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable instead of disabling")
	return cmd
}

func newACMEEABDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"rm"},
		Short:   "Delete an EAB credential",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a credential id", args[0])
			}
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to delete credential %d non-interactively; pass --yes", id)
				}
				if !termio.AskYesNo(fmt.Sprintf("Delete EAB credential %d?", id), false) {
					return nil
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.DeleteEAB(ctx, id); err != nil {
				return err
			}
			termio.OK("deleted credential %d", id)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newACMEAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "Inspect registered ACME accounts",
	}
	cmd.AddCommand(&cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every registered ACME account",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListACMEAccounts(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No ACME accounts have registered yet.")
				return nil
			}
			t := termio.NewTable("id", "eab credential", "contact", "status", "registered", "last used")
			for _, a := range res.Value {
				last := "-"
				if a.LastUsedAt != nil {
					last = a.LastUsedAt.Local().Format("2006-01-02 15:04")
				}
				t.Row(a.ID, a.EABName, strings.Join(a.Contact, ","), a.Status,
					a.CreatedAt.Local().Format("2006-01-02 15:04"), last)
			}
			t.Flush()
			return nil
		},
	})
	cmd.AddCommand(newACMEAccountsShowCmd())
	return cmd
}

func newACMEAccountsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show one ACME account and its orders",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not an account id (see `gocactl acme accounts list`)", args[0])
			}
			c, err := client()
			if err != nil {
				return err
			}
			acct, err := c.GetACMEAccount(ctx, id)
			if err != nil {
				return err
			}
			orders, err := c.ACMEAccountOrders(ctx, id)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintJSON(map[string]any{"account": acct.Value, "orders": orders.Value})
			}
			a := acct.Value
			termio.Section(fmt.Sprintf("Account %d", a.ID))
			termio.KV("eab credential", a.EABName)
			termio.KV("contact", strings.Join(a.Contact, ", "))
			termio.KV("status", a.Status)
			termio.KV("registered", a.CreatedAt.Format("2006-01-02 15:04"))
			if a.LastUsedAt != nil {
				termio.KV("last used", a.LastUsedAt.Format("2006-01-02 15:04"))
			}
			if len(orders.Value) > 0 {
				fmt.Println()
				fmt.Println("  Orders:")
				t := termio.NewTable("id", "status", "identifiers", "certificate", "created")
				for _, o := range orders.Value {
					names := make([]string, 0, len(o.Identifiers))
					for _, ident := range o.Identifiers {
						names = append(names, ident.Value)
					}
					cert := "-"
					if o.CertificateID != nil {
						cert = fmt.Sprint(*o.CertificateID)
					}
					t.Row(o.ID, o.Status, truncate(strings.Join(names, ","), 40), cert,
						o.CreatedAt.Local().Format("2006-01-02 15:04"))
				}
				t.Flush()
			}
			return nil
		},
	}
}

func newACMEStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the ACME directory URL and a quick summary",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			creds, err := c.ListEAB(ctx)
			if err != nil {
				return err
			}
			accounts, err := c.ListACMEAccounts(ctx)
			if err != nil {
				return err
			}
			active := 0
			for _, cr := range creds.Value {
				if cr.Usable() {
					active++
				}
			}
			if flagJSON {
				return termio.PrintJSON(map[string]any{
					"directory_url": c.ACMEDirectoryURL(),
					"credentials":   len(creds.Value),
					"active":        active,
					"accounts":      len(accounts.Value),
				})
			}
			termio.Section("ACME")
			termio.KV("directory URL", c.ACMEDirectoryURL())
			termio.KV("EAB credentials", fmt.Sprintf("%d (%d usable)", len(creds.Value), active))
			termio.KV("registered accounts", len(accounts.Value))
			return nil
		},
	}
}
