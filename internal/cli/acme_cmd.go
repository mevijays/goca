package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/acme"
)

// newACMECmd groups goca's ACME (RFC 8555) support: managing the External
// Account Binding credentials that are the entire trust decision for this
// server's EAB-only implementation, and inspecting what has registered with
// them. The protocol itself is served at /acme/* by `goca run web` - there is
// no CLI equivalent for issuing through ACME, since that's the ACME client's
// job (cert-manager, certbot, acme.sh, ...), not an operator's.
func newACMECmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "Manage ACME (RFC 8555) access: External Account Binding credentials",
		Long: strings.TrimSpace(`
goca's ACME server is EAB-only: there is no HTTP-01/DNS-01 challenge
validation, because for a private CA the point of ACME is automation, not
proving domain ownership to the public internet. An EAB credential is the
entire trust decision - it binds accounts bootstrapped with it to one CA, one
certificate profile, an optional set of allowed domains, and an optional
account limit.

See docs/acme-eab.md for the full walkthrough, including a cert-manager
ClusterIssuer example.`),
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
	cmd.AddCommand(
		newACMEEABCreateCmd(),
		newACMEEABListCmd(),
		newACMEEABShowCmd(),
		newACMEEABDisableCmd(),
		newACMEEABDeleteCmd(),
	)
	return cmd
}

func newACMEEABCreateCmd() *cobra.Command {
	var (
		caRef          string
		profile        string
		days           int
		allowedDomains []string
		maxAccounts    int
		expiresInDays  int
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an EAB credential",
		Long: strings.TrimSpace(`
Generates a public keyID and a secret HMAC key. The HMAC key is printed once,
here - only its encrypted form is stored, the same way private keys are.

Everything an ACME account bootstrapped with this credential is allowed to do
is decided here, not negotiated per request: which authority signs its
certificates, what profile, and optionally which domains it may request and
how many accounts may ever be created with it.`),
		Example: strings.TrimSpace(`
  goca acme eab create cluster-a --ca acme-issuing-ca --allowed-domain '*.svc.cluster-a.internal'
  goca acme eab create cluster-b --profile server --days 90 --max-accounts 1
  goca acme eab create shared --allowed-domain '*.internal.lab' --allowed-domain '*.corp.lab'`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)

			res, err := svc.CreateEAB(cmd.Context(), acme.CreateEABInput{
				Name:           args[0],
				CARef:          caRef,
				Profile:        profile,
				Days:           days,
				AllowedDomains: allowedDomains,
				MaxAccounts:    maxAccounts,
				ExpiresInDays:  expiresInDays,
				Actor:          a.actor(),
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{"credential": res.Cred, "hmac_key": res.HMACKeyB64})
			}

			section("EAB credential created")
			kv("name", res.Cred.Name)
			kv("key id", res.Cred.KeyID)
			if len(res.Cred.AllowedDomains) > 0 {
				kv("allowed domains", strings.Join(res.Cred.AllowedDomains, ", "))
			} else {
				kv("allowed domains", "any (unrestricted)")
			}
			if res.Cred.CAID != nil {
				kv("authority", fmt.Sprint(*res.Cred.CAID))
			} else {
				kv("authority", "default issuing CA")
			}
			kv("profile", res.Cred.Profile)
			fmt.Println()
			fmt.Printf("  \033[1mHMAC key: %s\033[0m\n", res.HMACKeyB64)
			fmt.Println()
			warn("this key is shown once; store it in your cert-manager Secret now")
			info("see: goca acme eab show %s   (or docs/acme-eab.md for the ClusterIssuer YAML)", res.Cred.KeyID)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&caRef, "ca", "", "authority accounts issue from (default: the default issuing CA)")
	fl.StringVar(&profile, "profile", "server", "certificate profile for accounts bootstrapped with this credential")
	fl.IntVar(&days, "days", 0, "certificate validity in days (default: the authority/global default)")
	fl.StringSliceVar(&allowedDomains, "allowed-domain", nil,
		"glob pattern an order's identifiers must match (repeatable); default: unrestricted")
	fl.IntVar(&maxAccounts, "max-accounts", 0, "cap on accounts bootstrapped with this credential (0 = unlimited)")
	fl.IntVar(&expiresInDays, "expires-in-days", 0, "disable this credential automatically after N days (0 = never)")
	return cmd
}

func newACMEEABListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List EAB credentials",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			creds, err := svc.ListEAB(cmd.Context())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(creds)
			}
			if len(creds) == 0 {
				fmt.Println("No EAB credentials yet. Create one with `goca acme eab create <name>`.")
				return nil
			}
			t := newTable("id", "name", "key id", "authority", "profile", "domains", "accounts", "state")
			for _, c := range creds {
				ca := "default"
				if c.CAID != nil {
					ca = fmt.Sprint(*c.CAID)
				}
				domains := "any"
				if len(c.AllowedDomains) > 0 {
					domains = strings.Join(c.AllowedDomains, ",")
				}
				accounts := fmt.Sprint(c.AccountCount)
				if c.MaxAccounts > 0 {
					accounts = fmt.Sprintf("%d/%d", c.AccountCount, c.MaxAccounts)
				}
				state := "active"
				if c.Disabled {
					state = "disabled"
				} else if c.ExpiresAt != nil && !c.Usable() {
					state = "expired"
				}
				t.row(c.ID, c.Name, c.KeyID, ca, c.Profile, truncate(domains, 30), accounts, state)
			}
			t.flush()
			return nil
		},
	}
}

func newACMEEABShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id|key-id>",
		Short: "Show one EAB credential in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			c, err := svc.ResolveEAB(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(c)
			}
			section(c.Name)
			kv("id", c.ID)
			kv("key id", c.KeyID)
			if c.CAID != nil {
				kv("authority", fmt.Sprint(*c.CAID))
			} else {
				kv("authority", "default issuing CA (resolved per order)")
			}
			kv("profile", c.Profile)
			if c.Days > 0 {
				kv("certificate validity", fmt.Sprintf("%d days", c.Days))
			} else {
				kv("certificate validity", "authority/global default")
			}
			if len(c.AllowedDomains) > 0 {
				kv("allowed domains", strings.Join(c.AllowedDomains, ", "))
			} else {
				kv("allowed domains", "any (unrestricted)")
			}
			if c.MaxAccounts > 0 {
				kv("accounts", fmt.Sprintf("%d / %d", c.AccountCount, c.MaxAccounts))
			} else {
				kv("accounts", fmt.Sprintf("%d (unlimited)", c.AccountCount))
			}
			state := "active"
			if c.Disabled {
				state = "disabled"
			}
			kv("state", state)
			if c.ExpiresAt != nil {
				kv("expires", c.ExpiresAt.Format("2006-01-02"))
			}
			kv("created", fmt.Sprintf("%s by %s", c.CreatedAt.Format("2006-01-02 15:04"), c.CreatedBy))
			if c.LastUsedAt != nil {
				kv("last used", c.LastUsedAt.Format("2006-01-02 15:04"))
			}
			return nil
		},
	}
}

func newACMEEABDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <id|key-id>",
		Short: "Disable (or with --enable, re-enable) an EAB credential",
		Long: strings.TrimSpace(`
Disabling a credential stops it bootstrapping new ACME accounts. Accounts it
already created keep working - from registration onward they authenticate
with their own key, not the EAB secret - so this does not interrupt an
existing cert-manager ClusterIssuer's renewals. Delete the credential (once
unused) to remove it entirely.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			c, err := svc.ResolveEAB(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := svc.SetEABDisabled(cmd.Context(), c.ID, !enable, a.actor()); err != nil {
				return err
			}
			if enable {
				ok("%s is enabled", c.Name)
			} else {
				ok("%s is disabled", c.Name)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable instead of disabling")
	return cmd
}

func newACMEEABDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id|key-id>",
		Aliases: []string{"rm"},
		Short:   "Delete an EAB credential",
		Long: strings.TrimSpace(`
Refuses while any ACME account was bootstrapped with it, so history is never
silently lost - disable it instead, or remove those accounts first.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			c, err := svc.ResolveEAB(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", c.Name)
				}
				if !askYesNo(fmt.Sprintf("Delete EAB credential %q?", c.Name), false) {
					return nil
				}
			}
			if err := svc.DeleteEAB(cmd.Context(), c.ID, a.actor()); err != nil {
				return err
			}
			ok("deleted %q", c.Name)
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
	cmd.AddCommand(newACMEAccountsListCmd(), newACMEAccountsShowCmd())
	return cmd
}

func newACMEAccountsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List every registered ACME account",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			accounts, err := svc.ListAccounts(cmd.Context())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(accounts)
			}
			if len(accounts) == 0 {
				fmt.Println("No ACME accounts have registered yet.")
				return nil
			}
			t := newTable("id", "eab credential", "contact", "status", "registered", "last used")
			for _, acct := range accounts {
				lastUsed := "-"
				if acct.LastUsedAt != nil {
					lastUsed = acct.LastUsedAt.Local().Format("2006-01-02 15:04")
				}
				t.row(acct.ID, acct.EABName, strings.Join(acct.Contact, ","), acct.Status,
					acct.CreatedAt.Local().Format("2006-01-02 15:04"), lastUsed)
			}
			t.flush()
			return nil
		},
	}
}

func newACMEAccountsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show one ACME account and its orders",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			var id int64
			if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
				return fmt.Errorf("%q is not an account id (see `goca acme accounts list`)", args[0])
			}
			acct, err := svc.GetAccountByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			orders, err := svc.ListOrders(cmd.Context(), id)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{"account": acct, "orders": orders})
			}
			section(fmt.Sprintf("Account %d", acct.ID))
			kv("eab credential", acct.EABName)
			kv("contact", strings.Join(acct.Contact, ", "))
			kv("status", acct.Status)
			kv("registered", acct.CreatedAt.Format("2006-01-02 15:04"))
			if acct.LastUsedAt != nil {
				kv("last used", acct.LastUsedAt.Format("2006-01-02 15:04"))
			}
			if len(orders) > 0 {
				fmt.Println()
				fmt.Println("  Orders:")
				t := newTable("id", "status", "identifiers", "certificate", "created")
				for _, o := range orders {
					names := make([]string, 0, len(o.Identifiers))
					for _, id := range o.Identifiers {
						names = append(names, id.Value)
					}
					cert := "-"
					if o.CertificateID != nil {
						cert = fmt.Sprint(*o.CertificateID)
					}
					t.row(o.ID, o.Status, truncate(strings.Join(names, ","), 40), cert,
						o.CreatedAt.Local().Format("2006-01-02 15:04"))
				}
				t.flush()
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
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			svc := acme.New(a.svc)
			creds, err := svc.ListEAB(cmd.Context())
			if err != nil {
				return err
			}
			accounts, err := svc.ListAccounts(cmd.Context())
			if err != nil {
				return err
			}
			active := 0
			for _, c := range creds {
				if c.Usable() {
					active++
				}
			}
			if flagJSON {
				return printJSON(map[string]any{
					"directory_url": svc.DirectoryURL(),
					"credentials":   len(creds),
					"active":        active,
					"accounts":      len(accounts),
				})
			}
			section("ACME")
			kv("directory URL", svc.DirectoryURL())
			kv("EAB credentials", fmt.Sprintf("%d (%d usable)", len(creds), active))
			kv("registered accounts", len(accounts))
			if len(creds) == 0 {
				fmt.Println()
				info("no EAB credentials exist yet; create one with `goca acme eab create <name>`")
			}
			return nil
		},
	}
}

// truncate shortens a string for table display.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
