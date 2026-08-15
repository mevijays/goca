package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/auth"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

//
// ---------- csr ----------
//

func newCSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Generate certificate signing requests",
	}
	cmd.AddCommand(newCSRNewCmd())
	return cmd
}

func newCSRNewCmd() *cobra.Command {
	var (
		cn, org, ou                 string
		country, province, locality string
		sans                        []string
		keyType                     string
		outDir, csrOut, keyOut      string
		wizard                      bool
	)
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a private key and CSR without signing anything",
		Long: strings.TrimSpace(`
Produces a key and a CSR, exactly like ` + "`openssl req -new`" + `, and stores
neither. Sign it later with ` + "`goca cert sign`" + `, the portal, the API, or
an entirely different CA.`),
		Example: strings.TrimSpace(`
  goca csr new --common-name app.internal.lan --san app.internal.lan --out ./req
  goca csr new --common-name app.internal.lan --csr-out app.csr --key-out app.key`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if wizard || (cn == "" && interactive()) {
				section("New certificate signing request")
				cn = askRequired("Common name (CN)", cn)
				if len(sans) == 0 {
					if v := ask("Subject alternative names (comma separated)", cn); v != "" {
						sans = splitCSV(v)
					}
				}
				org = ask("Organization (O)", org)
				ou = ask("Organizational unit (OU)", ou)
				country = ask("Country code (C)", country)
				types := make([]string, len(pki.KeyTypes))
				for i, k := range pki.KeyTypes {
					types[i] = string(k)
				}
				keyType = askChoice("Key type", types, firstNonEmpty(keyType, a.cfg.CA.DefaultKeyType, "rsa-2048"))
				if outDir == "" && csrOut == "" {
					outDir = ask("Write files to this directory (blank = print here)", "")
				}
			}

			res, err := a.svc.GenerateCSR(cmd.Context(), ca.GenerateCSRInput{
				Subject: pki.Subject{
					CommonName: cn, Organization: org, OrganizationalUnit: ou,
					Country: country, Province: province, Locality: locality,
				},
				SANs:    sans,
				KeyType: keyType,
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(res)
			}

			base := safeName(cn)
			wrote := false
			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o750); err != nil {
					return err
				}
				if err := writeOut(filepath.Join(outDir, base+".key"), []byte(res.PrivateKeyPEM), 0o600); err != nil {
					return err
				}
				if err := writeOut(filepath.Join(outDir, base+".csr"), []byte(res.CSRPEM), 0o644); err != nil {
					return err
				}
				wrote = true
			}
			if keyOut != "" {
				if err := writeOut(keyOut, []byte(res.PrivateKeyPEM), 0o600); err != nil {
					return err
				}
				wrote = true
			}
			if csrOut != "" {
				if err := writeOut(csrOut, []byte(res.CSRPEM), 0o644); err != nil {
					return err
				}
				wrote = true
			}

			section("Request created")
			kv("subject", res.Info.Subject)
			if len(res.Info.SANs) > 0 {
				kv("SANs", strings.Join(res.Info.SANs, ", "))
			}
			kv("key type", res.KeyType)
			if !wrote {
				fmt.Println()
				fmt.Print(res.PrivateKeyPEM)
				fmt.Print(res.CSRPEM)
			}
			fmt.Println()
			warn("this key is not stored anywhere; keep the copy above safe")
			info("sign it with: goca cert sign --csr %s.csr", base)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&cn, "common-name", "", "subject common name (CN)")
	fl.StringVar(&org, "organization", "", "subject organization (O)")
	fl.StringVar(&ou, "organizational-unit", "", "subject organizational unit (OU)")
	fl.StringVar(&country, "country", "", "subject country code (C)")
	fl.StringVar(&province, "province", "", "subject state or province (ST)")
	fl.StringVar(&locality, "locality", "", "subject locality (L)")
	fl.StringSliceVar(&sans, "san", nil, "subject alternative name; repeatable")
	fl.StringVar(&keyType, "key-type", "", "rsa-2048|rsa-3072|rsa-4096|ec-p256|ec-p384|ec-p521|ed25519")
	fl.StringVar(&outDir, "out", "", "directory to write the key and CSR into")
	fl.StringVar(&csrOut, "csr-out", "", "write the CSR to this file")
	fl.StringVar(&keyOut, "key-out", "", "write the private key to this file")
	fl.BoolVar(&wizard, "wizard", false, "prompt for every field")
	return cmd
}

//
// ---------- inspect ----------
//

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Describe a certificate or CSR from a PEM file",
		Long: strings.TrimSpace(`
Parses a PEM certificate or certificate signing request and prints a summary.
Works on anything, not only files goca produced.`),
		Example: strings.TrimSpace(`
  goca inspect server.crt
  goca inspect app.csr
  openssl s_client -connect example.com:443 </dev/null 2>/dev/null | goca inspect -`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readFileOrStdin(args[0])
			if err != nil {
				return err
			}
			if strings.Contains(string(data), "CERTIFICATE REQUEST") {
				csr, err := pki.ParseCSR(data)
				if err != nil {
					return err
				}
				desc := pki.DescribeCSR(csr)
				if flagJSON {
					return printJSON(desc)
				}
				section("Certificate signing request")
				kv("subject", desc.Subject)
				kv("common name", desc.CommonName)
				if len(desc.SANs) > 0 {
					kv("SANs", strings.Join(desc.SANs, ", "))
				}
				kv("key type", desc.KeyType)
				kv("signature", desc.SignatureAlgorithm)
				return nil
			}
			cert, err := pki.ParseCertPEM(data)
			if err != nil {
				return err
			}
			info := pki.Describe(cert)
			if flagJSON {
				return printJSON(info)
			}
			section("Certificate")
			kv("subject", info.Subject)
			kv("issuer", info.Issuer)
			kv("serial", info.Serial)
			if len(info.SANs) > 0 {
				kv("SANs", strings.Join(info.SANs, ", "))
			}
			kv("is CA", info.IsCA)
			kv("key type", info.KeyType)
			kv("signature", info.SignatureAlgorithm)
			kv("key usage", strings.Join(info.KeyUsage, ", "))
			kv("extended key usage", strings.Join(info.ExtKeyUsage, ", "))
			kv("valid from", info.NotBefore.Format("2006-01-02 15:04 MST"))
			kv("valid until", fmt.Sprintf("%s (%d days left)",
				info.NotAfter.Format("2006-01-02"), info.DaysRemaining))
			if len(info.CRLDistPoints) > 0 {
				kv("CRL URLs", strings.Join(info.CRLDistPoints, ", "))
			}
			kv("SHA-256", info.FingerprintSHA256)
			return nil
		},
	}
}

//
// ---------- users ----------
//

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage portal accounts",
	}
	cmd.AddCommand(
		newUserAddCmd(), newUserListCmd(), newUserRoleCmd(),
		newUserPasswdCmd(), newUserDisableCmd(), newUserDeleteCmd(),
	)
	return cmd
}

func newUserAddCmd() *cobra.Command {
	var password, displayName, email, role string
	cmd := &cobra.Command{
		Use:   "add <username>",
		Short: "Create a local (password) account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			generated := false
			if password == "" {
				if interactive() {
					pw, err := askPassword("Password", true)
					if err != nil {
						return err
					}
					password = pw
				} else {
					pw, err := auth.GeneratePassword(20)
					if err != nil {
						return err
					}
					password = pw
					generated = true
				}
			}
			u, err := a.auth.CreateLocalUser(cmd.Context(), args[0], password, displayName, email, role)
			if err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "user.create", u.Username, "role="+u.Role, "")
			if flagJSON {
				out := map[string]any{"user": u}
				if generated {
					out["password"] = password
				}
				return printJSON(out)
			}
			ok("created %s (%s)", u.Username, u.Role)
			if generated {
				fmt.Printf("  generated password: %s\n", password)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "password (prompted, or generated when non-interactive)")
	cmd.Flags().StringVar(&displayName, "display-name", "", "display name")
	cmd.Flags().StringVar(&email, "email", "", "email address")
	cmd.Flags().StringVar(&role, "role", "user", "user or admin")
	return cmd
}

func newUserListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List portal accounts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			users, err := a.svc.Store().ListUsers(cmd.Context())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(users)
			}
			if len(users) == 0 {
				fmt.Println("No users yet.")
				return nil
			}
			t := newTable("id", "username", "name", "email", "source", "role", "state", "last login")
			for _, u := range users {
				state := "enabled"
				if u.Disabled {
					state = "disabled"
				}
				last := "-"
				if u.LastLogin != nil {
					last = u.LastLogin.Local().Format("2006-01-02 15:04")
				}
				t.row(u.ID, u.Username, u.DisplayName, u.Email, u.Source, u.Role, state, last)
			}
			t.flush()
			return nil
		},
	}
}

func newUserRoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "role <username> <user|admin>",
		Short: "Change a user's role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			u, err := a.svc.Store().GetUserByName(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			role := args[1]
			if role != store.RoleAdmin && role != store.RoleUser {
				return fmt.Errorf("role must be %q or %q", store.RoleUser, store.RoleAdmin)
			}
			if err := a.svc.Store().SetUserRole(cmd.Context(), u.ID, role); err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "user.role", u.Username, role, "")
			ok("%s is now %s", u.Username, role)
			return nil
		},
	}
}

func newUserPasswdCmd() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "passwd <username>",
		Short: "Set a local account's password",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			u, err := a.svc.Store().GetUserByName(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if password == "" {
				pw, err := askPassword("New password", true)
				if err != nil {
					return err
				}
				password = pw
			}
			if err := a.auth.SetPassword(cmd.Context(), u, password); err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "user.password_change", u.Username, "cli", "")
			ok("password updated for %s", u.Username)
			return nil
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "new password (prompted when omitted)")
	return cmd
}

func newUserDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <username>",
		Short: "Disable (or with --enable, re-enable) an account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			u, err := a.svc.Store().GetUserByName(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.svc.Store().SetUserDisabled(cmd.Context(), u.ID, !enable); err != nil {
				return err
			}
			if !enable {
				_ = a.svc.Store().DeleteUserSessions(cmd.Context(), u.ID)
			}
			state := "disabled"
			if enable {
				state = "enabled"
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "user.disable", u.Username, state, "")
			ok("%s is now %s", u.Username, state)
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
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			u, err := a.svc.Store().GetUserByName(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !yes && interactive() && !askYesNo(fmt.Sprintf("Delete user %s?", u.Username), false) {
				return nil
			}
			if err := a.svc.Store().DeleteUser(cmd.Context(), u.ID); err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "user.delete", u.Username, "", "")
			ok("deleted %s", u.Username)
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
		Use:   "token",
		Short: "Manage REST API tokens",
	}
	cmd.AddCommand(newTokenCreateCmd(), newTokenListCmd(), newTokenRevokeCmd())
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	var owner, role string
	var days int
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Mint a bearer token for the REST API",
		Long: strings.TrimSpace(`
The plaintext token is printed once. Only its hash is stored, so it cannot be
recovered later - mint a new one if it is lost.`),
		Example: strings.TrimSpace(`
  goca token create ansible --role admin --days 365
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/cas`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if owner == "" {
				owner = a.cfg.Auth.LocalAdmin.Username
			}
			u, err := a.svc.Store().GetUserByName(cmd.Context(), owner)
			if err != nil {
				return fmt.Errorf("owner %q: %w", owner, err)
			}
			if days < 0 {
				return fmt.Errorf("--days must be 0 (never expires) or positive")
			}
			var ttl time.Duration
			if days > 0 {
				ttl = time.Duration(days) * 24 * time.Hour
			}
			plaintext, rec, err := a.auth.IssueAPIToken(cmd.Context(), u, args[0], role, ttl)
			if err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "token.create", rec.Name, "role="+rec.Role, "")
			if flagJSON {
				return printJSON(map[string]any{"token": plaintext, "record": rec})
			}
			section("API token created")
			kv("name", rec.Name)
			kv("owner", u.Username)
			kv("role", rec.Role)
			if rec.ExpiresAt != nil {
				kv("expires", rec.ExpiresAt.Format("2006-01-02"))
			} else {
				kv("expires", "never")
			}
			fmt.Println()
			fmt.Printf("  \033[1m%s\033[0m\n", plaintext)
			fmt.Println()
			warn("this is the only time the token is shown")
			return nil
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "account that owns the token (default: the local administrator)")
	cmd.Flags().StringVar(&role, "role", "", "user or admin (default: the owner's role)")
	cmd.Flags().IntVar(&days, "days", 365, "lifetime in days; 0 means never expires")
	return cmd
}

func newTokenListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List API tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			tokens, err := a.auth.ListAPITokens(cmd.Context(), 0)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(tokens)
			}
			if len(tokens) == 0 {
				fmt.Println("No API tokens yet.")
				return nil
			}
			t := newTable("id", "name", "prefix", "owner", "role", "expires", "last used", "state")
			for _, tok := range tokens {
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
				t.row(tok.ID, tok.Name, "goca_"+tok.Prefix, tok.Username, tok.Role, exp, last, state)
			}
			t.flush()
			return nil
		},
	}
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			var id int64
			if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
				return fmt.Errorf("%q is not a token id (see `goca token list`)", args[0])
			}
			if err := a.auth.RevokeAPIToken(cmd.Context(), id); err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "token.revoke", args[0], "", "")
			ok("token %s revoked", args[0])
			return nil
		},
	}
}

//
// ---------- ldap ----------
//

func newLDAPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ldap",
		Short: "Test and inspect the directory configuration",
	}
	cmd.AddCommand(newLDAPTestCmd(), newLDAPLoginTestCmd())
	return cmd
}

func newLDAPTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Check connectivity, the service bind and the search base",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if !a.auth.LDAPEnabled() {
				return fmt.Errorf("LDAP is not enabled; re-run `goca setup` or edit %s", a.cfg.Path)
			}
			section("LDAP")
			kv("url", a.cfg.Auth.LDAP.URL)
			kv("bind DN", firstNonEmpty(a.cfg.Auth.LDAP.BindDN, "(anonymous)"))
			kv("base DN", a.cfg.Auth.LDAP.BaseDN)
			kv("user filter", a.cfg.Auth.LDAP.UserFilter)
			fmt.Println()
			if err := a.auth.LDAP().TestConnection(cmd.Context()); err != nil {
				return err
			}
			ok("connection, bind and search base all check out")
			return nil
		},
	}
}

func newLDAPLoginTestCmd() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "login <username>",
		Short: "Try a full directory login and show the resulting identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if !a.auth.LDAPEnabled() {
				return fmt.Errorf("LDAP is not enabled")
			}
			if password == "" {
				pw, err := askPassword("Password for "+args[0], false)
				if err != nil {
					return err
				}
				password = pw
			}
			id, err := a.auth.LDAP().Authenticate(cmd.Context(), args[0], password)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(id)
			}
			section("Directory identity")
			kv("username", id.Username)
			kv("DN", id.DN)
			kv("display name", id.DisplayName)
			kv("email", id.Email)
			kv("groups", strings.Join(id.Groups, ", "))
			kv("would be admin", id.IsAdmin)
			return nil
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "password (prompted when omitted)")
	return cmd
}
