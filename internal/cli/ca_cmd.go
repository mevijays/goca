package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ca",
		Short:   "Manage certificate authorities",
		Aliases: []string{"authority"},
	}
	cmd.AddCommand(
		newCACreateCmd(),
		newCAListCmd(),
		newCAShowCmd(),
		newCAExportCmd(),
		newCADefaultCmd(),
		newCAStatusCmd(),
		newCADeleteCmd(),
		newCACRLCmd(),
		// Running underneath an authority goca does not own.
		newCASubordinateCmd(),
		newCAImportSignedCmd(),
		newCAImportCmd(),
		newCAPendingCmd(),
		newCARevokeCmd(),
	)
	return cmd
}

func newCACreateCmd() *cobra.Command {
	var (
		wizard      bool
		name        string
		cn, org, ou string
		country     string
		province    string
		locality    string
		keyType     string
		days        int
		parent      string
		pathLen     int
		crlURLs     []string
		ocspURLs    []string
		permitted   []string
		makeDefault bool
		exportDir   string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a root or intermediate certificate authority",
		Long: strings.TrimSpace(`
Generates a key pair and a CA certificate, then stores both in the database.
The private key is encrypted with the server master key from the config file.

Without --parent the CA is a self-signed root. With --parent it is signed by an
existing authority, which keeps the root available for offline storage.`),
		Example: strings.TrimSpace(`
  # Guided
  goca ca create --wizard

  # Root CA
  goca ca create --name "Acme Root CA" --common-name "Acme Root CA" \
      --organization Acme --country IN --key-type rsa-4096 --days 3650

  # Intermediate under it
  goca ca create --name "Acme Issuing CA" --common-name "Acme Issuing CA" \
      --parent acme-root-ca --days 1825 --path-len 0`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()

			in := ca.CreateCAInput{
				Name: name,
				Subject: pki.Subject{
					CommonName: cn, Organization: org, OrganizationalUnit: ou,
					Country: country, Province: province, Locality: locality,
				},
				KeyType:       keyType,
				Days:          days,
				ParentRef:     parent,
				PathLen:       pathLen,
				CRLDistPoints: crlURLs,
				OCSPServers:   ocspURLs,
				PermittedDNS:  permitted,
				MakeDefault:   makeDefault,
				Actor:         a.actor(),
			}

			if wizard || (in.Subject.CommonName == "" && interactive()) {
				if err := caWizard(ctx, a, &in); err != nil {
					return err
				}
			}

			created, err := a.svc.CreateCA(ctx, in)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(created)
			}

			section("Authority created")
			printCASummary(created)
			if a.cfg.Server.BaseURL != "" {
				info("public certificate: %s/public/ca/%s.crt", a.cfg.Server.BaseURL, created.Slug)
			}

			if exportDir != "" {
				if err := exportCA(ctx, a, created, exportDir, true); err != nil {
					return err
				}
			}
			return nil
		},
	}

	fl := cmd.Flags()
	fl.BoolVar(&wizard, "wizard", false, "prompt for every field")
	fl.StringVar(&name, "name", "", "display name (defaults to the common name)")
	fl.StringVar(&cn, "common-name", "", "subject common name (CN)")
	fl.StringVar(&org, "organization", "", "subject organization (O)")
	fl.StringVar(&ou, "organizational-unit", "", "subject organizational unit (OU)")
	fl.StringVar(&country, "country", "", "subject country code (C)")
	fl.StringVar(&province, "province", "", "subject state or province (ST)")
	fl.StringVar(&locality, "locality", "", "subject locality (L)")
	fl.StringVar(&keyType, "key-type", "", "rsa-2048|rsa-3072|rsa-4096|ec-p256|ec-p384|ec-p521|ed25519")
	fl.IntVar(&days, "days", 0, "validity in days (default: the configured CA default)")
	fl.StringVar(&parent, "parent", "", "id, slug or name of the signing authority (blank = self-signed root)")
	fl.IntVar(&pathLen, "path-len", 1, "how many CA levels may sit below this one")
	fl.StringSliceVar(&crlURLs, "crl-url", nil, "CRL distribution point to embed in issued certificates")
	fl.StringSliceVar(&ocspURLs, "ocsp-url", nil, "OCSP responder URL to embed in issued certificates")
	fl.StringSliceVar(&permitted, "permitted-dns", nil, "restrict this CA to these DNS domains (name constraint)")
	fl.BoolVar(&makeDefault, "default", false, "make this the default issuing authority")
	fl.StringVar(&exportDir, "export", "", "also write the certificate, chain and key to this directory")
	return cmd
}

func caWizard(ctx context.Context, a *app, in *ca.CreateCAInput) error {
	existing, _ := a.svc.ListCAs(ctx)

	section("New certificate authority")
	if len(existing) > 0 {
		kind := askChoice("Authority type", []string{"root", "intermediate"}, "root")
		if kind == "intermediate" {
			fmt.Println("  Available parents:")
			for _, c := range existing {
				fmt.Printf("    %d) %s (%s, expires %s)\n", c.ID, c.Name, c.Slug,
					c.NotAfter.Format("2006-01-02"))
			}
			in.ParentRef = askRequired("  Parent authority (id, slug or name)", fmt.Sprint(existing[0].ID))
		}
	}
	in.Subject.CommonName = askRequired("Common name (CN)", firstNonEmpty(in.Subject.CommonName, "goca Root CA"))
	in.Name = ask("Display name", firstNonEmpty(in.Name, in.Subject.CommonName))
	in.Subject.Organization = ask("Organization (O)", in.Subject.Organization)
	in.Subject.OrganizationalUnit = ask("Organizational unit (OU)", in.Subject.OrganizationalUnit)
	in.Subject.Country = ask("Country code (C)", in.Subject.Country)
	in.Subject.Province = ask("State / province (ST)", in.Subject.Province)
	in.Subject.Locality = ask("Locality (L)", in.Subject.Locality)

	types := make([]string, len(pki.KeyTypes))
	for i, k := range pki.KeyTypes {
		types[i] = string(k)
	}
	in.KeyType = askChoice("Key type", types, firstNonEmpty(in.KeyType, string(pki.KeyRSA4096)))

	def := in.Days
	if def <= 0 {
		def = a.cfg.CA.DefaultCADays
	}
	in.Days = askInt("Validity (days)", def)
	in.PathLen = askInt("Path length (CA levels allowed below this one)", in.PathLen)

	if a.cfg.Server.BaseURL != "" && askYesNo("Embed a CRL distribution point in issued certificates?", true) {
		slug := ca.Slugify(firstNonEmpty(in.Name, in.Subject.CommonName))
		in.CRLDistPoints = []string{fmt.Sprintf("%s/public/crl/%s.crl", a.cfg.Server.BaseURL, slug)}
	}
	if len(existing) == 0 {
		in.MakeDefault = true
	} else {
		in.MakeDefault = askYesNo("Make this the default issuing authority?", in.MakeDefault)
	}
	return nil
}

func newCAListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List certificate authorities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			cas, err := a.svc.ListCAs(cmd.Context())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(cas)
			}
			if len(cas) == 0 {
				fmt.Println("No certificate authorities yet. Create one with `goca ca create --wizard`.")
				return nil
			}
			t := newTable("id", "name", "slug", "kind", "origin", "key", "expires", "days left", "status", "default")
			for _, c := range cas {
				def := ""
				if c.IsDefault {
					def = "*"
				}
				key := "stored"
				if !c.HasKey() {
					key = "none"
				}
				expires, daysLeft := "-", "-"
				if !c.Pending() {
					expires = c.NotAfter.Format("2006-01-02")
					daysLeft = fmt.Sprint(c.DaysLeft())
				}
				t.row(c.ID, c.Name, c.Slug, c.Kind(), c.Origin(), key,
					expires, daysLeft, c.Status, def)
			}
			t.flush()

			// Point out anything that needs a follow-up action.
			for _, c := range cas {
				if c.Pending() {
					info("%q is awaiting an external signature: goca ca import-signed %s --cert signed.crt",
						c.Name, c.Slug)
				}
			}
			return nil
		},
	}
}

func newCAShowCmd() *cobra.Command {
	var showPEM bool
	cmd := &cobra.Command{
		Use:   "show <id|slug|name>",
		Short: "Show one certificate authority in detail",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ref := ""
			if len(args) > 0 {
				ref = args[0]
			}
			c, err := a.svc.ResolveCA(cmd.Context(), ref)
			if err != nil {
				return err
			}
			cert, err := pki.ParseCertPEM([]byte(c.CertPEM))
			if err != nil {
				return err
			}
			info := pki.Describe(cert)
			if flagJSON {
				return printJSON(map[string]any{"ca": c, "info": info})
			}
			section(c.Name)
			printCASummary(c)
			kv("signature", info.SignatureAlgorithm)
			kv("key usage", strings.Join(info.KeyUsage, ", "))
			if len(info.CRLDistPoints) > 0 {
				kv("CRL URLs", strings.Join(info.CRLDistPoints, ", "))
			}
			if len(info.OCSPServers) > 0 {
				kv("OCSP URLs", strings.Join(info.OCSPServers, ", "))
			}
			_, issued, _ := a.svc.Search(cmd.Context(), store.CertFilter{CAID: c.ID, Limit: 1})
			_, revoked, _ := a.svc.Search(cmd.Context(), store.CertFilter{CAID: c.ID, Status: store.StatusRevoked, Limit: 1})
			kv("certificates issued", issued)
			kv("certificates revoked", revoked)
			if showPEM {
				fmt.Println()
				fmt.Print(c.CertPEM)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showPEM, "pem", false, "also print the certificate PEM")
	return cmd
}

func newCAExportCmd() *cobra.Command {
	var (
		outDir  string
		withKey bool
		stdout  string
	)
	cmd := &cobra.Command{
		Use:   "export <id|slug|name>",
		Short: "Write a CA's certificate, chain, CRL and (optionally) key to disk",
		Long: strings.TrimSpace(`
Exports the artefacts of an authority. Without --out the files are written to
the current directory. Use --stdout to print a single artefact instead.`),
		Example: strings.TrimSpace(`
  goca ca export acme-root-ca --out ./ca
  goca ca export acme-root-ca --out ./ca --with-key
  goca ca export acme-root-ca --stdout cert
  goca ca export acme-root-ca --stdout crl > acme.crl`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()
			ref := ""
			if len(args) > 0 {
				ref = args[0]
			}
			c, err := a.svc.ResolveCA(ctx, ref)
			if err != nil {
				return err
			}

			if stdout != "" {
				switch stdout {
				case "cert", "crt", "pem":
					fmt.Print(c.CertPEM)
				case "chain":
					chain, err := a.svc.CAChainPEM(ctx, c)
					if err != nil {
						return err
					}
					os.Stdout.Write(chain)
				case "key":
					key, err := a.svc.CAKeyPEM(ctx, c)
					if err != nil {
						return err
					}
					os.Stdout.Write(key)
				case "crl":
					_, crlPEM, err := a.svc.GenerateCRL(ctx, c.ID, a.actor())
					if err != nil {
						return err
					}
					os.Stdout.Write(crlPEM)
				default:
					return fmt.Errorf("unknown artefact %q (cert, chain, key or crl)", stdout)
				}
				return nil
			}

			dir := outDir
			if dir == "" {
				dir = "."
			}
			return exportCA(ctx, a, c, dir, withKey)
		},
	}
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "directory to write files into")
	cmd.Flags().BoolVar(&withKey, "with-key", false, "also export the CA private key (mode 0600)")
	cmd.Flags().StringVar(&stdout, "stdout", "", "print one artefact to stdout: cert, chain, key or crl")
	return cmd
}

func exportCA(ctx context.Context, a *app, c *store.CA, dir string, withKey bool) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	section("Exporting " + c.Name)

	certPath := filepath.Join(dir, c.Slug+".crt")
	if err := writeOut(certPath, []byte(c.CertPEM), 0o644); err != nil {
		return err
	}
	if chain, err := a.svc.CAChainPEM(ctx, c); err == nil {
		if err := writeOut(filepath.Join(dir, c.Slug+"-chain.pem"), chain, 0o644); err != nil {
			return err
		}
	}
	if _, crlPEM, err := a.svc.GenerateCRL(ctx, c.ID, a.actor()); err == nil {
		if err := writeOut(filepath.Join(dir, c.Slug+".crl.pem"), crlPEM, 0o644); err != nil {
			return err
		}
	}
	if withKey {
		key, err := a.svc.CAKeyPEM(ctx, c)
		if err != nil {
			return err
		}
		if err := writeOut(filepath.Join(dir, c.Slug+".key"), key, 0o600); err != nil {
			return err
		}
		a.svc.AuditWithIP(ctx, a.actor(), "ca.key_download", c.Name, "cli export", "")
		warn("the private key is now on disk in cleartext; protect %s accordingly",
			filepath.Join(dir, c.Slug+".key"))
	}
	return nil
}

func newCADefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <id|slug|name>",
		Short: "Set the default issuing authority",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			c, err := a.svc.ResolveCA(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.svc.SetDefaultCA(cmd.Context(), c.ID, a.actor()); err != nil {
				return err
			}
			ok("%q is now the default issuing authority", c.Name)
			return nil
		},
	}
}

func newCAStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <id|slug|name> <active|disabled>",
		Short: "Enable or disable issuance from an authority",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			c, err := a.svc.ResolveCA(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.svc.SetCAStatus(cmd.Context(), c.ID, args[1], a.actor()); err != nil {
				return err
			}
			ok("%q is now %s", c.Name, args[1])
			return nil
		},
	}
}

func newCADeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id|slug|name>",
		Aliases: []string{"rm"},
		Short:   "Delete an authority and every certificate it issued",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			c, err := a.svc.ResolveCA(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			_, issued, _ := a.svc.Search(cmd.Context(), store.CertFilter{CAID: c.ID, Limit: 1})
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", c.Name)
				}
				warn("this deletes %q, its private key and %d issued certificates", c.Name, issued)
				if !askYesNo("Really delete it?", false) {
					return nil
				}
			}
			if err := a.svc.DeleteCA(cmd.Context(), c.ID, a.actor()); err != nil {
				return err
			}
			ok("deleted %q and %d certificates", c.Name, issued)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newCACRLCmd() *cobra.Command {
	var out string
	var der bool
	cmd := &cobra.Command{
		Use:   "crl <id|slug|name>",
		Short: "Generate a certificate revocation list",
		Args:  cobra.MaximumNArgs(1),
		Example: strings.TrimSpace(`
  goca ca crl acme-root-ca
  goca ca crl acme-root-ca --out acme.crl --der`),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ref := ""
			if len(args) > 0 {
				ref = args[0]
			}
			c, err := a.svc.ResolveCA(cmd.Context(), ref)
			if err != nil {
				return err
			}
			derBytes, pemBytes, err := a.svc.GenerateCRL(cmd.Context(), c.ID, a.actor())
			if err != nil {
				return err
			}
			data := pemBytes
			if der {
				data = derBytes
			}
			if out == "" && !flagJSON {
				out = "-"
			}
			if flagJSON {
				return printJSON(map[string]string{"ca": c.Name, "crl_pem": string(pemBytes)})
			}
			return writeOut(out, data, 0o644)
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write to this file instead of stdout")
	cmd.Flags().BoolVar(&der, "der", false, "emit DER instead of PEM")
	return cmd
}

func printCASummary(c *store.CA) {
	kv("id", c.ID)
	kv("name", c.Name)
	kv("slug", c.Slug)
	kv("subject", c.Subject)
	kv("kind", c.Kind())
	kv("origin", c.Origin())
	if c.Pending() {
		kv("status", "pending — awaiting an externally signed certificate")
		kv("key type", c.KeyType)
		return
	}
	kv("serial", c.SerialHex)
	kv("key type", c.KeyType)
	kv("private key", map[bool]string{true: "stored (can issue)", false: "not held (trust anchor)"}[c.HasKey()])
	kv("valid from", c.NotBefore.Format("2006-01-02 15:04 MST"))
	kv("valid until", fmt.Sprintf("%s (%d days left)", c.NotAfter.Format("2006-01-02"), c.DaysLeft()))
	kv("status", c.Status)
	kv("default", c.IsDefault)
	kv("SHA-256", c.Fingerprint)
}
