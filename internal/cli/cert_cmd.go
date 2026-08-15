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

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cert",
		Short:   "Request, search, export and revoke certificates",
		Aliases: []string{"certificate", "certs"},
	}
	cmd.AddCommand(
		newCertIssueCmd(),
		newCertSignCmd(),
		newCertListCmd(),
		newCertShowCmd(),
		newCertExportCmd(),
		newCertRevokeCmd(),
		newCertDeleteCmd(),
		// Lifecycle: rotation and the wider shapes of revocation.
		newCertRenewCmd(),
		newCertHistoryCmd(),
		newCertHoldCmd(),
		newCertReleaseCmd(),
		newCertBulkRevokeCmd(),
	)
	return cmd
}

// issueFlags is shared by `cert issue` (generate) and `cert sign` (from CSR).
type issueFlags struct {
	caRef      string
	cn         string
	org, ou    string
	country    string
	province   string
	locality   string
	sans       []string
	keyType    string
	profile    string
	days       int
	note       string
	noStoreKey bool
	outDir     string
	keyOut     string
	certOut    string
	chainOut   string
	wizard     bool
}

func (f *issueFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.caRef, "ca", "", "issuing authority id, slug or name (default: the default authority)")
	fl.StringVar(&f.cn, "common-name", "", "subject common name (CN)")
	fl.StringVar(&f.org, "organization", "", "subject organization (O)")
	fl.StringVar(&f.ou, "organizational-unit", "", "subject organizational unit (OU)")
	fl.StringVar(&f.country, "country", "", "subject country code (C)")
	fl.StringVar(&f.province, "province", "", "subject state or province (ST)")
	fl.StringVar(&f.locality, "locality", "", "subject locality (L)")
	fl.StringSliceVar(&f.sans, "san", nil,
		"subject alternative name; repeatable. Bare values are auto-typed, or prefix with DNS:, IP:, EMAIL:, URI:")
	fl.StringVar(&f.profile, "profile", "server", "server|client|server-client|code-signing|email")
	fl.IntVar(&f.days, "days", 0, "validity in days (default: the configured certificate default)")
	fl.StringVar(&f.note, "note", "", "free-text note stored with the certificate")
	fl.BoolVar(&f.noStoreKey, "no-store-key", false,
		"do not keep the private key in the database (it is printed once and then unrecoverable)")
	fl.StringVar(&f.outDir, "out", "", "write cert, key and chain into this directory")
	fl.StringVar(&f.certOut, "cert-out", "", "write the certificate to this file")
	fl.StringVar(&f.keyOut, "key-out", "", "write the private key to this file")
	fl.StringVar(&f.chainOut, "chain-out", "", "write the CA chain to this file")
}

func (f *issueFlags) subject() pki.Subject {
	return pki.Subject{
		CommonName: f.cn, Organization: f.org, OrganizationalUnit: f.ou,
		Country: f.country, Province: f.province, Locality: f.locality,
	}
}

func newCertIssueCmd() *cobra.Command {
	f := &issueFlags{}
	cmd := &cobra.Command{
		Use:     "issue",
		Aliases: []string{"request", "new"},
		Short:   "Generate a key and CSR, then sign it (the common case)",
		Long: strings.TrimSpace(`
Generates a private key, builds a CSR from the subject and SANs you give, signs
it with the chosen authority and stores everything.

The key is stored encrypted so it can be downloaded again later, from here, the
portal or the API. Pass --no-store-key for a download-once workflow: the key is
printed exactly once and never retained.`),
		Example: strings.TrimSpace(`
  # Guided
  goca cert issue --wizard

  # A TLS server certificate
  goca cert issue --common-name app.internal.lan \
      --san app.internal.lan --san api.internal.lan --san 10.0.0.20 \
      --days 397 --out ./app

  # A client certificate from a specific authority
  goca cert issue --ca acme-issuing-ca --profile client \
      --common-name "alice@example.com" --san alice@example.com`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if f.wizard || (f.cn == "" && interactive()) {
				if err := certWizard(cmd.Context(), a, f); err != nil {
					return err
				}
			}
			if f.keyType == "" {
				f.keyType = a.cfg.CA.DefaultKeyType
			}
			storeKey := !f.noStoreKey
			return runIssue(cmd.Context(), a, ca.IssueInput{
				CARef:    f.caRef,
				Mode:     ca.ModeGenerate,
				Subject:  f.subject(),
				SANs:     f.sans,
				KeyType:  f.keyType,
				Profile:  f.profile,
				Days:     f.days,
				StoreKey: &storeKey,
				Note:     f.note,
				Actor:    a.actor(),
			}, f)
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&f.keyType, "key-type", "",
		"rsa-2048|rsa-3072|rsa-4096|ec-p256|ec-p384|ec-p521|ed25519")
	cmd.Flags().BoolVar(&f.wizard, "wizard", false, "prompt for every field")
	return cmd
}

func newCertSignCmd() *cobra.Command {
	f := &issueFlags{}
	var csrFile, keyFile string
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a CSR you already have (from openssl or anywhere else)",
		Long: strings.TrimSpace(`
Signs an existing certificate signing request. The requester keeps their private
key; goca never sees it unless you pass --key, which stores it alongside the
certificate so the pair can be re-downloaded later.

Subject and SAN flags override what the CSR carries, which lets you correct a
request without asking for a new one.`),
		Example: strings.TrimSpace(`
  openssl req -new -newkey rsa:2048 -nodes -keyout app.key -out app.csr \
      -subj "/CN=app.internal.lan"

  goca cert sign --csr app.csr --san app.internal.lan --days 397
  goca cert sign --csr app.csr --key app.key --out ./app
  cat app.csr | goca cert sign --csr - --profile client`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if csrFile == "" {
				return fmt.Errorf("--csr is required (use - to read from stdin)")
			}
			csrPEM, err := readFileOrStdin(csrFile)
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}
			parsed, err := pki.ParseCSR(csrPEM)
			if err != nil {
				return err
			}
			var keyPEM []byte
			if keyFile != "" {
				keyPEM, err = readFileOrStdin(keyFile)
				if err != nil {
					return fmt.Errorf("read private key: %w", err)
				}
			}

			if !flagJSON {
				desc := pki.DescribeCSR(parsed)
				section("Signing request")
				kv("subject", desc.Subject)
				if len(desc.SANs) > 0 {
					kv("SANs in CSR", strings.Join(desc.SANs, ", "))
				}
				kv("key type", desc.KeyType)
				fmt.Println()
			}

			storeKey := !f.noStoreKey
			return runIssue(cmd.Context(), a, ca.IssueInput{
				CARef:    f.caRef,
				Mode:     ca.ModeCSR,
				Subject:  f.subject(),
				SANs:     f.sans,
				Profile:  f.profile,
				Days:     f.days,
				CSRPEM:   string(csrPEM),
				KeyPEM:   string(keyPEM),
				StoreKey: &storeKey,
				Note:     f.note,
				Actor:    a.actor(),
			}, f)
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&csrFile, "csr", "", "CSR file in PEM format, or - for stdin")
	cmd.Flags().StringVar(&keyFile, "key", "",
		"the CSR's private key, stored so the pair can be downloaded again later")
	return cmd
}

func certWizard(ctx context.Context, a *app, f *issueFlags) error {
	cas, err := a.svc.ListCAs(ctx)
	if err != nil {
		return err
	}
	if len(cas) == 0 {
		return fmt.Errorf("no certificate authority exists yet; run `goca ca create --wizard` first")
	}

	section("New certificate")
	if len(cas) > 1 && f.caRef == "" {
		fmt.Println("  Authorities:")
		for _, c := range cas {
			def := ""
			if c.IsDefault {
				def = " (default)"
			}
			fmt.Printf("    %d) %s%s\n", c.ID, c.Name, def)
		}
		f.caRef = ask("  Issuing authority (id, slug or name; blank = default)", "")
	}
	f.cn = askRequired("Common name (CN)", f.cn)
	if len(f.sans) == 0 {
		if v := ask("Subject alternative names (comma separated; blank = use the CN)", f.cn); v != "" {
			f.sans = splitCSV(v)
		}
	}
	f.org = ask("Organization (O)", f.org)
	f.ou = ask("Organizational unit (OU)", f.ou)
	f.country = ask("Country code (C)", f.country)

	profiles := make([]string, len(pki.Profiles))
	for i, p := range pki.Profiles {
		profiles[i] = string(p)
	}
	f.profile = askChoice("Profile", profiles, firstNonEmpty(f.profile, "server"))

	types := make([]string, len(pki.KeyTypes))
	for i, k := range pki.KeyTypes {
		types[i] = string(k)
	}
	f.keyType = askChoice("Key type", types, firstNonEmpty(f.keyType, a.cfg.CA.DefaultKeyType, "rsa-2048"))

	def := f.days
	if def <= 0 {
		def = a.cfg.CA.DefaultCertDays
	}
	f.days = askInt("Validity (days)", def)
	f.noStoreKey = !askYesNo("Store the private key so it can be downloaded again later?", !f.noStoreKey)
	if f.outDir == "" {
		f.outDir = ask("Write the files to this directory (blank = print to the terminal)", "")
	}
	return nil
}

func runIssue(ctx context.Context, a *app, in ca.IssueInput, f *issueFlags) error {
	res, err := a.svc.Issue(ctx, in)
	if err != nil {
		return err
	}
	c := res.Certificate

	if flagJSON {
		return printJSON(map[string]any{
			"certificate":     c,
			"cert_pem":        c.CertPEM,
			"private_key_pem": res.PrivateKeyPEM,
			"chain_pem":       res.ChainPEM,
			"csr_pem":         res.CSRPEM,
			"key_stored":      c.HasKey,
		})
	}

	section("Certificate issued")
	printCertSummary(c)

	// Decide where the artefacts go.
	wroteFiles := false
	base := safeName(c.CommonName)
	if f != nil && f.outDir != "" {
		if err := os.MkdirAll(f.outDir, 0o750); err != nil {
			return err
		}
		fmt.Println()
		if err := writeOut(filepath.Join(f.outDir, base+".crt"), []byte(c.CertPEM), 0o644); err != nil {
			return err
		}
		if res.PrivateKeyPEM != "" {
			if err := writeOut(filepath.Join(f.outDir, base+".key"), []byte(res.PrivateKeyPEM), 0o600); err != nil {
				return err
			}
		}
		if res.ChainPEM != "" {
			if err := writeOut(filepath.Join(f.outDir, base+"-chain.pem"), []byte(res.ChainPEM), 0o644); err != nil {
				return err
			}
			full := append([]byte(c.CertPEM), []byte(res.ChainPEM)...)
			if err := writeOut(filepath.Join(f.outDir, base+"-fullchain.pem"), full, 0o644); err != nil {
				return err
			}
		}
		wroteFiles = true
	}
	if f != nil {
		if f.certOut != "" {
			if err := writeOut(f.certOut, []byte(c.CertPEM), 0o644); err != nil {
				return err
			}
			wroteFiles = true
		}
		if f.keyOut != "" && res.PrivateKeyPEM != "" {
			if err := writeOut(f.keyOut, []byte(res.PrivateKeyPEM), 0o600); err != nil {
				return err
			}
			wroteFiles = true
		}
		if f.chainOut != "" && res.ChainPEM != "" {
			if err := writeOut(f.chainOut, []byte(res.ChainPEM), 0o644); err != nil {
				return err
			}
			wroteFiles = true
		}
	}

	if !wroteFiles {
		if res.PrivateKeyPEM != "" {
			fmt.Println()
			fmt.Println("Private key:")
			fmt.Print(res.PrivateKeyPEM)
		}
		fmt.Println()
		fmt.Println("Certificate:")
		fmt.Print(c.CertPEM)
	}

	fmt.Println()
	if c.HasKey {
		info("the key is stored encrypted; re-download it any time with:")
		info("  goca cert export %s --with-key --out .", c.SerialHex)
	} else if res.PrivateKeyPEM != "" {
		warn("this key is NOT stored - the output above is the only copy")
	}
	return nil
}

func newCertListCmd() *cobra.Command {
	var (
		query      string
		caRef      string
		status     string
		profile    string
		requester  string
		expiringIn int
		limit      int
		offset     int
		sortBy     string
	)
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "search"},
		Short:   "Search issued certificates",
		Long: strings.TrimSpace(`
Searches everything ever issued by this server. The free-text query matches
common name, subject, SANs, serial, fingerprint and requester.`),
		Example: strings.TrimSpace(`
  goca cert list
  goca cert list --query internal.lan
  goca cert list --status active --expiring-in 30
  goca cert list --ca acme-issuing-ca --profile client --json`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()

			var caID int64
			if caRef != "" {
				c, err := a.svc.ResolveCA(ctx, caRef)
				if err != nil {
					return err
				}
				caID = c.ID
			}
			certs, total, err := a.svc.Search(ctx, store.CertFilter{
				Query:       query,
				CAID:        caID,
				Status:      status,
				Profile:     profile,
				RequestedBy: requester,
				ExpiringIn:  expiringIn,
				Limit:       limit,
				Offset:      offset,
				SortBy:      sortBy,
				SortDesc:    sortBy == "created_at" || sortBy == "",
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{"certificates": certs, "total": total})
			}
			if len(certs) == 0 {
				fmt.Println("No certificates matched.")
				return nil
			}
			t := newTable("id", "common name", "authority", "profile", "status", "expires", "days", "key", "requested by")
			for _, c := range certs {
				key := "-"
				if c.HasKey {
					key = "stored"
				}
				t.row(c.ID, c.CommonName, c.CAName, c.Profile, c.EffectiveStatus(),
					c.NotAfter.Format("2006-01-02"), c.DaysLeft(), key, c.RequestedBy)
			}
			t.flush()
			fmt.Printf("\n%d of %d shown\n", len(certs), total)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&query, "query", "q", "", "free-text search")
	fl.StringVar(&caRef, "ca", "", "limit to one authority")
	fl.StringVar(&status, "status", "", "active, expired or revoked")
	fl.StringVar(&profile, "profile", "", "limit to one profile")
	fl.StringVar(&requester, "requested-by", "", "limit to one requester")
	fl.IntVar(&expiringIn, "expiring-in", 0, "only certificates expiring within N days")
	fl.IntVar(&limit, "limit", 50, "maximum rows")
	fl.IntVar(&offset, "offset", 0, "rows to skip")
	fl.StringVar(&sortBy, "sort", "created_at", "created_at, not_after, common_name or serial")
	return cmd
}

func newCertShowCmd() *cobra.Command {
	var showPEM bool
	cmd := &cobra.Command{
		Use:   "show <id|serial>",
		Short: "Show one certificate in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			c, err := a.svc.FindCertificate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			info, err := a.svc.Describe(c)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{"certificate": c, "info": info, "cert_pem": c.CertPEM})
			}
			section(c.CommonName)
			printCertSummary(c)
			kv("signature", info.SignatureAlgorithm)
			kv("key usage", strings.Join(info.KeyUsage, ", "))
			kv("extended key usage", strings.Join(info.ExtKeyUsage, ", "))
			if c.Note != "" {
				kv("note", c.Note)
			}
			if c.Status == store.StatusRevoked && c.RevokedAt != nil {
				kv("revoked", fmt.Sprintf("%s (%s)",
					c.RevokedAt.Format("2006-01-02 15:04"), pki.ReasonName(c.RevokeCode)))
			}
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

func newCertExportCmd() *cobra.Command {
	var (
		outDir  string
		withKey bool
		stdout  string
		p12Out  string
		p12Pass string
	)
	cmd := &cobra.Command{
		Use:   "export <id|serial>",
		Short: "Write a certificate, its chain and (if stored) its key to disk",
		Long: strings.TrimSpace(`
Re-downloads anything goca holds for a certificate, at any point in the future.
The private key is available only when it was stored at issuance.`),
		Example: strings.TrimSpace(`
  goca cert export 12 --out ./app --with-key
  goca cert export 3A7F... --stdout cert
  goca cert export 12 --p12 app.p12 --p12-password 'secret'`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()
			c, err := a.svc.FindCertificate(ctx, args[0])
			if err != nil {
				return err
			}
			base := safeName(c.CommonName)

			if stdout != "" {
				switch stdout {
				case "cert", "crt", "pem":
					fmt.Print(c.CertPEM)
				case "key":
					key, err := a.svc.CertKeyPEM(ctx, c)
					if err != nil {
						return err
					}
					a.svc.AuditWithIP(ctx, a.actor(), "cert.key_download", c.CommonName,
						"cli serial="+c.SerialHex, "")
					os.Stdout.Write(key)
				case "chain":
					caRec, err := a.svc.GetCA(ctx, c.CAID)
					if err != nil {
						return err
					}
					chain, err := a.svc.CAChainPEM(ctx, caRec)
					if err != nil {
						return err
					}
					os.Stdout.Write(chain)
				case "fullchain":
					full, err := a.svc.CertChainPEM(ctx, c)
					if err != nil {
						return err
					}
					os.Stdout.Write(full)
				case "csr":
					if c.CSRPEM == "" {
						return fmt.Errorf("no CSR is stored for this certificate")
					}
					fmt.Print(c.CSRPEM)
				default:
					return fmt.Errorf("unknown artefact %q (cert, key, chain, fullchain or csr)", stdout)
				}
				return nil
			}

			if p12Out != "" {
				p12, err := a.svc.CertBundleP12(ctx, c, p12Pass)
				if err != nil {
					return err
				}
				a.svc.AuditWithIP(ctx, a.actor(), "cert.key_download", c.CommonName,
					"cli pkcs12 serial="+c.SerialHex, "")
				if p12Pass == "" {
					warn("the PKCS#12 bundle has an empty password")
				}
				return writeOut(p12Out, p12, 0o600)
			}

			dir := outDir
			if dir == "" {
				dir = "."
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return err
			}
			section("Exporting " + c.CommonName)
			if err := writeOut(filepath.Join(dir, base+".crt"), []byte(c.CertPEM), 0o644); err != nil {
				return err
			}
			if caRec, err := a.svc.GetCA(ctx, c.CAID); err == nil {
				if chain, err := a.svc.CAChainPEM(ctx, caRec); err == nil {
					if err := writeOut(filepath.Join(dir, base+"-chain.pem"), chain, 0o644); err != nil {
						return err
					}
					full := append([]byte(c.CertPEM), chain...)
					if err := writeOut(filepath.Join(dir, base+"-fullchain.pem"), full, 0o644); err != nil {
						return err
					}
				}
			}
			if c.CSRPEM != "" {
				if err := writeOut(filepath.Join(dir, base+".csr"), []byte(c.CSRPEM), 0o644); err != nil {
					return err
				}
			}
			if withKey {
				key, err := a.svc.CertKeyPEM(ctx, c)
				if err != nil {
					return err
				}
				if err := writeOut(filepath.Join(dir, base+".key"), key, 0o600); err != nil {
					return err
				}
				a.svc.AuditWithIP(ctx, a.actor(), "cert.key_download", c.CommonName,
					"cli export serial="+c.SerialHex, "")
			} else if c.HasKey {
				info("a private key is stored for this certificate; add --with-key to export it")
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&outDir, "out", "o", "", "directory to write files into (default: current directory)")
	fl.BoolVar(&withKey, "with-key", false, "also export the private key (mode 0600)")
	fl.StringVar(&stdout, "stdout", "", "print one artefact: cert, key, chain, fullchain or csr")
	fl.StringVar(&p12Out, "p12", "", "write a PKCS#12 bundle to this file")
	fl.StringVar(&p12Pass, "p12-password", "", "password for the PKCS#12 bundle")
	return cmd
}

func newCertRevokeCmd() *cobra.Command {
	var reason string
	var withCRL bool
	cmd := &cobra.Command{
		Use:   "revoke <id|serial>",
		Short: "Revoke a certificate",
		Long: strings.TrimSpace(`
Marks a certificate revoked. It appears in the issuing authority's next CRL;
pass --crl to regenerate that CRL immediately.

Reasons: unspecified, keyCompromise, CACompromise, affiliationChanged,
superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
AACompromise (or the numeric RFC 5280 code).`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()
			c, err := a.svc.FindCertificate(ctx, args[0])
			if err != nil {
				return err
			}
			code, err := pki.ParseReason(reason)
			if err != nil {
				return err
			}
			if err := a.svc.Revoke(ctx, c.ID, code, a.actor()); err != nil {
				return err
			}
			ok("revoked %s (serial %s, reason: %s)", c.CommonName, c.SerialHex, pki.ReasonName(code))
			if withCRL {
				if _, _, err := a.svc.GenerateCRL(ctx, c.CAID, a.actor()); err != nil {
					return err
				}
				ok("regenerated the CRL for %s", c.CAName)
			} else {
				info("publish it with: goca ca crl %d --out ca.crl --der", c.CAID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "RFC 5280 revocation reason")
	cmd.Flags().BoolVar(&withCRL, "crl", false, "regenerate the authority's CRL immediately")
	return cmd
}

func newCertDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id|serial>",
		Aliases: []string{"rm"},
		Short:   "Delete a certificate record from the database",
		Long: strings.TrimSpace(`
Removes the record entirely, including any stored key. This does not revoke the
certificate - a deleted certificate can no longer appear on a CRL. Revoke first
unless you are cleaning up a mistake.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			c, err := a.svc.FindCertificate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to delete non-interactively; pass --yes")
				}
				warn("deleting removes the record and its stored key, and it can no longer be revoked")
				if !askYesNo(fmt.Sprintf("Delete %s (serial %s)?", c.CommonName, c.SerialHex), false) {
					return nil
				}
			}
			if err := a.svc.Store().DeleteCertificate(cmd.Context(), c.ID); err != nil {
				return err
			}
			a.svc.AuditWithIP(cmd.Context(), a.actor(), "cert.delete", c.CommonName,
				"serial="+c.SerialHex, "")
			ok("deleted %s", c.CommonName)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func printCertSummary(c *store.Certificate) {
	kv("id", c.ID)
	kv("common name", c.CommonName)
	kv("subject", c.Subject)
	if sans := c.SANsDisplay(); sans != "" {
		kv("SANs", sans)
	}
	kv("serial", c.SerialHex)
	kv("authority", c.CAName)
	kv("profile", c.Profile)
	kv("key type", c.KeyType)
	kv("valid from", c.NotBefore.Format("2006-01-02 15:04 MST"))
	kv("valid until", fmt.Sprintf("%s (%d days left)", c.NotAfter.Format("2006-01-02"), c.DaysLeft()))
	kv("status", c.EffectiveStatus())
	kv("key stored", c.HasKey)
	kv("requested by", c.RequestedBy)
	kv("SHA-256", c.Fingerprint)
}

// readFileOrStdin reads a path, or stdin when the path is "-".
func readFileOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return os.ReadFile("/dev/stdin")
	}
	return os.ReadFile(path)
}

// safeName sanitises a common name for use as a file name.
func safeName(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, strings.TrimSpace(s))
	out = strings.Trim(out, "._-")
	if out == "" {
		return "certificate"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
