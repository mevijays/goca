package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// newCASubordinateCmd implements `goca ca request`, step one of running goca
// underneath an external authority such as pfSense.
func newCASubordinateCmd() *cobra.Command {
	var (
		wizard      bool
		name        string
		cn, org, ou string
		country     string
		province    string
		locality    string
		keyType     string
		parent      string
		out         string
	)
	cmd := &cobra.Command{
		Use:     "request",
		Aliases: []string{"csr", "subordinate"},
		Short:   "Create a subordinate CA request for an external authority to sign",
		Long: strings.TrimSpace(`
Generates a CA key pair here, keeps the private key encrypted in the database,
and writes a certificate signing request for an external authority to sign.

This is how you put goca underneath a CA you already run - a pfSense CA, a
corporate root, an offline root. The private key never leaves this server.

The authority is created in "pending" state and cannot issue anything until you
bring the signed certificate back with ` + "`goca ca import-signed`" + `.

On pfSense: System > Cert. Manager > CAs > Add, choose "Sign an intermediate
Certificate Authority", paste this CSR, pick the signing CA, and export the
result.`),
		Example: strings.TrimSpace(`
  goca ca request --wizard

  goca ca request --name "Branch Issuing CA" \
      --common-name "Branch Issuing CA" --organization Acme \
      --key-type rsa-4096 --out branch.csr

  # ... sign branch.csr on pfSense, save the result as branch.crt ...
  goca ca import-signed branch-issuing-ca --cert branch.crt --chain pfsense-root.crt`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			in := ca.SubordinateCSRInput{
				Name: name,
				Subject: pki.Subject{
					CommonName: cn, Organization: org, OrganizationalUnit: ou,
					Country: country, Province: province, Locality: locality,
				},
				KeyType:   keyType,
				ParentRef: parent,
				Actor:     a.actor(),
			}

			if wizard || (in.Subject.CommonName == "" && interactive()) {
				section("Subordinate CA request")
				in.Subject.CommonName = askRequired("Common name (CN)", firstNonEmpty(in.Subject.CommonName, "goca Issuing CA"))
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
				if out == "" {
					out = ask("Write the CSR to this file (blank = print it here)", "")
				}
			}

			res, err := a.svc.CreateSubordinateCSR(cmd.Context(), in)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(res)
			}

			section("Request created")
			kv("authority", res.CA.Name)
			kv("id / slug", fmt.Sprintf("%d / %s", res.CA.ID, res.CA.Slug))
			kv("subject", res.Info.Subject)
			kv("key type", res.CA.KeyType)
			kv("status", "pending — awaiting an externally signed certificate")

			if out != "" {
				fmt.Println()
				if err := writeOut(out, []byte(res.CSRPEM), 0o644); err != nil {
					return err
				}
			} else {
				fmt.Println()
				fmt.Print(res.CSRPEM)
			}

			fmt.Println()
			fmt.Println("  Next:")
			fmt.Println("    1. Sign this request with your external authority.")
			fmt.Println("       pfSense: System > Cert. Manager > CAs > Add >")
			fmt.Println("                \"Sign an intermediate Certificate Authority\"")
			fmt.Printf("    2. goca ca import-signed %s --cert signed.crt [--chain root.crt]\n", res.CA.Slug)
			fmt.Println()
			info("the private key stays here, encrypted; only the request leaves this server")
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
	fl.StringVar(&parent, "parent", "", "trust anchor this will chain to, if already imported")
	fl.StringVarP(&out, "out", "o", "", "write the CSR to this file instead of stdout")
	return cmd
}

// newCAImportSignedCmd implements step two: bringing the signed certificate back.
func newCAImportSignedCmd() *cobra.Command {
	var (
		certFile    string
		chainFile   string
		makeDefault bool
	)
	cmd := &cobra.Command{
		Use:     "import-signed <id|slug|name>",
		Aliases: []string{"complete"},
		Short:   "Import the certificate an external authority signed for a pending request",
		Long: strings.TrimSpace(`
Completes a subordinate CA created with ` + "`goca ca request`" + `. The
certificate is checked against the private key goca kept, so a certificate
issued for a different request is rejected rather than silently stored.

Pass --chain with the external authority's own certificate (its root, and any
intermediates) so goca can build complete chains. Anything in that file which is
not already known is imported as a trust anchor.`),
		Example: strings.TrimSpace(`
  goca ca import-signed branch-issuing-ca --cert signed.crt
  goca ca import-signed branch-issuing-ca --cert signed.crt --chain pfsense-root.crt --default
  goca ca import-signed 3 --cert - < signed.crt`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if certFile == "" {
				return fmt.Errorf("--cert is required (use - to read from stdin)")
			}
			certPEM, err := readFileOrStdin(certFile)
			if err != nil {
				return fmt.Errorf("read the signed certificate: %w", err)
			}
			var chainPEM []byte
			if chainFile != "" {
				chainPEM, err = readFileOrStdin(chainFile)
				if err != nil {
					return fmt.Errorf("read the chain: %w", err)
				}
			}

			c, err := a.svc.CompleteSubordinate(cmd.Context(), ca.CompleteSubordinateInput{
				CARef:       args[0],
				CertPEM:     string(certPEM),
				ChainPEM:    string(chainPEM),
				MakeDefault: makeDefault,
				Actor:       a.actor(),
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(c)
			}
			section("Authority activated")
			printCASummary(c)
			reportChain(cmd.Context(), a, c)
			return nil
		},
	}
	cmd.Flags().StringVar(&certFile, "cert", "", "the signed CA certificate (PEM), or - for stdin")
	cmd.Flags().StringVar(&chainFile, "chain", "", "the external authority's certificate chain (PEM)")
	cmd.Flags().BoolVar(&makeDefault, "default", false, "make this the default issuing authority")
	return cmd
}

// newCAImportCmd imports an authority created entirely outside goca.
func newCAImportCmd() *cobra.Command {
	var (
		certFile    string
		keyFile     string
		chainFile   string
		name        string
		makeDefault bool
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import an existing CA, with its key to issue or without to trust",
		Long: strings.TrimSpace(`
Brings an authority created elsewhere into goca.

With --key, goca can issue certificates from it immediately. This is the
shortest path when your external tool can export the intermediate as a pair -
pfSense does, under Cert. Manager > CAs > Export.

Without --key, the certificate is stored as a trust anchor: it completes chains
and is downloadable from the public endpoint, but cannot sign. This is how you
bring in the root above a subordinate you created with ` + "`goca ca request`" + `.

If the file holds several certificates, the first is the authority and the rest
are treated as its chain.`),
		Example: strings.TrimSpace(`
  # An issuing intermediate exported from pfSense, with its key
  goca ca import --cert pfsense-intermediate.crt --key pfsense-intermediate.key \
      --chain pfsense-root.crt --name "pfSense Issuing CA" --default

  # Just the root, so chains resolve
  goca ca import --cert pfsense-root.crt --name "pfSense Root CA"

  cat chain.pem | goca ca import --cert -`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if certFile == "" {
				if !interactive() {
					return fmt.Errorf("--cert is required (use - to read from stdin)")
				}
				certFile = askRequired("Path to the CA certificate (PEM)", "")
				keyFile = ask("Path to its private key (blank = import as a trust anchor only)", "")
				chainFile = ask("Path to the issuer chain, if any", "")
			}
			certPEM, err := readFileOrStdin(certFile)
			if err != nil {
				return fmt.Errorf("read the certificate: %w", err)
			}
			var keyPEM, chainPEM []byte
			if keyFile != "" {
				if keyPEM, err = readFileOrStdin(keyFile); err != nil {
					return fmt.Errorf("read the private key: %w", err)
				}
			}
			if chainFile != "" {
				if chainPEM, err = readFileOrStdin(chainFile); err != nil {
					return fmt.Errorf("read the chain: %w", err)
				}
			}

			c, err := a.svc.ImportCA(cmd.Context(), ca.ImportCAInput{
				Name:        name,
				CertPEM:     string(certPEM),
				KeyPEM:      string(keyPEM),
				ChainPEM:    string(chainPEM),
				MakeDefault: makeDefault,
				Actor:       a.actor(),
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(c)
			}

			section("Authority imported")
			printCASummary(c)
			if !c.HasKey() {
				fmt.Println()
				info("imported without a private key: this is a trust anchor.")
				info("it completes chains and is downloadable, but cannot issue certificates.")
			}
			reportChain(cmd.Context(), a, c)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&certFile, "cert", "", "CA certificate in PEM or DER, or - for stdin")
	fl.StringVar(&keyFile, "key", "", "its private key; supply it to issue from this CA")
	fl.StringVar(&chainFile, "chain", "", "issuer chain to import alongside as trust anchors")
	fl.StringVar(&name, "name", "", "display name (defaults to the certificate's common name)")
	fl.BoolVar(&makeDefault, "default", false, "make this the default issuing authority")
	return cmd
}

// newCAPendingCmd lists authorities waiting on an external signature.
func newCAPendingCmd() *cobra.Command {
	var showCSR string
	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List subordinate CAs awaiting an externally signed certificate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			if showCSR != "" {
				c, err := a.svc.ResolveCA(cmd.Context(), showCSR)
				if err != nil {
					return err
				}
				if c.CSRPEM == "" {
					return fmt.Errorf("%q has no stored signing request", c.Name)
				}
				fmt.Print(c.CSRPEM)
				return nil
			}

			pending, err := a.svc.Store().PendingCAs(cmd.Context())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(pending)
			}
			if len(pending) == 0 {
				fmt.Println("Nothing is waiting for an external signature.")
				return nil
			}
			t := newTable("id", "name", "slug", "subject", "key", "requested")
			for _, c := range pending {
				t.row(c.ID, c.Name, c.Slug, c.Subject, c.KeyType,
					c.CreatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.flush()
			fmt.Println()
			info("show a request with:   goca ca pending --csr <id|slug>")
			info("complete one with:     goca ca import-signed <id|slug> --cert signed.crt")
			return nil
		},
	}
	cmd.Flags().StringVar(&showCSR, "csr", "", "print the stored CSR of one pending authority")
	return cmd
}

// newCARevokeCmd retires an authority.
func newCARevokeCmd() *cobra.Command {
	var (
		reason  string
		cascade bool
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "revoke <id|slug|name>",
		Short: "Retire an authority, optionally revoking everything beneath it",
		Long: strings.TrimSpace(`
Disables an authority so nothing further can be issued from it.

With --cascade, every certificate it issued is revoked as well, along with any
subordinate authorities below it.

When the issuer is one goca controls, the authority's own certificate is added
to that issuer's CRL, which is the part relying parties can actually see. For a
root, or an issuer goca does not hold, revoke it on the external side too and
remove it from your trust stores.`),
		Example: strings.TrimSpace(`
  goca ca revoke branch-issuing-ca --reason cessationOfOperation
  goca ca revoke branch-issuing-ca --cascade --reason keyCompromise --yes`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()

			c, err := a.svc.ResolveCA(ctx, args[0])
			if err != nil {
				return err
			}
			code, err := pki.ParseReason(reason)
			if err != nil {
				return err
			}
			_, issued, _ := a.svc.Search(ctx, store.CertFilter{CAID: c.ID, Limit: 1})

			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to retire %q non-interactively; pass --yes", c.Name)
				}
				warn("retiring %q stops all issuance from it", c.Name)
				if cascade {
					warn("--cascade also revokes its %d certificates and any subordinate authorities", issued)
				}
				if !askYesNo("Continue?", false) {
					return nil
				}
			}

			res, err := a.svc.RevokeCA(ctx, c.ID, code, cascade, a.actor())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(res)
			}
			section("Authority retired")
			kv("authority", res.CA.Name)
			kv("reason", pki.ReasonName(code))
			kv("issuance", "disabled")
			if cascade {
				kv("certificates revoked", res.Certificates)
				if len(res.ChildCAs) > 0 {
					kv("subordinates retired", strings.Join(res.ChildCAs, ", "))
				}
			}
			if res.RevokedInParent {
				ok("added to the CRL of %s", res.ParentName)
				info("publish it with: goca ca crl %s", res.ParentName)
			}
			for _, w := range res.Warnings {
				warn("%s", w)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "cessationOfOperation", "RFC 5280 revocation reason")
	cmd.Flags().BoolVar(&cascade, "cascade", false, "also revoke every certificate issued by it")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

// reportChain tells the operator whether an imported authority chains to a root
// goca holds, since an incomplete chain is the usual import mistake.
func reportChain(ctx context.Context, a *app, c *store.CA) {
	if c.CertPEM == "" {
		return
	}
	fmt.Println()
	if a.svc.ChainComplete(ctx, c) {
		chain, _ := a.svc.CAChain(ctx, c)
		names := make([]string, 0, len(chain))
		for i := len(chain) - 1; i >= 0; i-- {
			names = append(names, chain[i].Subject.CommonName)
		}
		ok("chain complete: %s", strings.Join(names, " → "))
		return
	}
	warn("chain incomplete: goca does not hold the issuer of this certificate.")
	warn("certificates it issues will ship an incomplete chain until you import it:")
	warn("  goca ca import --cert issuer-root.crt")
}
