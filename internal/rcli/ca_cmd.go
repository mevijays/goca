package rcli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/termio"
)

// The table rendering here deliberately matches internal/cli's, column for
// column, so `goca ca list` and `gocactl ca list` produce identical output.
// The end-to-end test diffs them; anything that drifts shows up there.

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ca",
		Short:   "Manage certificate authorities",
		Aliases: []string{"cas"},
	}
	cmd.AddCommand(
		newCAListCmd(),
		newCAShowCmd(),
		newCACreateCmd(),
		newCAExportCmd(),
		newCADefaultCmd(),
		newCAStatusCmd(),
		newCADeleteCmd(),
		newCACRLCmd(),
		newCAPendingCmd(),
		newCARevokeCmd(),
	)
	return cmd
}

func newCAListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List certificate authorities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListCAs(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			cas := res.Value
			if len(cas) == 0 {
				fmt.Println("No certificate authorities yet. Create one with `gocactl ca create`.")
				return nil
			}
			t := termio.NewTable("id", "name", "slug", "kind", "origin", "key", "expires", "days left", "status", "default")
			for _, ca := range cas {
				def := ""
				if ca.IsDefault {
					def = "*"
				}
				key := "stored"
				if !ca.HasKey {
					key = "none"
				}
				expires, daysLeft := "-", "-"
				if !ca.Pending() {
					expires = ca.NotAfter.Format("2006-01-02")
					daysLeft = fmt.Sprint(ca.DaysLeft)
				}
				t.Row(ca.ID, ca.Name, ca.Slug, ca.Kind, ca.Origin, key,
					expires, daysLeft, ca.Status, def)
			}
			t.Flush()

			for _, ca := range cas {
				if ca.Pending() {
					termio.Info("%q is awaiting an external signature: gocactl ca import-signed %s --cert signed.crt",
						ca.Name, ca.Slug)
				}
			}
			return nil
		},
	}
}

func newCAShowCmd() *cobra.Command {
	var pemOnly bool
	cmd := &cobra.Command{
		Use:   "show <id|slug|name>",
		Short: "Show one authority in detail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.GetCA(ctx, args[0])
			if err != nil {
				return err
			}
			if pemOnly {
				fmt.Print(res.Value.CertPEM)
				return nil
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			ca := res.Value
			termio.Section(ca.Name)
			termio.KV("id", ca.ID)
			termio.KV("name", ca.Name)
			termio.KV("slug", ca.Slug)
			termio.KV("subject", ca.Subject)
			termio.KV("kind", ca.Kind)
			termio.KV("origin", ca.Origin)
			if ca.Status == "pending" {
				termio.KV("status", "pending — awaiting an externally signed certificate")
				termio.KV("key type", ca.KeyType)
				return nil
			}
			termio.KV("serial", ca.SerialHex)
			termio.KV("key type", ca.KeyType)
			if ca.HasKey {
				termio.KV("private key", "stored (can issue)")
			} else {
				termio.KV("private key", "not held (trust anchor)")
			}
			// Rendered in the timestamp's own zone, as goca does, rather than
			// converted to local: the two binaries print the same certificate
			// and must agree about when it was issued.
			termio.KV("valid from", ca.NotBefore.Format("2006-01-02 15:04 MST"))
			termio.KV("valid until", fmt.Sprintf("%s (%d days left)", ca.NotAfter.Format("2006-01-02"), ca.DaysLeft))
			termio.KV("status", ca.Status)
			termio.KV("default", ca.IsDefault)
			termio.KV("SHA-256", ca.Fingerprint)
			if info := ca.Info; info != nil {
				termio.KV("signature", info.SignatureAlgorithm)
				termio.KV("key usage", strings.Join(info.KeyUsage, ", "))
				if len(info.CRLDistPoints) > 0 {
					termio.KV("CRL URLs", strings.Join(info.CRLDistPoints, ", "))
				}
				if len(info.OCSPServers) > 0 {
					termio.KV("OCSP URLs", strings.Join(info.OCSPServers, ", "))
				}
			}
			// goca reads these two counts straight from the database; over the
			// API the cheapest equivalent is a one-row search for the totals.
			caRef := strconv.FormatInt(ca.ID, 10)
			if p, err := c.ListCerts(ctx, gocaclient.CertFilter{CARef: caRef, Limit: 1}); err == nil {
				termio.KV("certificates issued", p.Value.Total)
			}
			if p, err := c.ListCerts(ctx, gocaclient.CertFilter{CARef: caRef, Status: "revoked", Limit: 1}); err == nil {
				termio.KV("certificates revoked", p.Value.Total)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&pemOnly, "pem", false, "print only the certificate PEM")
	return cmd
}

func newCACreateCmd() *cobra.Command {
	var (
		name, cn, org, ou           string
		country, province, locality string
		keyType                     string
		days, pathLen               int
		parent                      string
		crlURLs, ocspURLs           []string
		permittedDNS                []string
		makeDefault                 bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a root or intermediate authority",
		Example: strings.TrimSpace(`
  gocactl ca create --name "Acme Root CA" --common-name "Acme Root CA" --key-type rsa-4096 --days 3650
  gocactl ca create --name "Acme Issuing CA" --common-name "Acme Issuing CA" --parent acme-root-ca --days 1825`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateCA(ctx, gocaclient.CreateCAInput{
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
				PermittedDNS:  permittedDNS,
				MakeDefault:   makeDefault,
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created %q (%s)", res.Value.Name, res.Value.Kind)
			termio.KV("id", res.Value.ID)
			termio.KV("slug", res.Value.Slug)
			termio.KV("serial", res.Value.SerialHex)
			termio.KV("valid until", res.Value.NotAfter.Local().Format("2006-01-02"))
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&name, "name", "", "display name (defaults to the common name)")
	fl.StringVar(&cn, "common-name", "", "subject common name (CN)")
	fl.StringVar(&org, "organization", "", "subject organization (O)")
	fl.StringVar(&ou, "organizational-unit", "", "subject organizational unit (OU)")
	fl.StringVar(&country, "country", "", "subject country code (C)")
	fl.StringVar(&province, "province", "", "subject state/province (ST)")
	fl.StringVar(&locality, "locality", "", "subject locality (L)")
	fl.StringVar(&keyType, "key-type", "", "rsa-2048|rsa-3072|rsa-4096|ec-p256|ec-p384|ec-p521|ed25519")
	fl.IntVar(&days, "days", 0, "validity in days (default: the server's CA default)")
	fl.StringVar(&parent, "parent", "", "issue under this authority instead of self-signing")
	fl.IntVar(&pathLen, "path-len", 0, "path length constraint")
	fl.StringSliceVar(&crlURLs, "crl-url", nil, "CRL distribution point to embed (repeatable)")
	fl.StringSliceVar(&ocspURLs, "ocsp-url", nil, "OCSP responder URL to embed (repeatable)")
	fl.StringSliceVar(&permittedDNS, "permitted-dns", nil, "name constraint (repeatable)")
	fl.BoolVar(&makeDefault, "default", false, "make this the default issuing authority")
	return cmd
}

func newCAExportCmd() *cobra.Command {
	var (
		outDir   string
		withKey  bool
		stdout   string
		bundle   bool
		fileName string
	)
	cmd := &cobra.Command{
		Use:   "export <id|slug|name>",
		Short: "Download an authority's certificate, chain, CRL or key",
		Long: strings.TrimSpace(`
Downloading the private key requires the admin role; the server refuses it
otherwise, exactly as it does in the portal.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}

			if stdout != "" {
				file, ok := map[string]string{
					"cert": "ca.crt", "chain": "chain.pem", "key": "ca.key", "crl": "crl.pem",
				}[stdout]
				if !ok {
					return fmt.Errorf("--stdout must be cert, chain, key or crl")
				}
				_, data, err := c.DownloadCA(ctx, args[0], file)
				if err != nil {
					return err
				}
				_, err = os.Stdout.Write(data)
				return err
			}

			if bundle || fileName != "" {
				file := fileName
				if file == "" {
					file = "bundle.zip"
				}
				name, data, err := c.DownloadCA(ctx, args[0], file)
				if err != nil {
					return err
				}
				return writeDownload(outDir, name, data, file)
			}

			files := []string{"ca.crt", "chain.pem"}
			if withKey {
				files = append(files, "ca.key")
			}
			for _, file := range files {
				name, data, err := c.DownloadCA(ctx, args[0], file)
				if err != nil {
					return err
				}
				if err := writeDownload(outDir, name, data, file); err != nil {
					return err
				}
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&outDir, "out", ".", "directory to write into")
	fl.BoolVar(&withKey, "with-key", false, "also download the private key (admin only)")
	fl.StringVar(&stdout, "stdout", "", "print one artefact to stdout: cert|chain|key|crl")
	fl.BoolVar(&bundle, "bundle", false, "download everything as a zip")
	fl.StringVar(&fileName, "file", "", "download one named artefact (ca.crt, ca.der, chain.pem, crl.pem, request.csr, bundle.zip, ...)")
	return cmd
}

// writeDownload saves a downloaded artefact, preferring the file name the
// server suggested via Content-Disposition.
func writeDownload(dir, serverName string, data []byte, fallback string) error {
	name := serverName
	if name == "" {
		name = fallback
	}
	if dir == "" || dir == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".p12") {
		mode = 0o600
	}
	return termio.WriteOut(filepath.Join(dir, name), data, mode)
}

func newCADefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <id|slug|name>",
		Short: "Make an authority the default issuer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.SetDefaultCA(ctx, args[0]); err != nil {
				return err
			}
			termio.OK("%s is now the default issuing authority", args[0])
			return nil
		},
	}
}

func newCAStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <id|slug|name> <active|disabled>",
		Short: "Enable or disable an authority for further issuance",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.SetCAStatus(ctx, args[0], args[1]); err != nil {
				return err
			}
			termio.OK("%s is now %s", args[0], args[1])
			return nil
		},
	}
}

func newCADeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete <id|slug|name>",
		Aliases: []string{"rm"},
		Short:   "Delete an authority and everything it issued",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", args[0])
				}
				if !termio.AskYesNo(fmt.Sprintf("Delete %q and every certificate it issued?", args[0]), false) {
					return nil
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.DeleteCA(ctx, args[0]); err != nil {
				return err
			}
			termio.OK("deleted %s", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newCACRLCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "crl <id|slug|name>",
		Short: "Generate a fresh CRL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.GenerateCRL(ctx, args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			pemStr, _ := res.Value["crl_pem"].(string)
			if out != "" {
				return termio.WriteOut(out, []byte(pemStr), 0o644)
			}
			termio.OK("generated a CRL for %s", args[0])
			if n, ok := res.Value["crl_number"]; ok {
				termio.KV("crl number", n)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "write the CRL here instead of summarising")
	return cmd
}

func newCAPendingCmd() *cobra.Command {
	var csrOf string
	cmd := &cobra.Command{
		Use:   "pending",
		Short: "List authorities awaiting an external signature",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			if csrOf != "" {
				res, err := c.CACSR(ctx, csrOf)
				if err != nil {
					return err
				}
				pemStr, _ := res.Value["csr_pem"].(string)
				fmt.Print(pemStr)
				return nil
			}
			res, err := c.PendingCAs(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("Nothing is waiting for an external signature.")
				return nil
			}
			t := termio.NewTable("id", "name", "slug", "subject", "key type", "requested")
			for _, p := range res.Value {
				t.Row(p.CA.ID, p.CA.Name, p.CA.Slug, p.CA.Subject, p.CA.KeyType,
					p.CA.CreatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&csrOf, "csr", "", "print one pending authority's signing request")
	return cmd
}

func newCARevokeCmd() *cobra.Command {
	var (
		reason  string
		cascade bool
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "revoke <id|slug|name>",
		Short: "Retire an authority",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to retire %q non-interactively; pass --yes", args[0])
				}
				prompt := fmt.Sprintf("Retire %q? Issuance stops immediately.", args[0])
				if cascade {
					prompt = fmt.Sprintf("Retire %q AND revoke everything it issued?", args[0])
				}
				if !termio.AskYesNo(prompt, false) {
					return nil
				}
			}
			// Parsed here rather than server-side so --reason takes the same names
			// as `goca ca revoke`; ParseReason accepts the numeric codes too.
			code, err := pki.ParseReason(reason)
			if err != nil {
				return err
			}
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.RevokeCA(ctx, args[0], code, cascade)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("retired %s", args[0])
			if n, ok := res.Value["revoked_certificates"]; ok {
				termio.KV("certificates revoked", n)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&reason, "reason", "cessationOfOperation", "RFC 5280 revocation reason")
	fl.BoolVar(&cascade, "cascade", false, "also revoke every certificate it issued")
	fl.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}
