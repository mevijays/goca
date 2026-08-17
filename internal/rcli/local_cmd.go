package rcli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/termio"
)

// `csr new` and `inspect` are the two commands that never contact the server,
// and that is the point of them rather than an implementation detail.
//
// The API does expose equivalents (POST /csr, POST /inspect), and using them
// would be a downgrade: POST /csr generates the private key *on the server* and
// returns it over the wire, and POST /inspect uploads a third-party certificate
// somewhere it has no reason to go. Both are done here with internal/pki, which
// the client already links. They keep working with no server configured, and
// the end-to-end test proves it by running them against a closed port.

func newCSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Generate signing requests locally",
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
	)
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a private key and CSR, entirely on this machine",
		Long: strings.TrimSpace(`
Produces a key and a CSR and stores neither anywhere. Nothing is sent to the
server - this works with no server configured at all - so the private key
never leaves this machine. Sign the request afterwards with
` + "`gocactl cert sign --csr <file>`" + `, the portal, or an entirely different CA.

Note the key type defaults to rsa-2048 here rather than to the server's
configured default, which this command deliberately does not ask for.`),
		Example: strings.TrimSpace(`
  gocactl csr new --common-name app.internal.lan --san app.internal.lan --out ./req
  gocactl csr new --common-name app.internal.lan --csr-out app.csr --key-out app.key`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cn == "" {
				if !termio.Interactive() {
					return fmt.Errorf("--common-name is required")
				}
				termio.Section("New certificate signing request")
				cn = termio.AskRequired("Common name (CN)", "")
				if len(sans) == 0 {
					if v := termio.Ask("Subject alternative names (comma separated)", cn); v != "" {
						sans = splitCSV(v)
					}
				}
				org = termio.Ask("Organization (O)", org)
				country = termio.Ask("Country code (C)", country)
			}

			kt, err := pki.ParseKeyType(orDefault(keyType, "rsa-2048"))
			if err != nil {
				return err
			}
			subject := pki.Subject{
				CommonName: cn, Organization: org, OrganizationalUnit: ou,
				Country: country, Province: province, Locality: locality,
			}
			if err := subject.Validate(); err != nil {
				return err
			}
			parsedSANs, err := pki.ParseSANs(sans)
			if err != nil {
				return err
			}
			gen, err := pki.GenerateCSR(pki.CSRRequest{Subject: subject, SANs: parsedSANs, KeyType: kt})
			if err != nil {
				return err
			}

			if flagJSON {
				parsed, err := pki.ParseCSR(gen.CSRPEM)
				if err != nil {
					return err
				}
				return termio.PrintJSON(map[string]any{
					"csr_pem":         string(gen.CSRPEM),
					"private_key_pem": string(gen.PrivateKeyPEM),
					"key_type":        string(gen.KeyType),
					"info":            pki.DescribeCSR(parsed),
				})
			}

			base := safeFileName(cn)
			switch {
			case outDir != "":
				if err := os.MkdirAll(outDir, 0o750); err != nil {
					return err
				}
				if err := termio.WriteOut(filepath.Join(outDir, base+".key"), gen.PrivateKeyPEM, 0o600); err != nil {
					return err
				}
				if err := termio.WriteOut(filepath.Join(outDir, base+".csr"), gen.CSRPEM, 0o644); err != nil {
					return err
				}
			case csrOut != "" || keyOut != "":
				if keyOut != "" {
					if err := termio.WriteOut(keyOut, gen.PrivateKeyPEM, 0o600); err != nil {
						return err
					}
				}
				if csrOut != "" {
					if err := termio.WriteOut(csrOut, gen.CSRPEM, 0o644); err != nil {
						return err
					}
				}
			default:
				fmt.Print(string(gen.PrivateKeyPEM))
				fmt.Print(string(gen.CSRPEM))
				termio.Warn("this key exists only here; save it before it scrolls away")
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&cn, "common-name", "", "subject common name (CN)")
	fl.StringVar(&org, "organization", "", "subject organization (O)")
	fl.StringVar(&ou, "organizational-unit", "", "subject organizational unit (OU)")
	fl.StringVar(&country, "country", "", "subject country code (C)")
	fl.StringVar(&province, "province", "", "subject state/province (ST)")
	fl.StringVar(&locality, "locality", "", "subject locality (L)")
	fl.StringSliceVar(&sans, "san", nil, "subject alternative name (repeatable)")
	fl.StringVar(&keyType, "key-type", "", "key algorithm (default rsa-2048; this command never asks the server)")
	fl.StringVar(&outDir, "out", "", "write <cn>.key and <cn>.csr into this directory")
	fl.StringVar(&csrOut, "csr-out", "", "write the CSR here")
	fl.StringVar(&keyOut, "key-out", "", "write the private key here")
	return cmd
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Decode a certificate or CSR, entirely on this machine",
		Long: strings.TrimSpace(`
The local equivalent of ` + "`openssl x509 -text -noout`" + `. Nothing is uploaded -
this works with no server configured - so a certificate someone sent you is
never handed to a server that has no reason to see it.`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				data []byte
				err  error
			)
			if args[0] == "-" {
				data, err = io.ReadAll(os.Stdin)
			} else {
				data, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}

			if strings.Contains(string(data), "CERTIFICATE REQUEST") {
				csr, err := pki.ParseCSR(data)
				if err != nil {
					return err
				}
				info := pki.DescribeCSR(csr)
				if flagJSON {
					return termio.PrintJSON(info)
				}
				termio.Section("Certificate signing request")
				termio.KV("subject", info.Subject)
				termio.KV("common name", info.CommonName)
				if len(info.SANs) > 0 {
					termio.KV("SANs", strings.Join(info.SANs, ", "))
				}
				termio.KV("key type", info.KeyType)
				termio.KV("signature", info.SignatureAlgorithm)
				return nil
			}

			cert, err := pki.ParseCertPEM(data)
			if err != nil {
				return err
			}
			info := pki.Describe(cert)
			if flagJSON {
				return termio.PrintJSON(info)
			}
			termio.Section(info.Subject)
			termio.KV("issuer", info.Issuer)
			termio.KV("serial", info.Serial)
			if len(info.SANs) > 0 {
				termio.KV("SANs", strings.Join(info.SANs, ", "))
			}
			termio.KV("valid from", info.NotBefore.Local().Format("2006-01-02 15:04"))
			termio.KV("valid until", fmt.Sprintf("%s (%d days)",
				info.NotAfter.Local().Format("2006-01-02 15:04"), info.DaysRemaining))
			termio.KV("is CA", info.IsCA)
			termio.KV("key type", info.KeyType)
			termio.KV("signature", info.SignatureAlgorithm)
			if len(info.KeyUsage) > 0 {
				termio.KV("key usage", strings.Join(info.KeyUsage, ", "))
			}
			if len(info.ExtKeyUsage) > 0 {
				termio.KV("extended key usage", strings.Join(info.ExtKeyUsage, ", "))
			}
			termio.KV("SHA-256", info.FingerprintSHA256)
			return nil
		},
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
