package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

func newCertRenewCmd() *cobra.Command {
	var (
		days       int
		sameKey    bool
		caRef      string
		keyType    string
		revokeOld  bool
		note       string
		outDir     string
		expiringIn int
		all        bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:     "renew [id|serial]",
		Aliases: []string{"reissue", "rotate"},
		Short:   "Issue a replacement for a certificate, keeping its subject and SANs",
		Long: strings.TrimSpace(`
Rotates a certificate. The replacement carries the same subject, SANs and
profile, and by default gets a brand new private key - which is the point of
rotating, since it retires the old key as well as the old certificate.

Use --same-key when the key is pinned somewhere and only the certificate should
change. Note that this keeps a compromised key in play; prefer a new key.

The old certificate is left valid so you can deploy the new one first. Add
--revoke-old to retire it in the same step, which records it as superseded.

Pass --expiring-in N --all to rotate everything due within N days.`),
		Example: strings.TrimSpace(`
  goca cert renew 12
  goca cert renew 12 --days 397 --revoke-old --out ./app
  goca cert renew 3A7F1C... --same-key
  goca cert renew --expiring-in 30 --all --yes`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()

			in := ca.RenewInput{
				Days:      days,
				SameKey:   sameKey,
				CARef:     caRef,
				KeyType:   keyType,
				RevokeOld: revokeOld,
				Note:      note,
				Actor:     a.actor(),
			}

			// Batch mode.
			if all || (len(args) == 0 && expiringIn > 0) {
				if expiringIn <= 0 {
					expiringIn = 30
				}
				due, _, err := a.svc.Search(ctx, store.CertFilter{
					ExpiringIn: expiringIn, Limit: 1000, SortBy: "not_after"})
				if err != nil {
					return err
				}
				if len(due) == 0 {
					fmt.Printf("Nothing expires within %d days.\n", expiringIn)
					return nil
				}
				if !flagJSON {
					section(fmt.Sprintf("%d certificate(s) expiring within %d days", len(due), expiringIn))
					t := newTable("id", "common name", "expires", "days")
					for _, c := range due {
						t.row(c.ID, c.CommonName, c.NotAfter.Format("2006-01-02"), c.DaysLeft())
					}
					t.flush()
					fmt.Println()
				}
				if !yes {
					if !interactive() {
						return fmt.Errorf("refusing to renew %d certificates non-interactively; pass --yes", len(due))
					}
					if !askYesNo("Renew all of them?", false) {
						return nil
					}
				}
				results, errs := a.svc.RenewExpiring(ctx, expiringIn, in)
				if flagJSON {
					return printJSON(map[string]any{"renewed": results, "errors": errorStrings(errs)})
				}
				for _, r := range results {
					ok("%s → new serial %s (valid until %s)", r.Certificate.CommonName,
						r.Certificate.SerialHex, r.Certificate.NotAfter.Format("2006-01-02"))
				}
				for _, e := range errs {
					warn("%v", e)
				}
				fmt.Printf("\n%d renewed, %d failed\n", len(results), len(errs))
				if len(errs) > 0 {
					return fmt.Errorf("%d certificate(s) could not be renewed", len(errs))
				}
				return nil
			}

			if len(args) == 0 {
				return fmt.Errorf("give a certificate id or serial, or use --expiring-in N --all")
			}
			old, err := a.svc.FindCertificate(ctx, args[0])
			if err != nil {
				return err
			}
			res, err := a.svc.Renew(ctx, old.ID, in)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(res)
			}

			c := res.Certificate
			section("Certificate renewed")
			kv("common name", c.CommonName)
			kv("previous serial", res.Previous.SerialHex)
			kv("new serial", c.SerialHex)
			kv("key", map[bool]string{true: "reused", false: "newly generated"}[sameKey])
			kv("valid until", fmt.Sprintf("%s (%d days)", c.NotAfter.Format("2006-01-02"), c.DaysLeft()))
			kv("authority", c.CAName)
			if res.RevokedOld {
				kv("previous certificate", "revoked as superseded")
			} else {
				kv("previous certificate", "still valid — revoke it once the new one is deployed")
			}

			if outDir != "" {
				fmt.Println()
				if err := os.MkdirAll(outDir, 0o750); err != nil {
					return err
				}
				base := safeName(c.CommonName)
				if err := writeOut(filepath.Join(outDir, base+".crt"), []byte(c.CertPEM), 0o644); err != nil {
					return err
				}
				if res.PrivateKeyPEM != "" {
					if err := writeOut(filepath.Join(outDir, base+".key"), []byte(res.PrivateKeyPEM), 0o600); err != nil {
						return err
					}
				}
				if res.ChainPEM != "" {
					full := append([]byte(c.CertPEM), []byte(res.ChainPEM)...)
					if err := writeOut(filepath.Join(outDir, base+"-fullchain.pem"), full, 0o644); err != nil {
						return err
					}
				}
			} else if res.PrivateKeyPEM != "" && !c.HasKey {
				fmt.Println()
				warn("this key is not stored; the copy below is the only one")
				fmt.Print(res.PrivateKeyPEM)
			}

			if !res.RevokedOld {
				fmt.Println()
				info("retire the old one when ready: goca cert revoke %d --reason superseded", res.Previous.ID)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&days, "days", 0, "validity of the replacement (default: the same span as the original)")
	fl.BoolVar(&sameKey, "same-key", false, "reuse the existing private key instead of generating a new one")
	fl.StringVar(&caRef, "ca", "", "issue the replacement from a different authority")
	fl.StringVar(&keyType, "key-type", "", "key type for the new key (ignored with --same-key)")
	fl.BoolVar(&revokeOld, "revoke-old", false, "revoke the previous certificate as superseded")
	fl.StringVar(&note, "note", "", "note to store with the replacement")
	fl.StringVar(&outDir, "out", "", "write the new certificate, key and chain into this directory")
	fl.IntVar(&expiringIn, "expiring-in", 0, "batch mode: renew everything expiring within N days")
	fl.BoolVar(&all, "all", false, "batch mode: renew every match")
	fl.BoolVar(&yes, "yes", false, "do not ask for confirmation in batch mode")
	return cmd
}

func newCertHoldCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hold <id|serial>",
		Short: "Suspend a certificate reversibly (RFC 5280 certificateHold)",
		Long: strings.TrimSpace(`
Puts a certificate on hold. It appears on the CRL exactly like a revoked one,
but the decision can be undone with ` + "`goca cert release`" + `.

Use it when you suspect a problem but have not confirmed it. Once you are sure a
key is compromised, revoke properly instead - that cannot be walked back, which
is the point.`),
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
			if err := a.svc.Hold(cmd.Context(), c.ID, a.actor()); err != nil {
				return err
			}
			ok("%s is on hold (serial %s)", c.CommonName, c.SerialHex)
			info("it will appear on the next CRL; release it with: goca cert release %d", c.ID)
			return nil
		},
	}
}

func newCertReleaseCmd() *cobra.Command {
	var withCRL bool
	cmd := &cobra.Command{
		Use:     "release <id|serial>",
		Aliases: []string{"unhold"},
		Short:   "Lift a hold and return a certificate to active use",
		Long: strings.TrimSpace(`
Reinstates a certificate that was placed on hold, removing it from the next CRL.

Only a hold can be lifted. Every other revocation reason is a permanent
statement about the certificate, and goca will not undo it.`),
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
			if err := a.svc.Release(ctx, c.ID, a.actor()); err != nil {
				return err
			}
			ok("%s is active again (serial %s)", c.CommonName, c.SerialHex)
			if withCRL {
				if _, _, err := a.svc.GenerateCRL(ctx, c.CAID, a.actor()); err != nil {
					return err
				}
				ok("regenerated the CRL for %s", c.CAName)
			} else {
				info("publish the change with: goca ca crl %d", c.CAID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&withCRL, "crl", false, "regenerate the authority's CRL immediately")
	return cmd
}

// newCertBulkRevokeCmd extends revocation to whole sets of certificates.
func newCertBulkRevokeCmd() *cobra.Command {
	var (
		reason  string
		caRef   string
		query   string
		status  string
		profile string
		expired bool
		yes     bool
		withCRL bool
	)
	cmd := &cobra.Command{
		Use:   "revoke-many",
		Short: "Revoke every certificate matching a filter",
		Long: strings.TrimSpace(`
Revokes certificates in bulk. At least one filter is required - the command
refuses to act on an unfiltered set, because "revoke everything" is rarely what
anyone means.

The matching certificates are listed and confirmed before anything happens.
Certificates that are already revoked are skipped rather than treated as errors,
so the command is safe to re-run.`),
		Example: strings.TrimSpace(`
  goca cert revoke-many --ca branch-issuing-ca --reason cessationOfOperation
  goca cert revoke-many --query old.internal.lan --reason superseded
  goca cert revoke-many --profile client --ca acme-issuing-ca --yes`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			ctx := cmd.Context()

			if caRef == "" && query == "" && profile == "" && !expired {
				return fmt.Errorf("give at least one filter: --ca, --query, --profile or --expired")
			}
			code, err := pki.ParseReason(reason)
			if err != nil {
				return err
			}

			filter := store.CertFilter{
				Query:   query,
				Status:  status,
				Profile: profile,
				Limit:   1000,
			}
			if expired {
				filter.Status = store.StatusExpired
			}
			if caRef != "" {
				c, err := a.svc.ResolveCA(ctx, caRef)
				if err != nil {
					return err
				}
				filter.CAID = c.ID
			}

			matches, total, err := a.svc.Search(ctx, filter)
			if err != nil {
				return err
			}
			if total == 0 {
				fmt.Println("Nothing matched that filter.")
				return nil
			}

			if !flagJSON {
				section(fmt.Sprintf("%d certificate(s) matched", total))
				t := newTable("id", "common name", "authority", "status", "expires")
				for _, c := range matches {
					t.row(c.ID, c.CommonName, c.CAName, c.EffectiveStatus(),
						c.NotAfter.Format("2006-01-02"))
				}
				t.flush()
				fmt.Println()
			}
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to revoke %d certificates non-interactively; pass --yes", total)
				}
				warn("revocation cannot be undone (except for holds)")
				if !askYesNo(fmt.Sprintf("Revoke all %d as %q?", total, pki.ReasonName(code)), false) {
					return nil
				}
			}

			res, err := a.svc.BulkRevoke(ctx, ca.BulkRevokeInput{
				Filter: &filter, Reason: code, Actor: a.actor()})
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(res)
			}
			ok("revoked %d certificate(s) as %s", len(res.Revoked), pki.ReasonName(code))
			for _, s := range res.Skipped {
				info("skipped: %s", s)
			}
			for _, e := range res.Errors {
				warn("%s", e)
			}
			if withCRL {
				for _, id := range res.CAIDs {
					if _, _, err := a.svc.GenerateCRL(ctx, id, a.actor()); err != nil {
						warn("CRL for authority %d: %v", id, err)
						continue
					}
					ok("regenerated the CRL for authority %d", id)
				}
			} else if len(res.CAIDs) > 0 {
				info("publish with: goca ca crl <authority>")
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&reason, "reason", "unspecified", "RFC 5280 revocation reason")
	fl.StringVar(&caRef, "ca", "", "limit to one authority")
	fl.StringVarP(&query, "query", "q", "", "free-text match on name, SAN, serial or requester")
	fl.StringVar(&status, "status", "", "limit to active, expired or revoked")
	fl.StringVar(&profile, "profile", "", "limit to one profile")
	fl.BoolVar(&expired, "expired", false, "limit to already-expired certificates")
	fl.BoolVar(&yes, "yes", false, "do not ask for confirmation")
	fl.BoolVar(&withCRL, "crl", false, "regenerate affected CRLs immediately")
	return cmd
}

// newCertHistoryCmd shows the rotation chain a certificate belongs to.
func newCertHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history <id|serial>",
		Short: "Show the renewal chain a certificate belongs to",
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
			chain, err := a.svc.RenewalHistory(cmd.Context(), c)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(chain)
			}
			section(fmt.Sprintf("Rotation history for %s", c.CommonName))
			t := newTable("", "id", "serial", "issued", "expires", "status", "key")
			for _, h := range chain {
				marker := " "
				if h.ID == c.ID {
					marker = "→"
				}
				key := "-"
				if h.HasKey {
					key = "stored"
				}
				t.row(marker, h.ID, h.SerialHex, h.CreatedAt.Format("2006-01-02"),
					h.NotAfter.Format("2006-01-02"), h.EffectiveStatus(), key)
			}
			t.flush()
			if len(chain) == 1 {
				fmt.Println()
				info("this certificate has not been renewed")
			}
			return nil
		},
	}
}

func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}
