package rcli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secret",
		Short:   "Manage the secret vault",
		Aliases: []string{"secrets"},
		Long: strings.TrimSpace(`
goca's secret manager stores three kinds of secret:

  kv          an opaque value (a password, an API key, ...)
  file        a named file (a kubeconfig, a credentials JSON blob, ...)
  certificate materialized on demand from a certificate goca already issued -
              nothing is stored beyond a pointer to that certificate

Every kv/file write creates a new, immutable version; nothing is overwritten.
Payloads are sealed at rest with a hybrid ML-KEM-768 + X25519 envelope - see
docs/secrets.md for what that buys over the AES-256-GCM goca already used.

Sealing and unsealing happen on the server, which holds the master key; this
client only ever sees the plaintext it asked for.`),
	}
	cmd.AddCommand(
		newSecretCreateCmd(),
		newSecretPutCmd(),
		newSecretGetCmd(),
		newSecretListCmd(),
		newSecretRmCmd(),
		newSecretVersionsCmd(),
		newSecretBindCmd(),
	)
	return cmd
}

func newSecretListCmd() *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListSecrets(ctx, typ)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No secrets yet. Create one with `gocactl secret create <name>`.")
				return nil
			}
			t := termio.NewTable("name", "type", "version", "state", "updated")
			for _, s := range res.Value {
				state := "active"
				if s.Disabled {
					state = "disabled"
				} else if s.RotationDue {
					state = "rotation due"
				}
				t.Row(s.Name, s.Type, s.CurrentVersion, state, s.UpdatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "only list one type: kv, file or certificate")
	return cmd
}

func newSecretCreateCmd() *cobra.Command {
	var (
		typ, description string
		labels           []string
		rotationDays     int
		certRef          string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Register a new secret's metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			labelMap, err := parseLabels(labels)
			if err != nil {
				return err
			}
			in := gocaclient.CreateSecretInput{
				Name:         args[0],
				Type:         typ,
				Description:  description,
				Labels:       labelMap,
				RotationDays: rotationDays,
			}
			if certRef != "" {
				// The API takes a numeric cert_id, so resolve the operator's
				// id-or-serial into one first.
				cert, err := c.GetCert(ctx, certRef)
				if err != nil {
					return fmt.Errorf("resolve --cert %q: %w", certRef, err)
				}
				id := cert.Value.ID
				in.CertID = &id
			}
			res, err := c.CreateSecret(ctx, in)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created %q (%s)", res.Value.Name, res.Value.Type)
			if res.Value.Type != "certificate" {
				termio.Info("write its first version with: gocactl secret put %s <value>", res.Value.Name)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&typ, "type", "kv", "kv, file or certificate")
	fl.StringVar(&description, "description", "", "human-readable description")
	fl.StringSliceVar(&labels, "label", nil, "key=value label (repeatable)")
	fl.IntVar(&rotationDays, "rotation-days", 0, "flag it overdue for rotation after N days (0 = never)")
	fl.StringVar(&certRef, "cert", "", "certificate id or serial (required for --type certificate)")
	return cmd
}

func parseLabels(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid --label %q, want key=value", p)
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, nil
}

func newSecretPutCmd() *cobra.Command {
	var (
		fromFile  string
		fromStdin bool
		create    bool
	)
	cmd := &cobra.Command{
		Use:   "put <name> [value]",
		Short: "Write a new version of a kv or file secret",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			name := args[0]

			var value []byte
			contentType := ""
			switch {
			case fromFile != "":
				if value, err = os.ReadFile(fromFile); err != nil {
					return err
				}
				contentType = filepath.Base(fromFile)
			case fromStdin:
				if value, err = io.ReadAll(os.Stdin); err != nil {
					return err
				}
			case len(args) == 2:
				value = []byte(args[1])
			default:
				return fmt.Errorf("provide a value, or one of --file / --stdin")
			}

			if create {
				if _, err := c.GetSecret(ctx, name); err != nil {
					if _, cerr := c.CreateSecret(ctx, gocaclient.CreateSecretInput{
						Name: name, Type: "kv",
					}); cerr != nil {
						return fmt.Errorf("auto-create %q: %w", name, cerr)
					}
				}
			}

			res, err := c.PutSecretVersion(ctx, name, value, contentType)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("%s: wrote version %d (%d bytes)", name, res.Value.Version, res.Value.SizeBytes)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&fromFile, "file", "", "read the payload from this file")
	fl.BoolVar(&fromStdin, "stdin", false, "read the payload from stdin")
	fl.BoolVar(&create, "create", false, "create the secret (as kv) first if it does not exist")
	return cmd
}

func newSecretGetCmd() *cobra.Command {
	var (
		version int
		out     string
		outDir  string
	)
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Read a secret's current (or one specific) version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			sec, err := c.GetSecret(ctx, args[0])
			if err != nil {
				return err
			}

			if sec.Value.Type == "certificate" {
				if outDir == "" {
					return fmt.Errorf("%q is a certificate secret; pass --out-dir to write tls.crt/tls.key/ca.crt", args[0])
				}
				files, ver, _, err := c.MaterializeSecret(ctx, args[0])
				if err != nil {
					return err
				}
				if err := os.MkdirAll(outDir, 0o750); err != nil {
					return err
				}
				for _, f := range files {
					mode := os.FileMode(0o644)
					if f.Name == "tls.key" {
						mode = 0o600
					}
					if err := os.WriteFile(filepath.Join(outDir, f.Name), f.Data, mode); err != nil {
						return err
					}
				}
				termio.OK("%s: wrote %d files to %s (%s)", args[0], len(files), outDir, ver)
				return nil
			}

			if version > 0 {
				data, err := c.GetSecretVersion(ctx, args[0], version)
				if err != nil {
					return err
				}
				return termio.WriteOut(out, data, 0o600)
			}
			files, _, _, err := c.MaterializeSecret(ctx, args[0])
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return fmt.Errorf("%q has no active version", args[0])
			}
			return termio.WriteOut(out, files[0].Data, 0o600)
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&version, "version", 0, "a specific version instead of the latest")
	fl.StringVar(&out, "out", "", "write to this file instead of stdout (kv/file secrets)")
	fl.StringVar(&outDir, "out-dir", "", "directory for tls.crt/tls.key/ca.crt (certificate secrets)")
	return cmd
}

func newSecretRmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"delete"},
		Short:   "Delete a secret, every version and every binding",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", args[0])
				}
				if !termio.AskYesNo(fmt.Sprintf("Delete secret %q and every version? This cannot be undone.", args[0]), false) {
					return nil
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.DeleteSecret(ctx, args[0]); err != nil {
				return err
			}
			termio.OK("deleted %q", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newSecretVersionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "versions <name>",
		Short: "List every version of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.SecretVersions(ctx, args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No versions yet.")
				return nil
			}
			t := termio.NewTable("version", "size", "sha256", "state", "created")
			for _, v := range res.Value {
				state := "active"
				if v.Destroyed {
					state = "destroyed"
				}
				t.Row(v.Version, v.SizeBytes, truncate(v.PayloadSHA256, 16), state,
					v.CreatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.Flush()
			return nil
		},
	}
	cmd.AddCommand(newSecretVersionDestroyCmd())
	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func newSecretVersionDestroyCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "destroy <name> <version>",
		Short: "Permanently scrub one version's ciphertext",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			ver, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("%q is not a version number", args[1])
			}
			if !yes {
				if !termio.Interactive() {
					return fmt.Errorf("refusing to destroy version %d of %q non-interactively; pass --yes", ver, args[0])
				}
				if !termio.AskYesNo(fmt.Sprintf("Permanently destroy version %d of %q?", ver, args[0]), false) {
					return nil
				}
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.DestroySecretVersion(ctx, args[0], ver); err != nil {
				return err
			}
			termio.OK("destroyed version %d of %q", ver, args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newSecretBindCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Authorize Kubernetes workloads to read a secret",
	}
	cmd.AddCommand(newSecretBindAddCmd(), newSecretBindListCmd(), newSecretBindRmCmd())
	return cmd
}

func newSecretBindAddCmd() *cobra.Command {
	var (
		namespace, serviceAccount, authMethod string
		expiresInDays                         int
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a binding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.BindSecret(ctx, args[0], namespace, serviceAccount, authMethod, expiresInDays)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("bound %s to namespace=%s service-account=%s auth-method=%s",
				args[0], res.Value.K8sNamespace, res.Value.K8sServiceAccount, res.Value.K8sAuthMethod)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&namespace, "namespace", "*", "namespace glob pattern")
	fl.StringVar(&serviceAccount, "service-account", "*", "ServiceAccount glob pattern")
	fl.StringVar(&authMethod, "auth-method", "*", "CSI trust domain (k8s auth method) glob pattern; '*' matches any cluster")
	fl.IntVar(&expiresInDays, "expires-in-days", 0, "revoke automatically after N days (0 = never)")
	return cmd
}

func newSecretBindListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list <name>",
		Aliases: []string{"ls"},
		Short:   "List a secret's bindings",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.SecretBindings(ctx, args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No bindings yet.")
				return nil
			}
			t := termio.NewTable("id", "namespace", "service account", "auth method", "state", "expires")
			for _, b := range res.Value {
				state := "active"
				if !b.Usable() {
					state = "expired"
				}
				expires := "never"
				if b.ExpiresAt != nil {
					expires = b.ExpiresAt.Local().Format("2006-01-02")
				}
				t.Row(b.ID, b.K8sNamespace, b.K8sServiceAccount, b.K8sAuthMethod, state, expires)
			}
			t.Flush()
			return nil
		},
	}
}

func newSecretBindRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <binding-id>",
		Aliases: []string{"delete", "unbind"},
		Short:   "Revoke a binding",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a binding id (see `gocactl secret bind list <name>`)", args[0])
			}
			c, err := client()
			if err != nil {
				return err
			}
			if err := c.UnbindSecret(ctx, id); err != nil {
				return err
			}
			termio.OK("revoked binding %d", id)
			return nil
		},
	}
}
