package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// newSecretCmd groups goca's secret manager: named, versioned secrets sealed
// with a hybrid ML-KEM-768 + X25519 envelope (see internal/pqcrypt and
// docs/secrets.md), stored alongside CAs and certificates, and - in a later
// phase - readable by Kubernetes workloads through the Secrets Store CSI
// Driver via the bindings managed here.
func newSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secret",
		Short:   "Manage the secret vault: kv/file secrets and certificate exports",
		Aliases: []string{"secrets", "vault"},
		Long: strings.TrimSpace(`
goca's secret manager stores three kinds of secret:

  kv          an opaque value (a password, an API key, ...)
  file        a named file (a kubeconfig, a credentials JSON blob, ...)
  certificate materialized on demand from a certificate goca already issued -
              nothing is stored beyond a pointer to that certificate

Every kv/file write creates a new, immutable version; nothing is overwritten.
Payloads are sealed at rest with a hybrid ML-KEM-768 + X25519 envelope - see
docs/secrets.md for what that buys over the AES-256-GCM goca already used.`),
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

// parseLabels turns repeated "key=value" flags into a map.
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

func newSecretCreateCmd() *cobra.Command {
	var (
		typ          string
		description  string
		labels       []string
		rotationDays int
		certRef      string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Register a new secret's metadata",
		Long: strings.TrimSpace(`
Creates a secret's metadata only. A kv or file secret has no version yet -
follow up with "goca secret put" to give it content. A certificate secret is
complete immediately: pass --cert with a certificate id or serial and it
always reflects that certificate's current state.`),
		Example: strings.TrimSpace(`
  goca secret create team-a/db/password --label env=prod
  goca secret create team-a/kubeconfig --type file
  goca secret create team-a/web-tls --type certificate --cert 42`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			labelMap, err := parseLabels(labels)
			if err != nil {
				return err
			}
			in := vault.CreateInput{
				Name:         args[0],
				Type:         typ,
				Description:  description,
				Labels:       labelMap,
				RotationDays: rotationDays,
				Actor:        a.actor(),
			}
			if certRef != "" {
				cert, err := a.svc.FindCertificate(cmd.Context(), certRef)
				if err != nil {
					return fmt.Errorf("resolve --cert %q: %w", certRef, err)
				}
				in.CertID = &cert.ID
			}
			sec, err := a.vault.Create(cmd.Context(), in)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(sec)
			}
			ok("created %q (%s)", sec.Name, sec.Type)
			if sec.Type != store.SecretTypeCertificate {
				info("write its first version with: goca secret put %s <value>", sec.Name)
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&typ, "type", store.SecretTypeKV, "secret type: kv, file or certificate")
	fl.StringVar(&description, "description", "", "human-readable description")
	fl.StringSliceVar(&labels, "label", nil, "key=value label (repeatable)")
	fl.IntVar(&rotationDays, "rotation-days", 0, "flag the secret overdue for rotation after N days (0 = never)")
	fl.StringVar(&certRef, "cert", "", "certificate id or serial to materialize (required when --type certificate)")
	return cmd
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
		Long: strings.TrimSpace(`
Seals value as a new, immutable version. The previous version is kept, not
overwritten - see "goca secret versions". Provide the payload as a trailing
argument, with --file, or with --stdin; exactly one is required.

With --create, a secret that does not exist yet is created first as type kv
- so a first write can be one command, the way "vault kv put" works.`),
		Example: strings.TrimSpace(`
  goca secret put team-a/db/password 'hunter2' --create
  goca secret put team-a/kubeconfig --file ./kubeconfig.yaml
  kubectl get secret app-tls -o jsonpath='{.data.ca\.crt}' | base64 -d | goca secret put team-a/ca-bundle --stdin`),
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			name := args[0]
			var value []byte
			contentType := ""
			switch {
			case fromFile != "":
				value, err = os.ReadFile(fromFile)
				if err != nil {
					return err
				}
				contentType = filepath.Base(fromFile)
			case fromStdin:
				value, err = io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
			case len(args) == 2:
				value = []byte(args[1])
			default:
				return fmt.Errorf("provide a value, or one of --file / --stdin")
			}

			if create {
				if _, err := a.vault.Get(cmd.Context(), name); err != nil {
					if _, cerr := a.vault.Create(cmd.Context(), vault.CreateInput{
						Name: name, Type: store.SecretTypeKV, Actor: a.actor(),
					}); cerr != nil {
						return fmt.Errorf("auto-create %q: %w", name, cerr)
					}
				}
			}

			v, err := a.vault.Put(cmd.Context(), name, value, contentType, a.actor())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(v)
			}
			ok("%s: wrote version %d (%d bytes)", name, v.Version, v.SizeBytes)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&fromFile, "file", "", "read the payload from this file")
	fl.BoolVar(&fromStdin, "stdin", false, "read the payload from stdin")
	fl.BoolVar(&create, "create", false, "create the secret (as type kv) first, if it does not exist")
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
		Long: strings.TrimSpace(`
For kv/file secrets, prints the raw payload to stdout, or writes it to --out.
For certificate secrets, --out-dir is required: it writes the standard
tls.crt / tls.key / ca.crt triad there, freshly resolved from the linked
certificate every time - a certificate secret has no version of its own.`),
		Example: strings.TrimSpace(`
  goca secret get team-a/db/password
  goca secret get team-a/kubeconfig --out ./kubeconfig.yaml
  goca secret get team-a/web-tls --out-dir ./certs`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()

			sec, err := a.vault.Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			if sec.Type == store.SecretTypeCertificate {
				if outDir == "" {
					return fmt.Errorf("%q is a certificate secret; pass --out-dir to write tls.crt/tls.key/ca.crt", sec.Name)
				}
				_, files, ver, err := a.vault.Materialize(cmd.Context(), sec.Name)
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
				ok("%s: wrote %d files to %s (%s)", sec.Name, len(files), outDir, ver)
				return nil
			}

			if version > 0 {
				_, pt, err := a.vault.GetVersion(cmd.Context(), sec.Name, version)
				if err != nil {
					return err
				}
				return writeOut(out, pt, 0o600)
			}
			_, pt, err := a.vault.GetLatest(cmd.Context(), sec.Name)
			if err != nil {
				return err
			}
			return writeOut(out, pt, 0o600)
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&version, "version", 0, "a specific version instead of the latest")
	fl.StringVar(&out, "out", "", "write to this file instead of stdout (kv/file secrets)")
	fl.StringVar(&outDir, "out-dir", "", "directory to write tls.crt/tls.key/ca.crt into (certificate secrets)")
	return cmd
}

func newSecretListCmd() *cobra.Command {
	var typ string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secrets",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			secrets, err := a.vault.List(cmd.Context(), typ)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(secrets)
			}
			if len(secrets) == 0 {
				fmt.Println("No secrets yet. Create one with `goca secret create <name>`.")
				return nil
			}
			t := newTable("name", "type", "version", "state", "updated")
			for _, s := range secrets {
				state := "active"
				if s.Disabled {
					state = "disabled"
				} else if s.RotationDue() {
					state = "rotation due"
				}
				t.row(s.Name, s.Type, s.CurrentVersion, state, s.UpdatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "only list one type: kv, file or certificate")
	return cmd
}

func newSecretRmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"delete"},
		Short:   "Delete a secret, every version and every binding permanently",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to delete %q non-interactively; pass --yes", args[0])
				}
				if !askYesNo(fmt.Sprintf("Delete secret %q and every version? This cannot be undone.", args[0]), false) {
					return nil
				}
			}
			if err := a.vault.Delete(cmd.Context(), args[0], a.actor()); err != nil {
				return err
			}
			ok("deleted %q", args[0])
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
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			_, versions, err := a.vault.Versions(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(versions)
			}
			if len(versions) == 0 {
				fmt.Println("No versions yet.")
				return nil
			}
			t := newTable("version", "size", "sha256", "state", "created")
			for _, v := range versions {
				state := "active"
				if v.Destroyed {
					state = "destroyed"
				}
				t.row(v.Version, v.SizeBytes, truncate(v.PayloadSHA256, 16), state,
					v.CreatedAt.Local().Format("2006-01-02 15:04"))
			}
			t.flush()
			return nil
		},
	}
	cmd.AddCommand(newSecretVersionDestroyCmd())
	return cmd
}

func newSecretVersionDestroyCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "destroy <name> <version>",
		Short: "Permanently scrub one version's ciphertext",
		Long: strings.TrimSpace(`
Crypto-shreds the stored ciphertext for one version while keeping its row (and
its place in the version history) - so audit trails and version numbers stay
intact, but the content is unrecoverable.`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ver, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("%q is not a version number", args[1])
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if !yes {
				if !interactive() {
					return fmt.Errorf("refusing to destroy version %d of %q non-interactively; pass --yes", ver, args[0])
				}
				if !askYesNo(fmt.Sprintf("Permanently destroy version %d of %q?", ver, args[0]), false) {
					return nil
				}
			}
			if err := a.vault.DestroyVersion(cmd.Context(), args[0], ver, a.actor()); err != nil {
				return err
			}
			ok("destroyed version %d of %q", ver, args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask for confirmation")
	return cmd
}

func newSecretBindCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Authorize Kubernetes (namespace, ServiceAccount) pairs to read a secret",
		Long: strings.TrimSpace(`
Bindings are the entire trust decision for the Secrets Store CSI Driver
provider (a later goca release): only a pod running as a bound namespace and
ServiceAccount may fetch the secret. Namespace and ServiceAccount are each
matched with shell-glob syntax ("web-*", "*"); an empty value means "*".`),
	}
	cmd.AddCommand(newSecretBindAddCmd(), newSecretBindListCmd(), newSecretBindRmCmd())
	return cmd
}

func newSecretBindAddCmd() *cobra.Command {
	var (
		namespace      string
		serviceAccount string
		authMethod     string
		expiresInDays  int
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a binding",
		Example: strings.TrimSpace(`
  goca secret bind add team-a/web-tls --namespace team-a --service-account web-*
  goca secret bind add team-a/shared-key --namespace '*' --service-account ci-runner --expires-in-days 30
  goca secret bind add prod/db --namespace team-a --service-account web --auth-method cluster-a`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			var expiresAt *time.Time
			if expiresInDays > 0 {
				t := time.Now().AddDate(0, 0, expiresInDays)
				expiresAt = &t
			}
			b, err := a.vault.Bind(cmd.Context(), args[0], namespace, serviceAccount, authMethod, expiresAt, a.actor())
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(b)
			}
			ok("bound %s to namespace=%s service-account=%s auth-method=%s", args[0], b.K8sNamespace, b.K8sServiceAccount, b.K8sAuthMethod)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&namespace, "namespace", "*", "namespace glob pattern")
	fl.StringVar(&serviceAccount, "service-account", "*", "ServiceAccount glob pattern")
	fl.StringVar(&authMethod, "auth-method", "*", "CSI trust domain (k8s auth method) glob pattern; '*' matches any cluster")
	fl.IntVar(&expiresInDays, "expires-in-days", 0, "revoke this binding automatically after N days (0 = never)")
	return cmd
}

func newSecretBindListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list <name>",
		Aliases: []string{"ls"},
		Short:   "List a secret's bindings",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			bindings, err := a.vault.Bindings(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(bindings)
			}
			if len(bindings) == 0 {
				fmt.Println("No bindings yet.")
				return nil
			}
			t := newTable("id", "namespace", "service account", "auth method", "state", "expires")
			for _, b := range bindings {
				state := "active"
				if !b.Usable() {
					state = "expired"
				}
				expires := "never"
				if b.ExpiresAt != nil {
					expires = b.ExpiresAt.Local().Format("2006-01-02")
				}
				t.row(b.ID, b.K8sNamespace, b.K8sServiceAccount, b.K8sAuthMethod, state, expires)
			}
			t.flush()
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
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a binding id (see `goca secret bind list <name>`)", args[0])
			}
			a, err := open()
			if err != nil {
				return err
			}
			defer a.Close()
			if err := a.vault.Unbind(cmd.Context(), id, a.actor()); err != nil {
				return err
			}
			ok("revoked binding %d", id)
			return nil
		},
	}
}
