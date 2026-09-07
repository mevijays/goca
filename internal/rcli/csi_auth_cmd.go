package rcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

// This file is the gocactl surface for CSI trust domains (k8s_auth_methods):
// the named Kubernetes clusters whose ServiceAccount tokens a goca server
// verifies. It is the remote counterpart to the server's
// /api/v1/csi-auth-methods REST endpoints.

func newCsiAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "csi-auth",
		Aliases: []string{"csi", "trust-domain"},
		Short:   "Manage CSI trust domains (Kubernetes clusters goca verifies)",
	}
	cmd.AddCommand(
		newCsiAuthListCmd(),
		newCsiAuthCreateCmd(),
		newCsiAuthUpdateCmd(),
		newCsiAuthDisableCmd(),
		newCsiAuthDeleteCmd(),
	)
	return cmd
}

func newCsiAuthListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List CSI trust domains",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListCsiAuthMethods(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No CSI trust domains configured.")
				return nil
			}
			t := termio.NewTable("id", "name", "audience", "issuer", "api server", "state")
			for _, m := range res.Value {
				state := "active"
				if m.Disabled {
					state = "disabled"
				}
				t.Row(m.ID, m.Name, m.Audience, m.IssuerURL, m.APIServerURL, state)
			}
			t.Flush()
			return nil
		},
	}
}

func newCsiAuthCreateCmd() *cobra.Command {
	var (
		audience           string
		issuerURL          string
		apiServerURL       string
		caCert             string
		reviewerToken      string
		insecureSkipVerify bool
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a CSI trust domain",
		Long: strings.TrimSpace(`
Registers a named Kubernetes cluster (or group of clusters sharing an issuer)
whose ServiceAccount tokens goca will verify. Provide either --issuer-url (the
cluster's ServiceAccount OIDC issuer) or --api-server-url plus --reviewer-token
(TokenReview API). The reviewer token is encrypted at rest and never shown
again.`),
		Example: strings.TrimSpace(`
  gocactl csi-auth create cluster-a --issuer-url https://sts.amazonaws.com --audience goca-csi
  gocactl csi-auth create cluster-b --api-server-url https://10.0.0.1:6443 --reviewer-token $(kubectl create token goca-server-token-reviewer -n goca-csi --duration=8760h) --ca-cert /path/ca.crt`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateCsiAuthMethod(ctx, gocaclient.CsiAuthMethod{
				Name:               args[0],
				Audience:           audience,
				IssuerURL:          issuerURL,
				APIServerURL:       apiServerURL,
				CACert:             caCert,
				ReviewerToken:      reviewerToken,
				InsecureSkipVerify: insecureSkipVerify,
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created CSI trust domain %q (id %d)", res.Value.Name, res.Value.ID)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&audience, "audience", "goca-csi", "token audience to verify")
	fl.StringVar(&issuerURL, "issuer-url", "", "cluster ServiceAccount OIDC issuer URL")
	fl.StringVar(&apiServerURL, "api-server-url", "", "cluster API server URL (TokenReview path)")
	fl.StringVar(&caCert, "ca-cert", "", "PEM CA to trust when calling the cluster API server")
	fl.StringVar(&reviewerToken, "reviewer-token", "", "ServiceAccount token for the TokenReview API (encrypted at rest)")
	fl.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "skip TLS verification for the cluster API server (lab use only)")
	return cmd
}

func newCsiAuthUpdateCmd() *cobra.Command {
	var (
		audience           string
		issuerURL          string
		apiServerURL       string
		caCert             string
		reviewerToken      string
		insecureSkipVerify bool
	)
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a CSI trust domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a trust domain id (see `gocactl csi-auth list`)", args[0])
			}
			// Fetch the current row so unchanged fields are preserved.
			cur, err := c.GetCsiAuthMethod(ctx, id)
			if err != nil {
				return err
			}
			in := gocaclient.CsiAuthMethod{
				Name:               cur.Value.Name,
				Audience:           cur.Value.Audience,
				IssuerURL:          cur.Value.IssuerURL,
				APIServerURL:       cur.Value.APIServerURL,
				CACert:             cur.Value.CACert,
				InsecureSkipVerify: cur.Value.InsecureSkipVerify,
				Disabled:           cur.Value.Disabled,
			}
			fl := cmd.Flags()
			if fl.Changed("audience") {
				in.Audience = audience
			}
			if fl.Changed("issuer-url") {
				in.IssuerURL = issuerURL
			}
			if fl.Changed("api-server-url") {
				in.APIServerURL = apiServerURL
			}
			if fl.Changed("ca-cert") {
				in.CACert = caCert
			}
			if fl.Changed("insecure-skip-verify") {
				in.InsecureSkipVerify = insecureSkipVerify
			}
			if fl.Changed("reviewer-token") {
				in.ReviewerToken = reviewerToken
			}
			res, err := c.UpdateCsiAuthMethod(ctx, id, in)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("updated CSI trust domain %q (id %d)", res.Value.Name, res.Value.ID)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&audience, "audience", "", "token audience to verify")
	fl.StringVar(&issuerURL, "issuer-url", "", "cluster ServiceAccount OIDC issuer URL")
	fl.StringVar(&apiServerURL, "api-server-url", "", "cluster API server URL (TokenReview path)")
	fl.StringVar(&caCert, "ca-cert", "", "PEM CA to trust when calling the cluster API server")
	fl.StringVar(&reviewerToken, "reviewer-token", "", "new ServiceAccount token for the TokenReview API (encrypted at rest)")
	fl.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "skip TLS verification for the cluster API server (lab use only)")
	return cmd
}

func newCsiAuthDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable a CSI trust domain (rejects all its tokens)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a trust domain id (see `gocactl csi-auth list`)", args[0])
			}
			if err := c.SetCsiAuthMethodDisabled(ctx, id, !enable); err != nil {
				return err
			}
			if enable {
				termio.OK("enabled CSI trust domain %d", id)
			} else {
				termio.OK("disabled CSI trust domain %d", id)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable instead of disable")
	return cmd
}

func newCsiAuthDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"rm"},
		Short:   "Delete a CSI trust domain",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a trust domain id (see `gocactl csi-auth list`)", args[0])
			}
			if err := c.DeleteCsiAuthMethod(ctx, id); err != nil {
				return err
			}
			termio.OK("deleted CSI trust domain %d", id)
			return nil
		},
	}
}
