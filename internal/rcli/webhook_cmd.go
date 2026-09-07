package rcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

// This file is the gocactl surface for webhooks (G9): named HTTP endpoints
// that receive signed event notifications when goca records an audit action.
// It is the remote counterpart to the server's /api/v1/webhooks REST
// endpoints.

func newWebhookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "webhook",
		Aliases: []string{"hooks"},
		Short:   "Manage webhooks (signed event notifications)",
	}
	cmd.AddCommand(
		newWebhookListCmd(),
		newWebhookCreateCmd(),
		newWebhookUpdateCmd(),
		newWebhookDisableCmd(),
		newWebhookDeleteCmd(),
		newWebhookDeliveriesCmd(),
	)
	return cmd
}

func newWebhookListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List webhooks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.ListWebhooks(ctx)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No webhooks configured.")
				return nil
			}
			t := termio.NewTable("id", "name", "url", "events", "state")
			for _, wh := range res.Value {
				state := "active"
				if wh.Disabled {
					state = "disabled"
				}
				t.Row(wh.ID, wh.Name, wh.URL, wh.Events, state)
			}
			t.Flush()
			return nil
		},
	}
}

func newWebhookCreateCmd() *cobra.Command {
	var (
		url    string
		events string
		secret string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a webhook",
		Long: strings.TrimSpace(`
Registers a named HTTP endpoint that receives a signed JSON event whenever
goca records an audit action matching the event filter. The filter is a
comma-separated list of action prefixes (e.g. "cert.issue,secret.put"); "*"
matches every event. The --secret signing key is encrypted at rest and never
shown again; each delivery is signed with HMAC-SHA256 in the X-Goca-Signature
header.`),
		Example: strings.TrimSpace(`
  gocactl webhook create ops --url https://hooks.example.com/goca --events '*'
  gocactl webhook create cert-audit --url https://hooks.example.com/certs --events cert.issue,cert.revoke --secret s3cr3t`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			res, err := c.CreateWebhook(ctx, gocaclient.Webhook{
				Name:   args[0],
				URL:    url,
				Events: events,
				Secret: secret,
			})
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("created webhook %q (id %d)", res.Value.Name, res.Value.ID)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&url, "url", "", "endpoint to POST events to (required)")
	fl.StringVar(&events, "events", "*", "comma-separated action prefixes to match; '*' = all")
	fl.StringVar(&secret, "secret", "", "HMAC signing key (encrypted at rest; omit for unsigned)")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func newWebhookUpdateCmd() *cobra.Command {
	var (
		url    string
		events string
		secret string
	)
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a webhook",
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
				return fmt.Errorf("%q is not a webhook id (see `gocactl webhook list`)", args[0])
			}
			// Fetch the current row so unchanged fields are preserved.
			cur, err := c.GetWebhook(ctx, id)
			if err != nil {
				return err
			}
			in := gocaclient.Webhook{
				Name:     cur.Value.Name,
				URL:      cur.Value.URL,
				Events:   cur.Value.Events,
				Disabled: cur.Value.Disabled,
			}
			fl := cmd.Flags()
			if fl.Changed("url") {
				in.URL = url
			}
			if fl.Changed("events") {
				in.Events = events
			}
			if fl.Changed("secret") {
				in.Secret = secret
			}
			res, err := c.UpdateWebhook(ctx, id, in)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			termio.OK("updated webhook %q (id %d)", res.Value.Name, res.Value.ID)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&url, "url", "", "new endpoint to POST events to")
	fl.StringVar(&events, "events", "", "new comma-separated action prefixes; '*' = all")
	fl.StringVar(&secret, "secret", "", "new HMAC signing key (encrypted at rest)")
	return cmd
}

func newWebhookDisableCmd() *cobra.Command {
	var enable bool
	cmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "Disable a webhook (skips all its deliveries)",
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
				return fmt.Errorf("%q is not a webhook id (see `gocactl webhook list`)", args[0])
			}
			if err := c.SetWebhookDisabled(ctx, id, !enable); err != nil {
				return err
			}
			if enable {
				termio.OK("enabled webhook %d", id)
			} else {
				termio.OK("disabled webhook %d", id)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "re-enable instead of disable")
	return cmd
}

func newWebhookDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"rm"},
		Short:   "Delete a webhook and its delivery history",
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
				return fmt.Errorf("%q is not a webhook id (see `gocactl webhook list`)", args[0])
			}
			if err := c.DeleteWebhook(ctx, id); err != nil {
				return err
			}
			termio.OK("deleted webhook %d", id)
			return nil
		},
	}
}

func newWebhookDeliveriesCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:     "deliveries <id>",
		Aliases: []string{"history"},
		Short:   "Show recent delivery attempts for a webhook",
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
				return fmt.Errorf("%q is not a webhook id (see `gocactl webhook list`)", args[0])
			}
			res, err := c.ListWebhookDeliveries(ctx, id, limit)
			if err != nil {
				return err
			}
			if flagJSON {
				return termio.PrintRaw(res.Raw)
			}
			if len(res.Value) == 0 {
				fmt.Println("No deliveries recorded.")
				return nil
			}
			t := termio.NewTable("id", "event", "status", "attempts", "last status", "last error")
			for _, d := range res.Value {
				t.Row(d.ID, d.Event, d.Status, d.Attempts, d.LastStatus, truncate(d.LastError, 40))
			}
			t.Flush()
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of deliveries to show")
	return cmd
}
