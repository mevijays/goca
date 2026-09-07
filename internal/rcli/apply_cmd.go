package rcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/mevijays/goca/internal/gocaclient"
	"github.com/mevijays/goca/internal/termio"
)

// This file is the GitOps executor for goca's secret manager: `gocactl apply`
// and `gocactl diff`. A manifest declares the *metadata* of secrets and their
// CSI bindings - the declarative half of the workflow. Secret *values* stay
// out of git on purpose: they are pushed by a pipeline that holds the
// plaintext only transiently (`gocactl secret put`), or materialized from a
// certificate. The manifest is the source of truth for "which secrets exist,
// what they are called, and who may mount them"; `apply` converges the server
// to it, and `diff` reports the gap so a CI job can gate on it.

//
// ---------- manifest ----------
//

// Manifest is the on-disk shape of a goca secret manifest.
type Manifest struct {
	// APIVersion is accepted and currently must be "goca.dev/v1" when present.
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Secrets    []ManifestSecret `yaml:"secrets"`
}

// ManifestSecret declares one secret's metadata and its CSI bindings.
type ManifestSecret struct {
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"` // kv | file (certificate is managed imperatively)
	Description  string            `yaml:"description"`
	Labels       map[string]string `yaml:"labels"`
	RotationDays int               `yaml:"rotationDays"`
	Bindings     []ManifestBinding `yaml:"bindings"`
}

// ManifestBinding declares one CSI binding: which (namespace, ServiceAccount,
// trust domain) may mount the secret. All three are shell-glob patterns; an
// empty field means "*".
type ManifestBinding struct {
	Namespace      string `yaml:"namespace"`
	ServiceAccount string `yaml:"serviceAccount"`
	AuthMethod     string `yaml:"authMethod"`
	ExpiresInDays  int    `yaml:"expiresInDays"`
}

// parseManifest reads and validates a manifest file. A bare list of secrets
// (no apiVersion/kind wrapper) is accepted as a convenience.
func parseManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	m := &Manifest{}
	if err := yaml.Unmarshal(data, m); err != nil {
		// Convenience: a top-level list of secrets (no apiVersion/kind wrapper).
		var bare []ManifestSecret
		if berr := yaml.Unmarshal(data, &bare); berr == nil && len(bare) > 0 {
			m.Secrets = bare
		} else {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if m.APIVersion != "" && m.APIVersion != "goca.dev/v1" {
		return nil, fmt.Errorf("%s: unsupported apiVersion %q (want goca.dev/v1)", path, m.APIVersion)
	}
	// Canonicalize: an empty binding field means "*" (the server stores it
	// that way too), so make the manifest match what the server returns.
	for i := range m.Secrets {
		for j := range m.Secrets[i].Bindings {
			b := &m.Secrets[i].Bindings[j]
			b.Namespace = orStar(strings.TrimSpace(b.Namespace))
			b.ServiceAccount = orStar(strings.TrimSpace(b.ServiceAccount))
			b.AuthMethod = orStar(strings.TrimSpace(b.AuthMethod))
		}
	}
	if err := validateManifest(m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func validateManifest(m *Manifest) error {
	if len(m.Secrets) == 0 {
		return errors.New("manifest declares no secrets")
	}
	seen := map[string]bool{}
	for i, s := range m.Secrets {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("secrets[%d]: a name is required", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("secrets[%d]: duplicate secret name %q", i, s.Name)
		}
		seen[s.Name] = true
		switch s.Type {
		case "", "kv", "file":
		case "certificate":
			return fmt.Errorf("secrets[%d] (%s): certificate secrets are managed imperatively (they track a live certificate); declare kv or file in a manifest", i, s.Name)
		default:
			return fmt.Errorf("secrets[%d] (%s): unknown type %q (want kv or file)", i, s.Name, s.Type)
		}
		// Binding triples must be unique within a secret.
		triples := map[string]bool{}
		for _, b := range s.Bindings {
			key := bindingKey(b)
			if triples[key] {
				return fmt.Errorf("secrets[%d] (%s): duplicate binding (namespace=%q serviceAccount=%q authMethod=%q)", i, s.Name, b.Namespace, b.ServiceAccount, b.AuthMethod)
			}
			triples[key] = true
		}
	}
	return nil
}

//
// ---------- planning ----------
//

type actionKind string

const (
	actCreateSecret actionKind = "create-secret"
	actUpdateSecret actionKind = "update-secret"
	actBind         actionKind = "bind"
	actUnbind       actionKind = "unbind"
)

// Action is one converging step. It carries the structured data execute needs
// (the binding triple, the metadata fields) so execution never has to re-parse
// a human-readable string. Detail is for display only.
type Action struct {
	Kind   actionKind `json:"kind"`
	Secret string     `json:"secret"`
	Detail string     `json:"detail"`
	// Triple is "namespace\x00serviceAccount\x00authMethod" for bind/unbind.
	Triple string `json:"-"`
	// MetaFields lists which metadata fields change, for update-secret.
	MetaFields []string `json:"meta_fields,omitempty"`
}

// Plan is the ordered set of actions that converges the server to the manifest.
type Plan struct {
	Actions []Action
}

func (p *Plan) Empty() bool { return len(p.Actions) == 0 }

// serverState is the slice of server state the planner compares against.
type serverState struct {
	secrets  map[string]*gocaclient.Secret
	bindings map[string][]*gocaclient.SecretBinding // secret name -> bindings
}

// plan fetches the relevant server state and computes the converging actions.
func plan(ctx context.Context, c *gocaclient.Client, m *Manifest, prune bool) (*Plan, error) {
	st, err := fetchServerState(ctx, c, m)
	if err != nil {
		return nil, err
	}
	return planFromState(m, st, prune), nil
}

// fetchServerState lists every secret and, for each the manifest declares, its
// bindings. Secrets the manifest does not name are ignored - apply/diff only
// ever touch what is declared.
func fetchServerState(ctx context.Context, c *gocaclient.Client, m *Manifest) (*serverState, error) {
	list, err := c.ListSecrets(ctx, "")
	if err != nil {
		return nil, err
	}
	st := &serverState{secrets: map[string]*gocaclient.Secret{}, bindings: map[string][]*gocaclient.SecretBinding{}}
	for i := range list.Value {
		st.secrets[list.Value[i].Name] = &list.Value[i]
	}
	for _, d := range m.Secrets {
		if _, ok := st.secrets[d.Name]; !ok {
			continue
		}
		bres, err := c.SecretBindings(ctx, d.Name)
		if err != nil {
			return nil, err
		}
		bindings := make([]*gocaclient.SecretBinding, len(bres.Value))
		for j := range bres.Value {
			bindings[j] = &bres.Value[j]
		}
		st.bindings[d.Name] = bindings
	}
	return st, nil
}

// planFromState is the pure comparison: given the manifest and the server
// state, which actions converge the two? Split out from plan so it can be
// tested without a server.
func planFromState(m *Manifest, st *serverState, prune bool) *Plan {
	p := &Plan{}
	for _, d := range m.Secrets {
		srv, exists := st.secrets[d.Name]
		if !exists {
			p.Actions = append(p.Actions, Action{Kind: actCreateSecret, Secret: d.Name, Detail: "create secret (type " + orKV(d.Type) + ")"})
			// A brand-new secret has no bindings yet; declare them all.
			for _, b := range d.Bindings {
				p.Actions = append(p.Actions, Action{Kind: actBind, Secret: d.Name, Triple: bindingKey(b), Detail: bindingDetail(b)})
			}
			continue
		}
		// Type is immutable after creation; a mismatch is a conflict, not a
		// converging edit.
		if srv.Type != orKV(d.Type) {
			p.Actions = append(p.Actions, Action{Kind: actUpdateSecret, Secret: d.Name, Detail: fmt.Sprintf("CONFLICT: type is %q on the server but %q in the manifest (type is immutable)", srv.Type, orKV(d.Type))})
			continue
		}
		if changes := metaChanges(d, srv); len(changes) > 0 {
			p.Actions = append(p.Actions, Action{Kind: actUpdateSecret, Secret: d.Name, MetaFields: changes, Detail: "update " + strings.Join(changes, ", ")})
		}
		declared := map[string]bool{}
		for _, b := range d.Bindings {
			key := bindingKey(b)
			declared[key] = true
			if !bindingPresent(st.bindings[d.Name], b) {
				p.Actions = append(p.Actions, Action{Kind: actBind, Secret: d.Name, Triple: key, Detail: bindingDetail(b)})
			}
		}
		if prune {
			for _, sb := range st.bindings[d.Name] {
				key := sb.K8sNamespace + "\x00" + sb.K8sServiceAccount + "\x00" + sb.K8sAuthMethod
				if !declared[key] {
					p.Actions = append(p.Actions, Action{Kind: actUnbind, Secret: d.Name, Triple: key, Detail: "unbind " + bindingTriple(sb.K8sNamespace, sb.K8sServiceAccount, sb.K8sAuthMethod)})
				}
			}
		}
	}
	return p
}

// metaChanges reports which metadata fields differ between the declaration and
// the server. Empty means the metadata already matches.
func metaChanges(d ManifestSecret, srv *gocaclient.Secret) []string {
	var out []string
	if d.Description != srv.Description {
		out = append(out, "description")
	}
	// The server returns {} for a secret with no labels; a manifest that
	// declares none unmarshals to nil. Treat the two as equal.
	if !labelsEqual(d.Labels, srv.Labels) {
		out = append(out, "labels")
	}
	if d.RotationDays != srv.RotationDays {
		out = append(out, "rotationDays")
	}
	return out
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func bindingKey(b ManifestBinding) string {
	return orStar(b.Namespace) + "\x00" + orStar(b.ServiceAccount) + "\x00" + orStar(b.AuthMethod)
}

func bindingPresent(have []*gocaclient.SecretBinding, want ManifestBinding) bool {
	for _, sb := range have {
		if sb.K8sNamespace == orStar(want.Namespace) && sb.K8sServiceAccount == orStar(want.ServiceAccount) && sb.K8sAuthMethod == orStar(want.AuthMethod) {
			return true
		}
	}
	return false
}

func bindingDetail(b ManifestBinding) string {
	s := bindingTriple(b.Namespace, b.ServiceAccount, b.AuthMethod)
	if b.ExpiresInDays > 0 {
		s += fmt.Sprintf(" (expires in %dd)", b.ExpiresInDays)
	}
	return "bind " + s
}

func bindingTriple(ns, sa, method string) string {
	return "namespace=" + orStar(ns) + " serviceAccount=" + orStar(sa) + " authMethod=" + orStar(method)
}

func orKV(t string) string {
	if t == "" {
		return "kv"
	}
	return t
}
func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

//
// ---------- execution ----------
//

// execute applies a plan to the server, in order.
func execute(ctx context.Context, c *gocaclient.Client, m *Manifest, p *Plan) error {
	byName := map[string]ManifestSecret{}
	for _, d := range m.Secrets {
		byName[d.Name] = d
	}
	for _, a := range p.Actions {
		d := byName[a.Secret]
		switch a.Kind {
		case actCreateSecret:
			if _, err := c.CreateSecret(ctx, gocaclient.CreateSecretInput{
				Name:         d.Name,
				Type:         orKV(d.Type),
				Description:  d.Description,
				Labels:       d.Labels,
				RotationDays: d.RotationDays,
			}); err != nil {
				return fmt.Errorf("create %s: %w", d.Name, err)
			}
		case actUpdateSecret:
			body := map[string]any{}
			for _, f := range a.MetaFields {
				switch f {
				case "description":
					body["description"] = d.Description
				case "labels":
					body["labels"] = d.Labels
				case "rotationDays":
					body["rotation_days"] = d.RotationDays
				}
			}
			if len(body) == 0 {
				continue // a CONFLICT action has no MetaFields; nothing to do
			}
			if _, err := c.UpdateSecret(ctx, d.Name, body); err != nil {
				return fmt.Errorf("update %s: %w", d.Name, err)
			}
		case actBind:
			b := bindingByTriple(d.Bindings, a.Triple)
			if b == nil {
				return fmt.Errorf("bind %s: no declared binding matches %q", d.Name, a.Triple)
			}
			if _, err := c.BindSecret(ctx, d.Name, b.Namespace, b.ServiceAccount, b.AuthMethod, b.ExpiresInDays); err != nil {
				return fmt.Errorf("bind %s: %w", d.Name, err)
			}
		case actUnbind:
			bres, err := c.SecretBindings(ctx, d.Name)
			if err != nil {
				return fmt.Errorf("list bindings for %s: %w", d.Name, err)
			}
			for _, sb := range bres.Value {
				if sb.K8sNamespace+"\x00"+sb.K8sServiceAccount+"\x00"+sb.K8sAuthMethod == a.Triple {
					if err := c.UnbindSecret(ctx, sb.ID); err != nil {
						return fmt.Errorf("unbind %s: %w", d.Name, err)
					}
					break
				}
			}
		}
	}
	return nil
}

// bindingByTriple finds a declared binding by its "ns\x00sa\x00method" key.
func bindingByTriple(bindings []ManifestBinding, triple string) *ManifestBinding {
	for i := range bindings {
		if bindingKey(bindings[i]) == triple {
			return &bindings[i]
		}
	}
	return nil
}

//
// ---------- output ----------
//

func printPlan(p *Plan) {
	if p.Empty() {
		fmt.Println("No drift: the server already matches the manifest.")
		return
	}
	for _, a := range p.Actions {
		switch a.Kind {
		case actCreateSecret:
			fmt.Printf("+ create secret  %s  (%s)\n", a.Secret, a.Detail)
		case actUpdateSecret:
			fmt.Printf("~ update secret  %s  (%s)\n", a.Secret, a.Detail)
		case actBind:
			fmt.Printf("+ bind           %s  (%s)\n", a.Secret, a.Detail)
		case actUnbind:
			fmt.Printf("- unbind         %s  (%s)\n", a.Secret, a.Detail)
		}
	}
}

func printJSONPlan(p *Plan) error {
	return termio.PrintJSON(p.Actions)
}

//
// ---------- commands ----------
//

func newApplyCmd() *cobra.Command {
	var (
		files  []string
		prune  bool
		dryRun bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a secret manifest to the server (idempotent create/update)",
		Long: strings.TrimSpace(`
Converges the server's secrets and CSI bindings to a manifest. For each
declared secret it creates it if missing, updates changed metadata
(description, labels, rotationDays), and creates any missing bindings. It
never deletes a secret, and it only removes bindings when --prune is set.

Secret values are not part of the manifest - push them with ` + "`gocactl secret put`" + `
from a pipeline that holds the plaintext only transiently.

Run in a CI job on merge to keep the goca-side state in step with git.`),
		Example: strings.TrimSpace(`
  gocactl apply -f secrets.yaml
  gocactl apply -f secrets.yaml --prune
  gocactl apply -f secrets.yaml --dry-run`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(files) == 0 {
				return errors.New("a manifest is required: -f secrets.yaml")
			}
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			combined, err := loadManifests(files)
			if err != nil {
				return err
			}
			p, err := plan(ctx, c, combined, prune)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSONPlan(p)
			}
			if p.Empty() {
				termio.OK("no drift: the server already matches the manifest")
				return nil
			}
			printPlan(p)
			if dryRun {
				termio.Info("--dry-run: no changes were made")
				return nil
			}
			if err := execute(ctx, c, combined, p); err != nil {
				return err
			}
			termio.OK("applied %d change(s)", len(p.Actions))
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "filename", "f", nil, "manifest file(s); repeat the flag or comma-separate")
	cmd.Flags().BoolVar(&prune, "prune", false, "remove bindings that exist on the server but are not declared (secrets are never deleted)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the changes without applying them")
	return cmd
}

func newDiffCmd() *cobra.Command {
	var (
		files []string
		prune bool
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Report drift between a manifest and the server (for CI gates)",
		Long: strings.TrimSpace(`
Compares a manifest against the server and prints the changes ` + "`apply`" + ` would
make. Exits 0 when there is no drift and 1 when there is, so a CI job can fail
on drift. It never changes anything.`),
		Example: strings.TrimSpace(`
  gocactl diff -f secrets.yaml
  gocactl diff -f secrets.yaml --prune   # also report bindings that would be pruned`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(files) == 0 {
				return errors.New("a manifest is required: -f secrets.yaml")
			}
			ctx, cancel := cmdContext(cmd)
			defer cancel()
			c, err := client()
			if err != nil {
				return err
			}
			combined, err := loadManifests(files)
			if err != nil {
				return err
			}
			p, err := plan(ctx, c, combined, prune)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSONPlan(p)
			}
			printPlan(p)
			if !p.Empty() {
				return &DriftError{Plan: p}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "filename", "f", nil, "manifest file(s); repeat the flag or comma-separate")
	cmd.Flags().BoolVar(&prune, "prune", false, "also report bindings that would be pruned")
	return cmd
}

// loadManifests reads and merges every -f file into one manifest, then
// validates the combined result (catches a name declared in two files).
func loadManifests(files []string) (*Manifest, error) {
	combined := &Manifest{}
	for _, f := range files {
		m, err := parseManifest(f)
		if err != nil {
			return nil, err
		}
		combined.Secrets = append(combined.Secrets, m.Secrets...)
	}
	if err := validateManifest(combined); err != nil {
		return nil, err
	}
	return combined, nil
}

// DriftError is returned by `diff` when the server does not match the
// manifest. The root command maps it to exit code 1 (distinct from a real
// error, which is exit 2) so a CI gate can tell "drift" from "broken".
type DriftError struct {
	Plan *Plan
}

func (e *DriftError) Error() string {
	return fmt.Sprintf("drift detected: %d change(s) would be made by `gocactl apply`", len(e.Plan.Actions))
}
