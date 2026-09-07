package rcli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mevijays/goca/internal/gocaclient"
)

//
// ---------- manifest parsing ----------
//

func writeManifest(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseManifestValid(t *testing.T) {
	path := writeManifest(t, `
apiVersion: goca.dev/v1
kind: SecretManifest
secrets:
  - name: db-password
    type: kv
    description: primary db
    labels:
      team: platform
    rotationDays: 30
    bindings:
      - namespace: prod
        serviceAccount: app
        authMethod: cluster-a
        expiresInDays: 7
      - namespace: "*"
        serviceAccount: "*"
`)
	m, err := parseManifest(path)
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(m.Secrets) != 1 {
		t.Fatalf("want 1 secret, got %d", len(m.Secrets))
	}
	s := m.Secrets[0]
	if s.Name != "db-password" || s.Type != "kv" || s.Description != "primary db" || s.RotationDays != 30 {
		t.Errorf("unexpected secret fields: %+v", s)
	}
	if s.Labels["team"] != "platform" {
		t.Errorf("labels: %v", s.Labels)
	}
	if len(s.Bindings) != 2 {
		t.Fatalf("want 2 bindings, got %d", len(s.Bindings))
	}
	if s.Bindings[0].Namespace != "prod" || s.Bindings[0].ServiceAccount != "app" || s.Bindings[0].AuthMethod != "cluster-a" || s.Bindings[0].ExpiresInDays != 7 {
		t.Errorf("binding[0]: %+v", s.Bindings[0])
	}
	// Empty fields are canonicalized to "*" (the server stores them that way).
	if s.Bindings[1].Namespace != "*" || s.Bindings[1].ServiceAccount != "*" || s.Bindings[1].AuthMethod != "*" {
		t.Errorf("binding[1] should be canonicalized to *: %+v", s.Bindings[1])
	}
}

func TestParseManifestBareList(t *testing.T) {
	path := writeManifest(t, `
- name: api-key
  type: kv
`)
	m, err := parseManifest(path)
	if err != nil {
		t.Fatalf("parseManifest: %v", err)
	}
	if len(m.Secrets) != 1 || m.Secrets[0].Name != "api-key" {
		t.Fatalf("bare list not parsed: %+v", m)
	}
}

func TestParseManifestErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"unsupported apiVersion", "apiVersion: v2\nsecrets:\n  - name: a\n", "unsupported apiVersion"},
		{"no secrets", "apiVersion: goca.dev/v1\nsecrets: []\n", "no secrets"},
		{"missing name", "secrets:\n  - type: kv\n", "a name is required"},
		{"duplicate names", "secrets:\n  - name: a\n  - name: a\n", "duplicate secret name"},
		{"certificate rejected", "secrets:\n  - name: a\n    type: certificate\n", "certificate secrets are managed imperatively"},
		{"unknown type", "secrets:\n  - name: a\n    type: blob\n", "unknown type"},
		{"duplicate bindings", "secrets:\n  - name: a\n    bindings:\n      - namespace: x\n        serviceAccount: y\n      - namespace: x\n        serviceAccount: y\n", "duplicate binding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeManifest(t, tc.content)
			_, err := parseManifest(path)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %q", tc.want, err.Error())
			}
		})
	}
}

func TestParseManifestMissingFile(t *testing.T) {
	if _, err := parseManifest("/nonexistent/secrets.yaml"); err == nil {
		t.Fatal("want error for missing file")
	}
}

//
// ---------- planning ----------
//

func srvSecret(name, typ, desc string, labels map[string]string, rot int) *gocaclient.Secret {
	return &gocaclient.Secret{Name: name, Type: typ, Description: desc, Labels: labels, RotationDays: rot}
}

func srvBinding(ns, sa, method string) *gocaclient.SecretBinding {
	return &gocaclient.SecretBinding{K8sNamespace: ns, K8sServiceAccount: sa, K8sAuthMethod: method}
}

func stateOf(secrets ...*gocaclient.Secret) *serverState {
	st := &serverState{secrets: map[string]*gocaclient.Secret{}, bindings: map[string][]*gocaclient.SecretBinding{}}
	for _, s := range secrets {
		st.secrets[s.Name] = s
	}
	return st
}

func manifestOf(secrets ...ManifestSecret) *Manifest {
	return &Manifest{Secrets: secrets}
}

func kinds(p *Plan) []actionKind {
	out := make([]actionKind, len(p.Actions))
	for i, a := range p.Actions {
		out[i] = a.Kind
	}
	return out
}

func TestPlanNewSecret(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "db-password", Type: "kv",
		Bindings: []ManifestBinding{
			{Namespace: "prod", ServiceAccount: "app", AuthMethod: "cluster-a"},
			{Namespace: "*", ServiceAccount: "*"},
		},
	})
	p := planFromState(m, stateOf(), false)
	want := []actionKind{actCreateSecret, actBind, actBind}
	if !reflect.DeepEqual(kinds(p), want) {
		t.Fatalf("kinds = %v, want %v", kinds(p), want)
	}
	if p.Actions[0].Secret != "db-password" {
		t.Errorf("create action secret = %q", p.Actions[0].Secret)
	}
	// The bind actions carry the structured triple.
	if p.Actions[1].Triple != "prod\x00app\x00cluster-a" {
		t.Errorf("bind[0] triple = %q", p.Actions[1].Triple)
	}
	if p.Actions[2].Triple != "*\x00*\x00*" {
		t.Errorf("bind[1] triple = %q", p.Actions[2].Triple)
	}
}

func TestPlanNoDrift(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "db-password", Type: "kv", Description: "d",
		Labels:       map[string]string{"team": "x"},
		RotationDays: 30,
		Bindings:     []ManifestBinding{{Namespace: "prod", ServiceAccount: "app"}},
	})
	st := stateOf(srvSecret("db-password", "kv", "d", map[string]string{"team": "x"}, 30))
	st.bindings["db-password"] = []*gocaclient.SecretBinding{srvBinding("prod", "app", "*")}
	p := planFromState(m, st, true)
	if !p.Empty() {
		t.Fatalf("want empty plan, got %+v", p.Actions)
	}
}

func TestPlanMetadataDrift(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "db-password", Type: "kv", Description: "new desc",
		Labels:       map[string]string{"team": "y"},
		RotationDays: 90,
	})
	st := stateOf(srvSecret("db-password", "kv", "old desc", map[string]string{"team": "x"}, 30))
	p := planFromState(m, st, false)
	if len(p.Actions) != 1 {
		t.Fatalf("want 1 action, got %+v", p.Actions)
	}
	a := p.Actions[0]
	if a.Kind != actUpdateSecret {
		t.Fatalf("kind = %v", a.Kind)
	}
	want := []string{"description", "labels", "rotationDays"}
	if !reflect.DeepEqual(a.MetaFields, want) {
		t.Errorf("MetaFields = %v, want %v", a.MetaFields, want)
	}
}

func TestPlanPartialMetadataDrift(t *testing.T) {
	// Only rotationDays differs.
	m := manifestOf(ManifestSecret{Name: "s", Type: "kv", Description: "same", RotationDays: 60})
	st := stateOf(srvSecret("s", "kv", "same", nil, 30))
	p := planFromState(m, st, false)
	if len(p.Actions) != 1 || p.Actions[0].Kind != actUpdateSecret {
		t.Fatalf("actions = %+v", p.Actions)
	}
	if !reflect.DeepEqual(p.Actions[0].MetaFields, []string{"rotationDays"}) {
		t.Errorf("MetaFields = %v", p.Actions[0].MetaFields)
	}
}

func TestPlanNilVsEmptyLabelsNoDrift(t *testing.T) {
	// A manifest that declares no labels unmarshals to nil; the server
	// returns {}. That must not be reported as drift.
	m := manifestOf(ManifestSecret{Name: "s", Type: "kv"})
	st := stateOf(srvSecret("s", "kv", "", map[string]string{}, 0))
	p := planFromState(m, st, false)
	if !p.Empty() {
		t.Fatalf("want empty plan, got %+v", p.Actions)
	}
	// And the reverse: manifest declares labels, server has none -> drift.
	m2 := manifestOf(ManifestSecret{Name: "s", Type: "kv", Labels: map[string]string{"a": "b"}})
	p2 := planFromState(m2, st, false)
	if len(p2.Actions) != 1 || !reflect.DeepEqual(p2.Actions[0].MetaFields, []string{"labels"}) {
		t.Fatalf("want labels drift, got %+v", p2.Actions)
	}
}

func TestPlanMissingBinding(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "s", Type: "kv",
		Bindings: []ManifestBinding{
			{Namespace: "prod", ServiceAccount: "app"},
			{Namespace: "staging", ServiceAccount: "app"},
		},
	})
	st := stateOf(srvSecret("s", "kv", "", nil, 0))
	st.bindings["s"] = []*gocaclient.SecretBinding{srvBinding("prod", "app", "*")}
	p := planFromState(m, st, false)
	if len(p.Actions) != 1 {
		t.Fatalf("want 1 bind action, got %+v", p.Actions)
	}
	if p.Actions[0].Kind != actBind || p.Actions[0].Triple != "staging\x00app\x00*" {
		t.Fatalf("action = %+v", p.Actions[0])
	}
}

func TestPlanPruneUnbindsUndeclared(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "s", Type: "kv",
		Bindings: []ManifestBinding{{Namespace: "prod", ServiceAccount: "app"}},
	})
	st := stateOf(srvSecret("s", "kv", "", nil, 0))
	st.bindings["s"] = []*gocaclient.SecretBinding{
		srvBinding("prod", "app", "*"),
		srvBinding("rogue", "sa", "*"),
	}
	p := planFromState(m, st, true)
	if len(p.Actions) != 1 {
		t.Fatalf("want 1 unbind action, got %+v", p.Actions)
	}
	if p.Actions[0].Kind != actUnbind || p.Actions[0].Triple != "rogue\x00sa\x00*" {
		t.Fatalf("action = %+v", p.Actions[0])
	}
}

func TestPlanNoPruneKeepsExtraBindings(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "s", Type: "kv",
		Bindings: []ManifestBinding{{Namespace: "prod", ServiceAccount: "app"}},
	})
	st := stateOf(srvSecret("s", "kv", "", nil, 0))
	st.bindings["s"] = []*gocaclient.SecretBinding{
		srvBinding("prod", "app", "*"),
		srvBinding("rogue", "sa", "*"),
	}
	p := planFromState(m, st, false)
	if !p.Empty() {
		t.Fatalf("want empty plan without --prune, got %+v", p.Actions)
	}
}

func TestPlanTypeConflict(t *testing.T) {
	m := manifestOf(ManifestSecret{
		Name: "s", Type: "file",
		Bindings: []ManifestBinding{{Namespace: "prod", ServiceAccount: "app"}},
	})
	st := stateOf(srvSecret("s", "kv", "", nil, 0))
	st.bindings["s"] = []*gocaclient.SecretBinding{srvBinding("prod", "app", "*")}
	p := planFromState(m, st, true)
	if len(p.Actions) != 1 {
		t.Fatalf("want 1 conflict action, got %+v", p.Actions)
	}
	a := p.Actions[0]
	if a.Kind != actUpdateSecret {
		t.Fatalf("kind = %v", a.Kind)
	}
	if len(a.MetaFields) != 0 {
		t.Errorf("conflict action must have no MetaFields, got %v", a.MetaFields)
	}
	if !strings.Contains(a.Detail, "CONFLICT") {
		t.Errorf("detail = %q, want CONFLICT marker", a.Detail)
	}
}

func TestPlanEmptyTypeDefaultsToKV(t *testing.T) {
	// A manifest secret with no type must match a server "kv" secret.
	m := manifestOf(ManifestSecret{Name: "s"})
	st := stateOf(srvSecret("s", "kv", "", nil, 0))
	p := planFromState(m, st, false)
	if !p.Empty() {
		t.Fatalf("want empty plan, got %+v", p.Actions)
	}
}

func TestPlanMultipleSecrets(t *testing.T) {
	m := manifestOf(
		ManifestSecret{Name: "a", Type: "kv"},
		ManifestSecret{Name: "b", Type: "file", Bindings: []ManifestBinding{{Namespace: "n", ServiceAccount: "s"}}},
	)
	st := stateOf(srvSecret("a", "kv", "", nil, 0))
	p := planFromState(m, st, false)
	// "a" matches; "b" is new -> create + bind.
	want := []actionKind{actCreateSecret, actBind}
	if !reflect.DeepEqual(kinds(p), want) {
		t.Fatalf("kinds = %v, want %v", kinds(p), want)
	}
}

//
// ---------- DriftError ----------
//

func TestDriftError(t *testing.T) {
	p := &Plan{Actions: []Action{{Kind: actCreateSecret, Secret: "x"}}}
	e := &DriftError{Plan: p}
	if e.Error() == "" {
		t.Fatal("Error() must not be empty")
	}
	if e.Plan != p {
		t.Fatal("Plan field lost")
	}
}
