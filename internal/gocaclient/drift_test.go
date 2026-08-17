package gocaclient

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	// Imported in a _test file only. Test imports do not affect the shipped
	// binary, so this compares against the real server types without linking
	// the SQL drivers those packages pull in - see TestClientLinksNoSQLDriver.
	"github.com/mevijays/goca/internal/acme"
	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/store"
	"github.com/mevijays/goca/internal/vault"
)

// The client hand-writes DTOs rather than importing internal/store. That is a
// deliberate trade (see the package doc), and this is the price: something has
// to keep the copies honest.
//
// It matters most for request types. The server decodes with
// DisallowUnknownFields, so a single stale or misspelled json tag is not a
// silently ignored field - it is a hard 400 at runtime, found by a user rather
// than by CI.

// jsonTags returns the wire field names of a struct, ignoring `json:"-"`.
func jsonTags(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case name == "-":
			continue
		case f.Anonymous && name == "":
			// Embedded struct: its fields are promoted onto the wire.
			ft := f.Type
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				out = append(out, jsonTags(ft)...)
			}
			continue
		case name == "":
			if !f.IsExported() {
				continue
			}
			name = f.Name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func diff(a, b []string) (onlyA, onlyB []string) {
	inB := map[string]bool{}
	for _, s := range b {
		inB[s] = true
	}
	inA := map[string]bool{}
	for _, s := range a {
		inA[s] = true
		if !inB[s] {
			onlyA = append(onlyA, s)
		}
	}
	for _, s := range b {
		if !inA[s] {
			onlyB = append(onlyB, s)
		}
	}
	return onlyA, onlyB
}

// TestRequestDTOsMatchServerTypes is the important one: these structs are
// marshalled and sent, and the server rejects unknown fields outright.
func TestRequestDTOsMatchServerTypes(t *testing.T) {
	cases := []struct {
		name           string
		client, server any
	}{
		{"CreateCAInput", CreateCAInput{}, ca.CreateCAInput{}},
		{"IssueInput", IssueInput{}, ca.IssueInput{}},
		{"RenewInput", RenewInput{}, ca.RenewInput{}},
		{"SubordinateCSRInput", SubordinateCSRInput{}, ca.SubordinateCSRInput{}},
		{"ImportCAInput", ImportCAInput{}, ca.ImportCAInput{}},
		{"CompleteSubordinateInput", CompleteSubordinateInput{}, ca.CompleteSubordinateInput{}},
		{"CreateSecretInput", CreateSecretInput{}, vault.CreateInput{}},
		{"CreateEABInput", CreateEABInput{}, acme.CreateEABInput{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clientTags := jsonTags(reflect.TypeOf(c.client))
			serverTags := jsonTags(reflect.TypeOf(c.server))
			extra, missing := diff(clientTags, serverTags)
			if len(extra) > 0 {
				t.Errorf("client sends field(s) the server does not accept: %v\n"+
					"the server decodes with DisallowUnknownFields, so this is a 400 at runtime", extra)
			}
			if len(missing) > 0 {
				t.Errorf("client cannot set server field(s): %v", missing)
			}
		})
	}
}

// TestResponseDTOsAreASubsetOfServerTypes checks the other direction. A client
// field the server never sends is dead weight that silently decodes to a zero
// value, which looks like real data.
func TestResponseDTOsAreASubsetOfServerTypes(t *testing.T) {
	cases := []struct {
		name           string
		client, server any
		// computed are fields the API adds on top of the stored struct via a
		// response wrapper - they are legitimately absent from the store type.
		computed []string
	}{
		{"CA", CA{}, store.CA{},
			[]string{"cert_pem", "info", "has_key", "can_issue", "kind", "origin", "expired", "days_left"}},
		{"Certificate", Certificate{}, store.Certificate{},
			[]string{"cert_pem", "info", "sans"}},
		{"Secret", Secret{}, store.Secret{}, []string{"labels", "rotation_due"}},
		{"SecretVersion", SecretVersion{}, store.SecretVersion{}, nil},
		{"SecretBinding", SecretBinding{}, store.SecretBinding{}, nil},
		{"User", User{}, store.User{}, nil},
		{"APIToken", APIToken{}, store.APIToken{}, nil},
		{"AuditEntry", AuditEntry{}, store.AuditEntry{}, nil},
		{"EABCred", EABCred{}, store.EABCred{}, nil},
		{"AcmeAccount", AcmeAccount{}, store.AcmeAccount{}, nil},
		{"Stats", Stats{}, store.Stats{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serverTags := jsonTags(reflect.TypeOf(c.server))
			serverTags = append(serverTags, c.computed...)
			clientTags := jsonTags(reflect.TypeOf(c.client))
			extra, _ := diff(clientTags, serverTags)
			if len(extra) > 0 {
				t.Errorf("client declares field(s) the server never sends: %v\n"+
					"they will always decode to a zero value, which is indistinguishable from real data", extra)
			}
		})
	}
}

// TestCAResponseCarriesTheComputedFields pins the specific fields that exist
// only because the encrypted signing key is not serializable. If the server
// ever stops sending them, the client silently reports every authority as a
// keyless trust anchor again.
func TestCAResponseCarriesTheComputedFields(t *testing.T) {
	tags := map[string]bool{}
	for _, tag := range jsonTags(reflect.TypeOf(CA{})) {
		tags[tag] = true
	}
	for _, required := range []string{"has_key", "can_issue", "kind", "origin"} {
		if !tags[required] {
			t.Errorf("client CA is missing %q, which cannot be derived from the wire", required)
		}
	}
	// And the key itself must never appear.
	for _, forbidden := range []string{"key_enc", "key_pem"} {
		if tags[forbidden] {
			t.Errorf("client CA declares %q - the CA private key must not be part of this API", forbidden)
		}
	}
}
