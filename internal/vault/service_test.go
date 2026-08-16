package vault

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// newTestService builds a vault.Service (and the ca.Service it wraps for
// certificate materialization) backed by a throwaway database, mirroring
// internal/ca's own newTestService helper.
func newTestService(t *testing.T) (*Service, *ca.Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "test.db")
	cfg.Server.BaseURL = "http://vault.test"
	if err := cfg.GenerateSecrets(); err != nil {
		t.Fatalf("GenerateSecrets: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	caSvc, err := ca.New(cfg, st)
	if err != nil {
		t.Fatalf("ca.New: %v", err)
	}
	vSvc, err := New(cfg, st, caSvc)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return vSvc, caSvc, st
}

func TestSecretCreateGetListDelete(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newTestService(t)

	sec, err := v.Create(ctx, CreateInput{
		Name:        "team-a/db/password",
		Type:        store.SecretTypeKV,
		Description: "database password",
		Labels:      map[string]string{"env": "prod"},
		Actor:       "tester",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sec.Type != store.SecretTypeKV {
		t.Errorf("Type = %q, want kv", sec.Type)
	}

	got, err := v.Get(ctx, "team-a/db/password")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != sec.ID {
		t.Errorf("Get returned a different secret")
	}

	list, err := v.List(ctx, "")
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d, %v, want 1 secret", len(list), err)
	}

	if _, err := v.UpdateMeta(ctx, "team-a/db/password", "new description", map[string]string{"env": "staging"}, 30, "tester"); err != nil {
		t.Fatalf("UpdateMeta: %v", err)
	}
	updated, _ := v.Get(ctx, "team-a/db/password")
	if updated.Description != "new description" || updated.RotationDays != 30 {
		t.Errorf("UpdateMeta did not persist: %+v", updated)
	}

	if err := v.SetDisabled(ctx, "team-a/db/password", true, "tester"); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	if disabled, _ := v.Get(ctx, "team-a/db/password"); !disabled.Disabled {
		t.Error("SetDisabled(true) did not persist")
	}

	if err := v.Delete(ctx, "team-a/db/password", "tester"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := v.Get(ctx, "team-a/db/password"); !errIsNotFound(err) {
		t.Errorf("Get after delete = %v, want ErrNotFound", err)
	}
}

func TestSecretCreateRejectsBadType(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newTestService(t)
	if _, err := v.Create(ctx, CreateInput{Name: "x", Type: "not-a-type"}); err == nil {
		t.Error("Create accepted an unknown secret type")
	}
	if _, err := v.Create(ctx, CreateInput{Name: "", Type: store.SecretTypeKV}); err == nil {
		t.Error("Create accepted an empty name")
	}
}

func TestPutGetRoundTripAndVersioning(t *testing.T) {
	ctx := context.Background()
	v, _, st := newTestService(t)

	if _, err := v.Create(ctx, CreateInput{Name: "app/api-key", Type: store.SecretTypeKV, Actor: "tester"}); err != nil {
		t.Fatal(err)
	}

	v1, err := v.Put(ctx, "app/api-key", []byte("first-value"), "", "tester")
	if err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("first version = %d, want 1", v1.Version)
	}

	v2, err := v.Put(ctx, "app/api-key", []byte("second-value"), "", "tester")
	if err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	if v2.Version != 2 {
		t.Errorf("second version = %d, want 2", v2.Version)
	}

	// The database must never hold plaintext - only a pqenc:v1: envelope.
	var rawPayload string
	row := st.DB().QueryRowContext(ctx, `SELECT payload_enc FROM secret_versions WHERE id = ?`, v2.ID)
	if err := row.Scan(&rawPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawPayload, "pqenc:v1:") {
		t.Errorf("stored payload does not carry the pqenc:v1: prefix: %q", rawPayload[:min(20, len(rawPayload))])
	}
	if strings.Contains(rawPayload, "second-value") {
		t.Error("the plaintext appears verbatim in the stored payload")
	}

	sec, pt, err := v.GetLatest(ctx, "app/api-key")
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if string(pt) != "second-value" {
		t.Errorf("GetLatest = %q, want %q", pt, "second-value")
	}
	if sec.CurrentVersion != 2 {
		t.Errorf("CurrentVersion = %d, want 2", sec.CurrentVersion)
	}

	_, ptV1, err := v.GetVersion(ctx, "app/api-key", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if string(ptV1) != "first-value" {
		t.Errorf("GetVersion(1) = %q, want %q", ptV1, "first-value")
	}

	_, versions, err := v.Versions(ctx, "app/api-key")
	if err != nil || len(versions) != 2 {
		t.Fatalf("Versions = %d, %v, want 2", len(versions), err)
	}

	if err := v.DestroyVersion(ctx, "app/api-key", 1, "tester"); err != nil {
		t.Fatalf("DestroyVersion: %v", err)
	}
	if _, _, err := v.GetVersion(ctx, "app/api-key", 1); err == nil {
		t.Error("GetVersion succeeded on a destroyed version")
	}
	// The still-current version must be unaffected.
	if _, pt, err := v.GetLatest(ctx, "app/api-key"); err != nil || string(pt) != "second-value" {
		t.Errorf("GetLatest after destroying v1 = %q, %v", pt, err)
	}
}

func TestPutRejectsCertificateSecrets(t *testing.T) {
	ctx := context.Background()
	v, caSvc, _ := newTestService(t)
	rootCA := mustRootCA(t, caSvc)
	cert := mustLeafCert(t, caSvc, rootCA, "svc.test")

	if _, err := v.Create(ctx, CreateInput{Name: "team-a/tls", Type: store.SecretTypeCertificate, CertID: &cert.ID, Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, "team-a/tls", []byte("x"), "", "tester"); err == nil {
		t.Error("Put accepted a write to a certificate secret")
	}
}

func TestGetLatestRejectsDisabledSecret(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newTestService(t)
	if _, err := v.Create(ctx, CreateInput{Name: "x/y", Type: store.SecretTypeKV, Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, "x/y", []byte("v"), "", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := v.SetDisabled(ctx, "x/y", true, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.GetLatest(ctx, "x/y"); err == nil {
		t.Error("GetLatest succeeded on a disabled secret")
	}
	if _, err := v.Put(ctx, "x/y", []byte("v2"), "", "tester"); err == nil {
		t.Error("Put succeeded on a disabled secret")
	}
}

func TestCertificateMaterialization(t *testing.T) {
	ctx := context.Background()
	v, caSvc, _ := newTestService(t)
	rootCA := mustRootCA(t, caSvc)
	cert := mustLeafCert(t, caSvc, rootCA, "svc.test")

	sec, err := v.Create(ctx, CreateInput{
		Name: "team-a/svc-tls", Type: store.SecretTypeCertificate, CertID: &cert.ID, Actor: "tester",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, files, version, err := v.Materialize(ctx, sec.Name)
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if got.ID != sec.ID {
		t.Error("Materialize resolved the wrong secret")
	}
	if version != "cert:"+cert.SerialHex {
		t.Errorf("version marker = %q, want %q", version, "cert:"+cert.SerialHex)
	}

	byName := map[string][]byte{}
	for _, f := range files {
		byName[f.Name] = f.Data
	}
	for _, want := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("Materialize did not produce a %s file; got %v", want, filesToNames(files))
		}
	}
	if !bytes.Contains(byName["tls.crt"], []byte(cert.CertPEM)) {
		t.Error("tls.crt does not contain the leaf certificate")
	}
	if !bytes.Contains(byName["tls.crt"], []byte(rootCA.CertPEM)) {
		t.Error("tls.crt (full chain) does not contain the root CA")
	}
	if bytes.Equal(byName["ca.crt"], byName["tls.crt"]) {
		t.Error("ca.crt should be the issuer chain alone, not identical to the full chain")
	}
	key, err := caSvc.CertKeyPEM(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(byName["tls.key"], key) {
		t.Error("tls.key does not match the certificate's stored private key")
	}
}

func TestCreateCertificateSecretRequiresCertID(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newTestService(t)
	if _, err := v.Create(ctx, CreateInput{Name: "x", Type: store.SecretTypeCertificate}); err == nil {
		t.Error("Create accepted a certificate secret with no cert_id")
	}
}

func TestBindUnbindAndGlobMatching(t *testing.T) {
	ctx := context.Background()
	v, _, _ := newTestService(t)
	if _, err := v.Create(ctx, CreateInput{Name: "team-a/tls", Type: store.SecretTypeKV, Actor: "tester"}); err != nil {
		t.Fatal(err)
	}

	b, err := v.Bind(ctx, "team-a/tls", "team-a", "web-*", nil, "tester")
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	if !MatchesBinding(b, "team-a", "web-frontend") {
		t.Error("expected the glob web-* to match web-frontend")
	}
	if MatchesBinding(b, "team-a", "worker") {
		t.Error("expected the glob web-* NOT to match worker")
	}
	if MatchesBinding(b, "team-b", "web-frontend") {
		t.Error("expected namespace team-a NOT to match team-b")
	}

	past := time.Now().Add(-time.Minute)
	expired, err := v.Bind(ctx, "team-a/tls", "*", "*", &past, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if MatchesBinding(expired, "anything", "anything") {
		t.Error("an expired binding must not match")
	}

	bindings, err := v.Bindings(ctx, "team-a/tls")
	if err != nil || len(bindings) != 2 {
		t.Fatalf("Bindings = %d, %v, want 2", len(bindings), err)
	}

	if err := v.Unbind(ctx, b.ID, "tester"); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if bindings, err := v.Bindings(ctx, "team-a/tls"); err != nil || len(bindings) != 1 {
		t.Errorf("Bindings after Unbind = %d, %v, want 1", len(bindings), err)
	}
}

func mustRootCA(t *testing.T, svc *ca.Service) *store.CA {
	t.Helper()
	c, err := svc.CreateCA(context.Background(), ca.CreateCAInput{
		Name:    "Vault Test Root CA",
		Subject: pki.Subject{CommonName: "Vault Test Root CA", Organization: "Testing"},
		KeyType: "ec-p256",
		Days:    3650,
		PathLen: 1,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return c
}

func mustLeafCert(t *testing.T, svc *ca.Service, caRec *store.CA, cn string) *store.Certificate {
	t.Helper()
	res, err := svc.Issue(context.Background(), ca.IssueInput{
		CARef:   caRec.Slug,
		Mode:    ca.ModeGenerate,
		Subject: pki.Subject{CommonName: cn},
		SANs:    []string{cn},
		KeyType: "ec-p256",
		Days:    30,
		Actor:   "tester",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return res.Certificate
}

func filesToNames(files []File) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}
	return out
}

func errIsNotFound(err error) bool { return err == store.ErrNotFound }
