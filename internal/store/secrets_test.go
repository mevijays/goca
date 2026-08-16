package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestStoreForSecrets(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "secrets-test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSecretCRUD(t *testing.T) {
	ctx := context.Background()
	st := newTestStoreForSecrets(t)

	sec, err := st.CreateSecret(ctx, &Secret{
		Name:        "team-a/db/password",
		Type:        SecretTypeKV,
		Description: "database password",
		LabelsJSON:  EncodeLabels(map[string]string{"env": "prod"}),
		CreatedBy:   "admin",
	})
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if sec.ID == 0 {
		t.Fatal("CreateSecret returned a zero id")
	}
	if sec.CurrentVersion != 0 {
		t.Errorf("CurrentVersion = %d, want 0 before any version is written", sec.CurrentVersion)
	}
	if got := sec.Labels()["env"]; got != "prod" {
		t.Errorf("Labels()[env] = %q, want prod", got)
	}

	// Duplicate name must fail (UNIQUE constraint).
	if _, err := st.CreateSecret(ctx, &Secret{Name: "team-a/db/password", Type: SecretTypeKV}); err == nil {
		t.Error("CreateSecret accepted a duplicate name")
	}

	byName, err := st.GetSecretByName(ctx, "team-a/db/password")
	if err != nil {
		t.Fatalf("GetSecretByName: %v", err)
	}
	if byName.ID != sec.ID {
		t.Errorf("GetSecretByName returned id %d, want %d", byName.ID, sec.ID)
	}

	if _, err := st.GetSecret(ctx, 999999); !isNotFound(err) {
		t.Errorf("GetSecret(missing) = %v, want ErrNotFound", err)
	}

	list, err := st.ListSecrets(ctx, "")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListSecrets returned %d secrets, want 1", len(list))
	}
	if list, err := st.ListSecrets(ctx, SecretTypeCertificate); err != nil || len(list) != 0 {
		t.Errorf("ListSecrets(certificate) = %d results, %v, want 0 results", len(list), err)
	}

	if err := st.UpdateSecretMeta(ctx, sec.ID, "updated description", EncodeLabels(map[string]string{"env": "staging"}), 90); err != nil {
		t.Fatalf("UpdateSecretMeta: %v", err)
	}
	updated, err := st.GetSecret(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Description != "updated description" || updated.RotationDays != 90 {
		t.Errorf("UpdateSecretMeta did not persist: %+v", updated)
	}

	if err := st.SetSecretDisabled(ctx, sec.ID, true); err != nil {
		t.Fatalf("SetSecretDisabled: %v", err)
	}
	if disabled, _ := st.GetSecret(ctx, sec.ID); !disabled.Disabled {
		t.Error("SetSecretDisabled(true) did not persist")
	}
	if err := st.SetSecretDisabled(ctx, 999999, true); !isNotFound(err) {
		t.Errorf("SetSecretDisabled(missing) = %v, want ErrNotFound", err)
	}
}

func TestSecretVersionLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStoreForSecrets(t)

	sec, err := st.CreateSecret(ctx, &Secret{Name: "app/api-key", Type: SecretTypeKV})
	if err != nil {
		t.Fatal(err)
	}

	// A secret with no version yet has nothing to fetch.
	if _, err := st.GetLatestSecretVersion(ctx, sec.ID); !isNotFound(err) {
		t.Errorf("GetLatestSecretVersion(no versions) = %v, want ErrNotFound", err)
	}

	fixedSeal := func(payload string) SealFunc {
		return func(secretID int64, version int) (SealedVersion, error) {
			if secretID != sec.ID {
				t.Errorf("seal called with secretID %d, want %d", secretID, sec.ID)
			}
			return SealedVersion{PayloadEnc: payload, PayloadSHA256: "sha-of-" + payload, SizeBytes: 4}, nil
		}
	}

	v1, err := st.CreateSecretVersion(ctx, sec.ID, "", "admin", fixedSeal("pqenc:v1:AAAA"))
	if err != nil {
		t.Fatalf("CreateSecretVersion 1: %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("first version = %d, want 1", v1.Version)
	}

	var sawVersion int
	v2, err := st.CreateSecretVersion(ctx, sec.ID, "", "", func(secretID int64, version int) (SealedVersion, error) {
		sawVersion = version
		return SealedVersion{PayloadEnc: "pqenc:v1:BBBB", PayloadSHA256: "cafef00d", SizeBytes: 4}, nil
	})
	if err != nil {
		t.Fatalf("CreateSecretVersion 2: %v", err)
	}
	if v2.Version != 2 {
		t.Errorf("second version = %d, want 2", v2.Version)
	}
	if sawVersion != 2 {
		t.Errorf("seal callback saw version %d, want 2 - the version reserved by the transaction must reach the sealer before encryption", sawVersion)
	}

	// current_version on the parent secret must track the latest write.
	refreshed, err := st.GetSecret(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.CurrentVersion != 2 {
		t.Errorf("secrets.current_version = %d, want 2", refreshed.CurrentVersion)
	}

	latest, err := st.GetLatestSecretVersion(ctx, sec.ID)
	if err != nil {
		t.Fatalf("GetLatestSecretVersion: %v", err)
	}
	if latest.Version != 2 || latest.PayloadEnc != "pqenc:v1:BBBB" {
		t.Errorf("GetLatestSecretVersion = %+v, want version 2 with the second payload", latest)
	}

	versions, err := st.ListSecretVersions(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != 2 || versions[1].Version != 1 {
		t.Errorf("ListSecretVersions = %+v, want [2,1]", versions)
	}

	got1, err := st.GetSecretVersion(ctx, sec.ID, 1)
	if err != nil || got1.PayloadEnc != "pqenc:v1:AAAA" {
		t.Errorf("GetSecretVersion(1) = %+v, %v", got1, err)
	}

	// Destroying version 1 must scrub its ciphertext but keep the row, and
	// must not affect what GetLatestSecretVersion resolves to.
	if err := st.DestroySecretVersion(ctx, v1.ID); err != nil {
		t.Fatalf("DestroySecretVersion: %v", err)
	}
	destroyed, err := st.GetSecretVersion(ctx, sec.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !destroyed.Destroyed || destroyed.PayloadEnc != "" {
		t.Errorf("destroyed version = %+v, want Destroyed=true and PayloadEnc scrubbed", destroyed)
	}
	if latest, err := st.GetLatestSecretVersion(ctx, sec.ID); err != nil || latest.Version != 2 {
		t.Errorf("GetLatestSecretVersion after destroying v1 = %+v, %v, want version 2 unaffected", latest, err)
	}

	// Destroying every version leaves nothing "latest" to resolve.
	if err := st.DestroySecretVersion(ctx, v2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetLatestSecretVersion(ctx, sec.ID); !isNotFound(err) {
		t.Errorf("GetLatestSecretVersion after destroying all versions = %v, want ErrNotFound", err)
	}
}

func TestSecretVersionAgainstMissingSecret(t *testing.T) {
	ctx := context.Background()
	st := newTestStoreForSecrets(t)
	sealCalled := false
	_, err := st.CreateSecretVersion(ctx, 999999, "", "", func(int64, int) (SealedVersion, error) {
		sealCalled = true
		return SealedVersion{PayloadEnc: "x", PayloadSHA256: "y"}, nil
	})
	if !isNotFound(err) {
		t.Errorf("CreateSecretVersion(missing secret) = %v, want ErrNotFound", err)
	}
	if sealCalled {
		t.Error("seal was called for a secret that does not exist - the version was never reserved")
	}
}

func TestSecretBindings(t *testing.T) {
	ctx := context.Background()
	st := newTestStoreForSecrets(t)

	sec, err := st.CreateSecret(ctx, &Secret{Name: "team-a/tls", Type: SecretTypeCertificate})
	if err != nil {
		t.Fatal(err)
	}

	b1, err := st.CreateSecretBinding(ctx, &SecretBinding{
		SecretID:          sec.ID,
		K8sNamespace:      "team-a",
		K8sServiceAccount: "web-*",
		CreatedBy:         "admin",
	})
	if err != nil {
		t.Fatalf("CreateSecretBinding: %v", err)
	}
	if b1.SecretName != "team-a/tls" {
		t.Errorf("CreateSecretBinding did not join the secret name: got %q", b1.SecretName)
	}
	if !b1.Usable() {
		t.Error("a binding with no expiry should be usable")
	}

	past := time.Now().Add(-time.Hour)
	b2, err := st.CreateSecretBinding(ctx, &SecretBinding{
		SecretID:          sec.ID,
		K8sNamespace:      "team-b",
		K8sServiceAccount: "*",
		ExpiresAt:         &past,
	})
	if err != nil {
		t.Fatal(err)
	}
	if b2.Usable() {
		t.Error("a binding expired an hour ago should not be usable")
	}

	list, err := st.ListSecretBindings(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ListSecretBindings = %d, want 2", len(list))
	}

	all, err := st.ListAllSecretBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("ListAllSecretBindings = %d, want 2", len(all))
	}

	if err := st.DeleteSecretBinding(ctx, b1.ID); err != nil {
		t.Fatalf("DeleteSecretBinding: %v", err)
	}
	if list, err := st.ListSecretBindings(ctx, sec.ID); err != nil || len(list) != 1 {
		t.Errorf("ListSecretBindings after delete = %d, %v, want 1", len(list), err)
	}
	if err := st.DeleteSecretBinding(ctx, 999999); !isNotFound(err) {
		t.Errorf("DeleteSecretBinding(missing) = %v, want ErrNotFound", err)
	}
}

func TestDeleteSecretCascadesVersionsAndBindings(t *testing.T) {
	ctx := context.Background()
	st := newTestStoreForSecrets(t)

	sec, err := st.CreateSecret(ctx, &Secret{Name: "team-a/cascade", Type: SecretTypeKV})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSecretVersion(ctx, sec.ID, "", "", func(int64, int) (SealedVersion, error) {
		return SealedVersion{PayloadEnc: "x", PayloadSHA256: "y"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateSecretBinding(ctx, &SecretBinding{SecretID: sec.ID, K8sNamespace: "*", K8sServiceAccount: "*"}); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteSecret(ctx, sec.ID); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := st.GetSecret(ctx, sec.ID); !isNotFound(err) {
		t.Errorf("GetSecret after delete = %v, want ErrNotFound", err)
	}
	versions, err := st.ListSecretVersions(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Errorf("ListSecretVersions after cascading delete = %d, want 0", len(versions))
	}
	bindings, err := st.ListSecretBindings(ctx, sec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Errorf("ListSecretBindings after cascading delete = %d, want 0", len(bindings))
	}
	if err := st.DeleteSecret(ctx, sec.ID); !isNotFound(err) {
		t.Errorf("DeleteSecret(already gone) = %v, want ErrNotFound", err)
	}
}

func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
