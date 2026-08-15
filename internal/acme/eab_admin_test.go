package acme

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/mevijays/goca/internal/ca"
	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/pki"
	"github.com/mevijays/goca/internal/store"
)

// newTestService builds an acme.Service backed by a throwaway database and a
// root CA, mirroring internal/ca's own test harness.
func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "acme-test.db")
	cfg.Server.BaseURL = "http://ca.test"
	if err := cfg.GenerateSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	caSvc, err := ca.New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caSvc.CreateCA(context.Background(), ca.CreateCAInput{
		Name:    "Test Root CA",
		Subject: pki.Subject{CommonName: "Test Root CA"},
		KeyType: "ec-p256",
		Days:    3650,
		Actor:   "tester",
	}); err != nil {
		t.Fatal(err)
	}
	return New(caSvc)
}

func TestResolveEABByIDKeyIDAndName(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateEAB(ctx, CreateEABInput{Name: "cluster-a", Actor: "t"})
	if err != nil {
		t.Fatalf("CreateEAB: %v", err)
	}

	for _, ref := range []string{strconv.FormatInt(res.Cred.ID, 10), res.Cred.KeyID, "cluster-a", "CLUSTER-A"} {
		got, err := svc.ResolveEAB(ctx, ref)
		if err != nil {
			t.Errorf("ResolveEAB(%q): %v", ref, err)
			continue
		}
		if got.ID != res.Cred.ID {
			t.Errorf("ResolveEAB(%q) returned id %d, want %d", ref, got.ID, res.Cred.ID)
		}
	}

	if _, err := svc.ResolveEAB(ctx, "does-not-exist"); err == nil {
		t.Error("ResolveEAB accepted an unknown reference")
	}
}

func TestResolveEABAmbiguousNameIsRejected(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.CreateEAB(ctx, CreateEABInput{Name: "shared", Actor: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateEAB(ctx, CreateEABInput{Name: "shared", Actor: "t"}); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.ResolveEAB(ctx, "shared"); err == nil {
		t.Error("a name matching two credentials should be rejected as ambiguous, not silently picked")
	}
}

func TestDeleteEABRefusesWhileAccountsExist(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	res, err := svc.CreateEAB(ctx, CreateEABInput{Name: "in-use", Actor: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.st.CreateAcmeAccount(ctx, &store.AcmeAccount{
		EABID: res.Cred.ID, JWKJSON: "{}", JWKThumbprint: "abc", Status: store.AcmeStatusValid,
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.DeleteEAB(ctx, res.Cred.ID, "t"); err == nil {
		t.Fatal("deleted a credential that still has accounts bootstrapped from it")
	}
	if err := svc.SetEABDisabled(ctx, res.Cred.ID, true, "t"); err != nil {
		t.Fatalf("disabling should still work: %v", err)
	}
}

func TestCreateEABRejectsUnknownCA(t *testing.T) {
	svc := newTestService(t)
	_, err := svc.CreateEAB(context.Background(), CreateEABInput{
		Name: "x", CARef: "no-such-authority", Actor: "t",
	})
	if err == nil {
		t.Fatal("CreateEAB accepted a nonexistent authority reference")
	}
}
