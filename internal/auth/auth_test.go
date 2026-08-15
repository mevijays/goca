package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/mevijays/goca/internal/config"
	"github.com/mevijays/goca/internal/secret"
	"github.com/mevijays/goca/internal/store"
)

func newTestManager(t *testing.T) (*Manager, *store.Store, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.DBPath = filepath.Join(dir, "auth.db")
	cfg.Path = filepath.Join(dir, "config.yaml")
	if err := cfg.GenerateSecrets(); err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("AdminPassw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.LocalAdmin = config.LocalAdmin{Username: "admin", PasswordHash: hash}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(cfg.Path); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	key, _ := cfg.MasterKeyBytes()
	box, err := secret.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(cfg, st, box)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.EnsureLocalAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	return mgr, st, cfg
}

func TestLocalAdminCanAuthenticate(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	ctx := context.Background()

	u, err := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !u.IsAdmin() {
		t.Error("the break-glass account is not an admin")
	}
	if u.Source != store.SourceLocal {
		t.Errorf("source is %q", u.Source)
	}

	if _, err := mgr.Authenticate(ctx, "admin", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("a wrong password gave %v, want ErrInvalidCredentials", err)
	}
	if _, err := mgr.Authenticate(ctx, "nobody", "whatever"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("an unknown user gave %v, want ErrInvalidCredentials", err)
	}
	// The same error for both cases keeps the response from enumerating accounts.
}

func TestDisabledAccountCannotLogIn(t *testing.T) {
	mgr, st, _ := newTestManager(t)
	ctx := context.Background()

	u, err := mgr.CreateLocalUser(ctx, "bob", "BobPassw0rd!", "Bob", "bob@test", store.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Authenticate(ctx, "bob", "BobPassw0rd!"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := st.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Authenticate(ctx, "bob", "BobPassw0rd!"); !errors.Is(err, ErrDisabled) {
		t.Errorf("a disabled account gave %v, want ErrDisabled", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	ctx := context.Background()

	u, err := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	token, exp, err := mgr.CreateSession(ctx, u, "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if token == "" || exp.Before(time.Now()) {
		t.Fatal("a useless session was issued")
	}

	got, err := mgr.UserFromSession(ctx, token)
	if err != nil {
		t.Fatalf("UserFromSession: %v", err)
	}
	if got.ID != u.ID {
		t.Error("the session resolved to the wrong user")
	}
	if _, err := mgr.UserFromSession(ctx, "not-a-session"); err == nil {
		t.Error("a bogus session token was accepted")
	}

	if err := mgr.DestroySession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.UserFromSession(ctx, token); err == nil {
		t.Error("the session still resolves after being destroyed")
	}
}

func TestSessionTokenIsStoredHashed(t *testing.T) {
	mgr, st, _ := newTestManager(t)
	ctx := context.Background()

	u, _ := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")
	token, _, err := mgr.CreateSession(ctx, u, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Looking the raw token up as if it were the stored value must fail.
	if _, err := st.SessionUser(ctx, token); err == nil {
		t.Fatal("the session token is stored in the clear")
	}
	if _, err := st.SessionUser(ctx, HashToken(token)); err != nil {
		t.Fatalf("the hashed token does not resolve: %v", err)
	}
}

func TestAPITokenRoleIsCapped(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	ctx := context.Background()

	admin, _ := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")

	// An admin may mint a user-scoped token, and that token must not grant
	// admin rights even though its owner is an admin.
	plain, rec, err := mgr.IssueAPIToken(ctx, admin, "limited", store.RoleUser, time.Hour)
	if err != nil {
		t.Fatalf("IssueAPIToken: %v", err)
	}
	if rec.Role != store.RoleUser {
		t.Errorf("token role is %q", rec.Role)
	}
	effective, _, err := mgr.UserFromAPIToken(ctx, plain)
	if err != nil {
		t.Fatalf("UserFromAPIToken: %v", err)
	}
	if effective.IsAdmin() {
		t.Error("a user-scoped token granted admin rights")
	}

	// A non-admin cannot escalate by asking for an admin token.
	bob, err := mgr.CreateLocalUser(ctx, "bob", "BobPassw0rd!", "", "", store.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.IssueAPIToken(ctx, bob, "escalate", store.RoleAdmin, 0); err == nil {
		t.Error("a plain user was allowed to mint an admin token")
	}
}

func TestAPITokenExpiryAndRevocation(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	ctx := context.Background()
	admin, _ := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")

	expired, _, err := mgr.IssueAPIToken(ctx, admin, "expired", store.RoleUser, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.UserFromAPIToken(ctx, expired); err == nil {
		t.Error("an expired token was accepted")
	}

	live, rec, err := mgr.IssueAPIToken(ctx, admin, "live", store.RoleUser, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.UserFromAPIToken(ctx, live); err != nil {
		t.Fatalf("a live token was rejected: %v", err)
	}
	if err := mgr.RevokeAPIToken(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mgr.UserFromAPIToken(ctx, live); err == nil {
		t.Error("a revoked token was accepted")
	}
}

func TestAPITokenPrefixIsPredictableLength(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	ctx := context.Background()
	admin, _ := mgr.Authenticate(ctx, "admin", "AdminPassw0rd!")

	for i := 0; i < 25; i++ {
		plain, rec, err := mgr.IssueAPIToken(ctx, admin, "t", store.RoleUser, 0)
		if err != nil {
			t.Fatalf("IssueAPIToken: %v", err)
		}
		if len(rec.Prefix) != 8 {
			t.Fatalf("prefix %q is %d characters, want 8", rec.Prefix, len(rec.Prefix))
		}
		if want := TokenPrefix + rec.Prefix + "_"; plain[:len(want)] != want {
			t.Fatalf("token %q does not start with %q", plain, want)
		}
	}
}

func TestPasswordChangeUpdatesConfigForBreakGlassAdmin(t *testing.T) {
	mgr, st, cfg := newTestManager(t)
	ctx := context.Background()

	u, err := st.GetUserByName(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	oldHash := cfg.Auth.LocalAdmin.PasswordHash
	if err := mgr.SetPassword(ctx, u, "BrandNewPassw0rd!"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if cfg.Auth.LocalAdmin.PasswordHash == oldHash {
		t.Error("the config still holds the old hash, so a restart would undo the change")
	}

	// The new password works, and it survives a reload from disk.
	if _, err := mgr.Authenticate(ctx, "admin", "BrandNewPassw0rd!"); err != nil {
		t.Errorf("the new password does not work: %v", err)
	}
	reloaded, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(reloaded.Auth.LocalAdmin.PasswordHash, "BrandNewPassw0rd!") {
		t.Error("the persisted config does not carry the new password")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Error("a 5-character password was accepted")
	}
	if err := ValidatePassword("longenough"); err != nil {
		t.Errorf("a 10-character password was rejected: %v", err)
	}
}

func TestGeneratedPasswordsAreUsable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword(20)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 20 {
			t.Fatalf("generated password is %d characters, want 20", len(pw))
		}
		if err := ValidatePassword(pw); err != nil {
			t.Fatalf("a generated password fails the policy: %v", err)
		}
		if seen[pw] {
			t.Fatal("GeneratePassword repeated itself")
		}
		seen[pw] = true
	}
}

func TestLDAPDisabledByDefault(t *testing.T) {
	mgr, _, _ := newTestManager(t)
	if mgr.LDAPEnabled() {
		t.Error("LDAP should be off unless configured")
	}
	if !mgr.LocalEnabled() {
		t.Error("local login should be on by default")
	}
}
