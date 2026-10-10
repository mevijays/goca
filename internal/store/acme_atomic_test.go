package store

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// openTestStores returns SQLite always, plus PostgreSQL when
// GOCA_TEST_PG_HOST is set (with GOCA_TEST_PG_PORT/_USER/_PASSWORD/_DB). The
// conditional UPDATEs below lean on RowsAffected and on the not_after
// migration's per-dialect DDL - exactly what differs between the two.
func openTestStores(t *testing.T) map[string]*Store {
	t.Helper()
	out := map[string]*Store{}
	sq, err := Open(filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	out["sqlite"] = sq

	if host := os.Getenv("GOCA_TEST_PG_HOST"); host != "" {
		port, _ := strconv.Atoi(os.Getenv("GOCA_TEST_PG_PORT"))
		pg, err := OpenPostgres(PostgresParams{
			Host: host, Port: port, SSLMode: "disable",
			User: os.Getenv("GOCA_TEST_PG_USER"), Password: os.Getenv("GOCA_TEST_PG_PASSWORD"),
			Name: os.Getenv("GOCA_TEST_PG_DB"),
		})
		if err != nil {
			t.Fatalf("postgres: %v", err)
		}
		t.Cleanup(func() { pg.Close() })
		out["postgres"] = pg
	}
	return out
}

func TestReserveEABAccountSlotIsAtomic(t *testing.T) {
	for name, st := range openTestStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cred, err := st.CreateEABCred(ctx, &EABCred{
				KeyID: "atomic-" + strconv.FormatInt(time.Now().UnixNano(), 36), HMACKeyEnc: "x",
				Name: "one-shot", Profile: "server", MaxAccounts: 1, CreatedAt: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			var won int32
			var wg sync.WaitGroup
			for i := 0; i < 25; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if ok, err := st.ReserveEABAccountSlot(ctx, cred.ID); err == nil && ok {
						atomic.AddInt32(&won, 1)
					}
				}()
			}
			wg.Wait()
			if won != 1 {
				t.Fatalf("max_accounts=1 but %d concurrent reservations succeeded", won)
			}
			// Releasing gives the slot back exactly once.
			if err := st.ReleaseEABAccountSlot(ctx, cred.ID); err != nil {
				t.Fatal(err)
			}
			if ok, _ := st.ReserveEABAccountSlot(ctx, cred.ID); !ok {
				t.Fatal("slot not available again after release")
			}
		})
	}
}

func TestClaimAcmeOrderForFinalizeIsExclusive(t *testing.T) {
	for name, st := range openTestStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cred, err := st.CreateEABCred(ctx, &EABCred{
				KeyID: "claim-" + strconv.FormatInt(time.Now().UnixNano(), 36), HMACKeyEnc: "x",
				Name: "c", Profile: "server", CreatedAt: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			acct, err := st.CreateAcmeAccount(ctx, &AcmeAccount{
				EABID: cred.ID, JWKJSON: "{}", JWKThumbprint: "tp-" + cred.KeyID,
				Status: AcmeStatusValid, CreatedAt: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			want := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
			o, err := st.CreateAcmeOrder(ctx, &AcmeOrder{
				AccountID: acct.ID, Status: AcmeStatusReady,
				Identifiers: []AcmeIdentifier{{Type: "dns", Value: "a.internal"}},
				ExpiresAt:   time.Now().Add(time.Hour), CreatedAt: time.Now(), NotAfter: &want,
			})
			if err != nil {
				t.Fatal(err)
			}
			// not_after round-trips through the migrated column, as an instant.
			if o.NotAfter == nil || !o.NotAfter.Equal(want) {
				t.Fatalf("not_after = %v, want %v", o.NotAfter, want)
			}

			var won int32
			var wg sync.WaitGroup
			for i := 0; i < 25; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if ok, err := st.ClaimAcmeOrderForFinalize(ctx, o.ID); err == nil && ok {
						atomic.AddInt32(&won, 1)
					}
				}()
			}
			wg.Wait()
			if won != 1 {
				t.Fatalf("%d concurrent finalize claims succeeded, want exactly 1", won)
			}

			// A completed order is never demoted by a late failure. (Set the
			// status directly: linking a real certificate needs a CA, which
			// is beside the point here.)
			if _, err := st.db.ExecContext(ctx, `UPDATE acme_orders SET status = ? WHERE id = ?`, AcmeStatusValid, o.ID); err != nil {
				t.Fatal(err)
			}
			if err := st.SetAcmeOrderError(ctx, o.ID, `{"detail":"late failure"}`); err != nil {
				t.Fatal(err)
			}
			got, err := st.GetAcmeOrder(ctx, o.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != AcmeStatusValid {
				t.Fatalf("a late error demoted a completed order to %q", got.Status)
			}
		})
	}
}
