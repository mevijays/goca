package store

// Concurrency tests for the shared-database (multi-replica) deployment: each
// simulates several goca replicas hitting the same rows at once. On SQLite
// writes are serialized by the database, so the interesting run is the
// PostgreSQL one (GOCA_TEST_PG_HOST, see openTestStores) - which is where the
// read-then-write races these guard against actually happened.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestClaimDueWebhookDeliveriesIsExclusive(t *testing.T) {
	for name, st := range openTestStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			wh, err := st.CreateWebhook(ctx, &Webhook{
				Name: fmt.Sprintf("race-%d", time.Now().UnixNano()), URL: "https://hooks.invalid/x", Events: "*",
			})
			if err != nil {
				t.Fatal(err)
			}
			const total = 300
			want := map[int64]bool{}
			for i := 0; i < total; i++ {
				d, err := st.CreateWebhookDelivery(ctx, wh.ID, "cert.issue", "{}")
				if err != nil {
					t.Fatal(err)
				}
				want[d.ID] = true
			}

			// Eight "replicas" polling until the queue is drained.
			var mu sync.Mutex
			claims := map[int64]int{}
			var wg sync.WaitGroup
			for r := 0; r < 8; r++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for empty := 0; empty < 3; {
						got, err := st.ClaimDueWebhookDeliveries(ctx, time.Now().UTC(), time.Hour, 25)
						if err != nil {
							t.Error(err)
							return
						}
						if len(got) == 0 {
							empty++
							continue
						}
						mu.Lock()
						for _, d := range got {
							if want[d.ID] {
								claims[d.ID]++
							}
						}
						mu.Unlock()
					}
				}()
			}
			wg.Wait()

			dupes := 0
			for id, n := range claims {
				if n > 1 {
					dupes++
					if dupes <= 3 {
						t.Errorf("delivery %d claimed %d times - it would be delivered %d times", id, n, n)
					}
				}
			}
			if dupes > 0 {
				t.Fatalf("%d of %d deliveries were claimed by more than one replica", dupes, total)
			}
			if len(claims) != total {
				t.Fatalf("claimed %d distinct deliveries, want %d", len(claims), total)
			}
		})
	}
}

func TestNextCRLNumberIsStrictlyIncreasingAcrossReplicas(t *testing.T) {
	for name, st := range openTestStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			ca := mustCreateTestCA(t, st)
			const n = 40
			var mu sync.Mutex
			seen := map[int64]int{}
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := st.NextCRLNumber(ctx, ca.ID)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					seen[v]++
					mu.Unlock()
				}()
			}
			wg.Wait()
			for v, c := range seen {
				if c > 1 {
					t.Errorf("CRL number %d was handed out %d times", v, c)
				}
			}
			if len(seen) != n {
				t.Fatalf("%d distinct CRL numbers for %d CRLs", len(seen), n)
			}
		})
	}
}

func TestCreateSecretVersionConcurrentWritersAllSucceed(t *testing.T) {
	for name, st := range openTestStores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			sec, err := st.CreateSecret(ctx, &Secret{
				Name: fmt.Sprintf("race/%d", time.Now().UnixNano()), Type: SecretTypeKV, CreatedBy: "t",
			})
			if err != nil {
				t.Fatal(err)
			}
			const n = 20
			errs := make(chan error, n)
			versions := make(chan int, n)
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					v, err := st.CreateSecretVersion(ctx, sec.ID, "text/plain", "t",
						func(_ int64, version int) (SealedVersion, error) {
							return SealedVersion{PayloadEnc: fmt.Sprintf("v%d", version), PayloadSHA256: "x", SizeBytes: 1}, nil
						})
					if err != nil {
						errs <- err
						return
					}
					versions <- v.Version
				}()
			}
			wg.Wait()
			close(errs)
			close(versions)
			for err := range errs {
				t.Errorf("a concurrent write failed: %v", err)
			}
			got := map[int]bool{}
			for v := range versions {
				got[v] = true
			}
			if len(got) != n {
				t.Fatalf("%d distinct versions from %d writes", len(got), n)
			}
		})
	}
}

// mustCreateTestCA stores a minimal CA row; these tests only need its
// counters, not a usable key or certificate.
func mustCreateTestCA(t *testing.T, st *Store) *CA {
	t.Helper()
	now := time.Now().UTC()
	slug := fmt.Sprintf("race-ca-%d", now.UnixNano())
	ca, err := st.CreateCA(context.Background(), &CA{
		Name: slug, Slug: slug, Subject: "CN=" + slug, SerialHex: slug, KeyType: "ec-p256",
		CertPEM: "x", IsRoot: true, NotBefore: now, NotAfter: now.AddDate(1, 0, 0),
		Status: "active", Fingerprint: slug, CreatedBy: "t", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// TestConcurrentOpenOnFreshPostgres simulates a rollout: several replicas
// starting at once against a database that has never seen goca, each
// applying the schema and migrations. PostgreSQL's CREATE TABLE IF NOT EXISTS
// is not safe against itself - two sessions can both decide a table is
// missing and one then fails on the catalog's unique index - so a scale-up or
// first install could crash-loop pods for no reason.
func TestConcurrentOpenOnFreshPostgres(t *testing.T) {
	host := os.Getenv("GOCA_TEST_PG_HOST")
	if host == "" {
		t.Skip("needs GOCA_TEST_PG_HOST (PostgreSQL)")
	}
	port, _ := strconv.Atoi(os.Getenv("GOCA_TEST_PG_PORT"))
	base := PostgresParams{Host: host, Port: port, SSLMode: "disable",
		User: os.Getenv("GOCA_TEST_PG_USER"), Password: os.Getenv("GOCA_TEST_PG_PASSWORD"),
		Name: os.Getenv("GOCA_TEST_PG_DB")}

	// A brand-new database for this run, so the schema really is applied.
	admin, err := OpenPostgres(base)
	if err != nil {
		t.Fatal(err)
	}
	fresh := fmt.Sprintf("goca_rollout_%d", time.Now().UnixNano())
	if _, err := admin.db.Exec(`CREATE DATABASE ` + fresh); err != nil {
		t.Fatal(err)
	}
	admin.Close()
	p := base
	p.Name = fresh

	const replicas = 6
	errs := make(chan error, replicas)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, err := OpenPostgres(p)
			if err != nil {
				errs <- err
				return
			}
			st.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a replica failed to start against a fresh database: %v", err)
	}
}
