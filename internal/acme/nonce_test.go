package acme

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mevijays/goca/internal/store"
)

func newNonceStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "nonce.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestNonceManagerIssueAndConsume covers the basic contract: New() hands out
// a usable, single-use nonce, and does so without panicking under normal
// operation - New() panics on a crypto/rand.Read failure (see nonce.go), and
// this is the test that would catch an accidental regression turning that
// into a spurious panic on the happy path.
func TestNonceManagerIssueAndConsume(t *testing.T) {
	ctx := context.Background()
	m := NewNonceManager(newNonceStore(t))

	n, err := m.New(ctx)
	if err != nil || n == "" {
		t.Fatalf("New() = %q, %v", n, err)
	}
	if !m.Consume(ctx, n) {
		t.Fatal("Consume() rejected a freshly issued, unused nonce")
	}
	if m.Consume(ctx, n) {
		t.Fatal("Consume() accepted the same nonce twice - it must be single-use")
	}
	if m.Consume(ctx, "never-issued") || m.Consume(ctx, "") {
		t.Fatal("Consume() accepted a nonce that was never issued")
	}
}

// TestNonceManagerNewNeverRepeats is a cheap sanity check that New() is
// actually drawing fresh randomness each call, not returning a fixed or
// degenerate value.
func TestNonceManagerNewNeverRepeats(t *testing.T) {
	ctx := context.Background()
	m := NewNonceManager(newNonceStore(t))
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := m.New(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("New() repeated a nonce after %d calls", i)
		}
		seen[n] = true
	}
}

// TestNonceIssuedByOneReplicaRedeemableByAnother is the clustering contract:
// two NonceManagers over the same database stand in for two goca pods behind
// one Service. A nonce from either must be redeemable at the other, and when
// many pods race to redeem the same nonce exactly one may succeed.
func TestNonceIssuedByOneReplicaRedeemableByAnother(t *testing.T) {
	ctx := context.Background()
	st := newNonceStore(t)
	podA, podB := NewNonceManager(st), NewNonceManager(st)

	n, err := podA.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !podB.Consume(ctx, n) {
		t.Fatal("a nonce issued by one replica was rejected by another")
	}
	if podA.Consume(ctx, n) {
		t.Fatal("a nonce redeemed at one replica was accepted again at another")
	}

	n, err = podA.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(m *NonceManager) {
			defer wg.Done()
			if m.Consume(ctx, n) {
				atomic.AddInt32(&wins, 1)
			}
		}([]*NonceManager{podA, podB}[i%2])
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("a nonce was redeemed %d times by racing replicas, want exactly 1", wins)
	}
}
