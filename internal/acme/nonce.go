package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/mevijays/goca/internal/store"
)

// nonceTTL bounds how long an issued nonce remains redeemable. ACME clients
// fetch a nonce and use it within the same request, so this is generous
// headroom, not a session lifetime.
const nonceTTL = 10 * time.Minute

// NonceManager issues and single-use-consumes ACME replay nonces (RFC 8555
// §6.5), stored in the shared database.
//
// They used to live in an in-process map. That is fine for one goca process,
// but behind a Kubernetes Service with several replicas a nonce handed out by
// one pod is presented to another about (N-1)/N of the time - a badNonce
// every time. Clients retry badNonce, but each retry lands on a random pod
// again, so with three replicas most ACME flows needed several round trips
// and some ran out of retries. In the database every replica can redeem any
// nonce, and ConsumeAcmeNonce's conditional DELETE still lets exactly one of
// them succeed, which is the replay protection the nonce exists for.
type NonceManager struct {
	st *store.Store
}

// NewNonceManager creates a manager over the shared store.
func NewNonceManager(st *store.Store) *NonceManager {
	return &NonceManager{st: st}
}

// New issues and records a fresh nonce. Called for every /new-nonce request
// and stamped onto the Replay-Nonce header of every other ACME response,
// successful or not, per §6.5.
func (m *NonceManager) New(ctx context.Context) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read does not fail on any supported platform; a nonce
		// that might not be genuinely random must not be handed out.
		panic("acme: crypto/rand.Read failed: " + err.Error())
	}
	n := base64.RawURLEncoding.EncodeToString(b)
	if err := m.st.CreateAcmeNonce(ctx, n, time.Now().Add(nonceTTL)); err != nil {
		return "", err
	}
	return n, nil
}

// Consume redeems a nonce: true if it was issued, unexpired and not yet used,
// in which case it can never be redeemed again - by this replica or any other.
func (m *NonceManager) Consume(ctx context.Context, n string) bool {
	if n == "" {
		return false
	}
	ok, err := m.st.ConsumeAcmeNonce(ctx, n, time.Now())
	return err == nil && ok
}

// Purge drops expired nonces nobody redeemed. Safe to run from every replica.
func (m *NonceManager) Purge(ctx context.Context) (int64, error) {
	return m.st.PurgeExpiredAcmeNonces(ctx, time.Now())
}
