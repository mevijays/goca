package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// nonceTTL bounds how long an issued nonce remains redeemable. ACME clients
// fetch a nonce and use it within the same request, so this is generous
// headroom, not a session lifetime.
const nonceTTL = 10 * time.Minute

// NonceManager issues and single-use-consumes ACME replay nonces. It is kept
// in memory rather than in SQLite: nonces are inherently ephemeral, a restart
// losing them is indistinguishable from the client racing a concurrent
// request (both produce badNonce, which every ACME client already retries on
// per RFC 8555 §6.5), and it avoids a database write on every response.
type NonceManager struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewNonceManager creates an empty manager.
func NewNonceManager() *NonceManager {
	return &NonceManager{nonces: make(map[string]time.Time)}
}

// New issues a fresh nonce. Called for every /new-nonce request and stamped
// onto the Replay-Nonce header of every other ACME response, successful or
// not, per §6.5.
func (m *NonceManager) New() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()
	m.nonces[n] = time.Now().Add(nonceTTL)
	return n
}

// Consume redeems a nonce: true if it was valid and unused, in which case it
// is removed so it cannot be replayed.
func (m *NonceManager) Consume(n string) bool {
	if n == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	exp, ok := m.nonces[n]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(m.nonces, n)
	return true
}

// sweepLocked drops expired entries. Called opportunistically from New so no
// background goroutine or shutdown hook is needed; the map never grows
// unbounded in practice since ACME traffic is issuance-rate, not high-volume.
func (m *NonceManager) sweepLocked() {
	now := time.Now()
	for n, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, n)
		}
	}
}
