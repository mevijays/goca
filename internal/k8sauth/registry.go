package k8sauth

import (
	"sort"
	"sync"
)

// Registry is a thread-safe cache of named Verifiers - one per CSI trust
// domain. The web layer builds a Verifier from each k8s_auth_methods row (after
// decrypting its reviewer token) and registers it here under the row's name.
//
// A Registry replaces the old single global Verifier: with one, every cluster
// shared one issuer/audience, so a token from cluster A could be presented
// against a binding meant for cluster B. With a Registry, the CSI provider
// names the trust domain it is running in, and the server verifies the token
// under exactly that domain's parameters.
//
// The cache is invalidated by the web layer whenever a k8s_auth_methods row is
// created, updated, or deleted - it calls Set/Remove, which rebuilds or drops
// the affected Verifier. Verifiers are cheap to build (OIDC discovery is lazy)
// and safe to rebuild, so there is no TTL; correctness comes from the
// invalidation hooks, not from expiry.
type Registry struct {
	mu        sync.RWMutex
	verifiers map[string]*Verifier
	// fingerprints records what each Verifier was built from, so a caller
	// that re-reads the source (the shared database) can tell whether the
	// cached Verifier is still current - see SetWithFingerprint.
	fingerprints map[string]string
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{verifiers: make(map[string]*Verifier), fingerprints: make(map[string]string)}
}

// SetWithFingerprint registers v for name along with a fingerprint of the
// configuration it was built from.
//
// Invalidating on writes (Set/Remove from the handler that changed a row) only
// reaches the process that handled the write. With several goca replicas
// sharing one database, every other replica would keep verifying tokens under
// the old trust-domain settings - or keep accepting a domain that was just
// disabled - until restarted. Callers that re-read the row per request can
// compare its fingerprint with GetWithFingerprint's and rebuild only on change.
func (r *Registry) SetWithFingerprint(name string, v *Verifier, fingerprint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifiers[name] = v
	r.fingerprints[name] = fingerprint
}

// GetWithFingerprint returns the Verifier for name and the fingerprint it was
// registered with ("" if registered with plain Set).
func (r *Registry) GetWithFingerprint(name string) (*Verifier, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.verifiers[name]
	return v, r.fingerprints[name], ok
}

// Set registers (or replaces) the Verifier for name.
func (r *Registry) Set(name string, v *Verifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifiers[name] = v
	delete(r.fingerprints, name)
}

// Remove drops the Verifier for name, if present.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.verifiers, name)
	delete(r.fingerprints, name)
}

// Get returns the Verifier registered under name, and whether it exists.
func (r *Registry) Get(name string) (*Verifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.verifiers[name]
	return v, ok
}

// Has reports whether a Verifier is registered under name.
func (r *Registry) Has(name string) bool {
	_, ok := r.Get(name)
	return ok
}

// Names returns the registered trust-domain names, sorted for stable output.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.verifiers))
	for name := range r.verifiers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Len reports how many trust domains are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.verifiers)
}
