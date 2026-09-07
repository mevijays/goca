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
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{verifiers: make(map[string]*Verifier)}
}

// Set registers (or replaces) the Verifier for name.
func (r *Registry) Set(name string, v *Verifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifiers[name] = v
}

// Remove drops the Verifier for name, if present.
func (r *Registry) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.verifiers, name)
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
