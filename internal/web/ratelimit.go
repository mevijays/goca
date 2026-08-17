package web

import (
	"sync"
	"time"
)

// Throttling for the endpoints that check a credential. Before the API login
// endpoint existed, the only such endpoint was the portal's HTML form, which
// is awkward to script against; a JSON endpoint that returns a token is a
// much more convenient password oracle, so both are throttled here.
//
// This is in-process and in-memory, the same choice internal/acme's nonce
// store makes and for the same reason: goca is a single-process server, and a
// shared-state limiter would need infrastructure the project deliberately
// does not have. A restart clears the counters, which is an accepted
// trade-off - an attacker cannot trigger a restart, and an operator restarting
// to clear a lockout is a feature.

const (
	// loginFailLimit is how many failures a key may accumulate inside
	// loginFailWindow before it is refused.
	loginFailLimit = 5
	// loginFailWindow is the sliding window failures are counted over, and
	// also how long a tripped key stays refused.
	loginFailWindow = 15 * time.Minute
	// maxFailKeys bounds the map so an attacker rotating usernames cannot
	// grow it without limit. Past this, the oldest entries are dropped.
	maxFailKeys = 10000
)

// failCounter counts recent authentication failures per key.
type failCounter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newFailCounter() *failCounter {
	return &failCounter{hits: make(map[string][]time.Time)}
}

// retryAfter reports how long a key must wait, or 0 when it may proceed. It
// does not record anything - call Fail for that.
func (f *failCounter) retryAfter(key string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	recent := f.recentLocked(key, time.Now())
	if len(recent) < loginFailLimit {
		return 0
	}
	// Refuse until the oldest failure in the window ages out.
	return time.Until(recent[0].Add(loginFailWindow))
}

// Fail records one failed attempt against a key.
func (f *failCounter) Fail(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.hits[key] = append(f.recentLocked(key, now), now)
	f.evictLocked(now)
}

// Reset clears a key after a success.
func (f *failCounter) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hits, key)
}

// recentLocked returns key's failures still inside the window.
func (f *failCounter) recentLocked(key string, now time.Time) []time.Time {
	cutoff := now.Add(-loginFailWindow)
	hits := f.hits[key]
	i := 0
	for ; i < len(hits); i++ {
		if hits[i].After(cutoff) {
			break
		}
	}
	if i > 0 {
		hits = hits[i:]
		if len(hits) == 0 {
			delete(f.hits, key)
		} else {
			f.hits[key] = hits
		}
	}
	return hits
}

// evictLocked keeps the map bounded. It first drops keys whose failures have
// all aged out, and only if that is not enough drops arbitrary keys - which is
// safe, since forgetting a key can only ever be more permissive, never less.
func (f *failCounter) evictLocked(now time.Time) {
	if len(f.hits) <= maxFailKeys {
		return
	}
	cutoff := now.Add(-loginFailWindow)
	for k, hits := range f.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(f.hits, k)
		}
	}
	for k := range f.hits {
		if len(f.hits) <= maxFailKeys {
			break
		}
		delete(f.hits, k)
	}
}

// loginThrottle checks both the username and the client address before a
// credential is tested. They are counted separately on purpose: per-username
// stops one account being ground down from many hosts, per-IP stops one host
// spraying many usernames. Returns the wait, or 0 to proceed.
func (s *Server) loginThrottle(username, ip string) time.Duration {
	if wait := s.logins.retryAfter("user:" + username); wait > 0 {
		return wait
	}
	return s.logins.retryAfter("ip:" + ip)
}

// loginFailed records a failure against both keys.
func (s *Server) loginFailed(username, ip string) {
	s.logins.Fail("user:" + username)
	s.logins.Fail("ip:" + ip)
}

// loginSucceeded clears both counters after a correct password.
//
// Clearing the per-IP counter is a deliberate trade-off. Not clearing it locks
// out anyone who mistypes a few times, signs in correctly, then mistypes once
// more - and it is worse behind NAT, where one person's fumbling would spend
// a whole office's budget. Against that, an attacker who already holds one
// valid account could sign into it to reset their own per-IP budget. That
// costs little: the per-username counter is what actually protects a targeted
// account, it is never reset by somebody else's success, and an attacker with
// no valid account - the case per-IP throttling exists for - never succeeds
// and so never resets anything.
func (s *Server) loginSucceeded(username, ip string) {
	s.logins.Reset("user:" + username)
	s.logins.Reset("ip:" + ip)
}
