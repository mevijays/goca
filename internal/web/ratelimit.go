package web

import (
	"context"
	"time"

	"github.com/mevijays/goca/internal/store"
)

// Throttling for the endpoints that check a credential. Before the API login
// endpoint existed, the only such endpoint was the portal's HTML form, which
// is awkward to script against; a JSON endpoint that returns a token is a
// much more convenient password oracle, so both are throttled here.
//
// Failures are recorded in the shared database, not in process memory. With
// several goca replicas behind one Service, per-process counters would let an
// attacker make loginFailLimit guesses against EACH pod per window - and a
// load balancer spreads them across pods for free. Counting in the database
// makes the limit hold for the deployment as a whole. Old rows are purged by
// the server's janitor (see Server.janitor).

const (
	// loginFailLimit is how many failures a key may accumulate inside
	// loginFailWindow before it is refused.
	loginFailLimit = 5
	// loginFailWindow is the sliding window failures are counted over, and
	// also how long a tripped key stays refused.
	loginFailWindow = 15 * time.Minute
)

// failCounter counts recent authentication failures per key, across every
// replica sharing the database.
type failCounter struct {
	st *store.Store
}

func newFailCounter(st *store.Store) *failCounter { return &failCounter{st: st} }

// retryAfter reports how long key must wait before its next attempt, or 0.
//
// A database error fails open: the credential check that follows needs the
// same database and will fail on its own, so refusing here would only add a
// misleading "too many attempts" to an outage.
func (f *failCounter) retryAfter(ctx context.Context, key string) time.Duration {
	now := time.Now()
	recent, err := f.st.RecentAuthFailures(ctx, key, now.Add(-loginFailWindow), loginFailLimit)
	if err != nil || len(recent) < loginFailLimit {
		return 0
	}
	if wait := recent[0].Add(loginFailWindow).Sub(now); wait > 0 {
		return wait
	}
	return 0
}

// Fail records one failure for key.
func (f *failCounter) Fail(ctx context.Context, key string) {
	_ = f.st.RecordAuthFailure(ctx, key, time.Now())
}

// Reset forgets key's failures (after a successful sign-in).
func (f *failCounter) Reset(ctx context.Context, key string) {
	_ = f.st.ClearAuthFailures(ctx, key)
}

// Purge drops failures that no longer count towards any window.
func (f *failCounter) Purge(ctx context.Context) (int64, error) {
	return f.st.PurgeAuthFailures(ctx, time.Now().Add(-loginFailWindow))
}

// loginThrottle reports how long a sign-in for username from ip must wait.
// Both keys are checked so neither rotating usernames from one address nor
// spreading one username across addresses gets past the limit.
func (s *Server) loginThrottle(ctx context.Context, username, ip string) time.Duration {
	if wait := s.logins.retryAfter(ctx, "user:"+username); wait > 0 {
		return wait
	}
	return s.logins.retryAfter(ctx, "ip:"+ip)
}

func (s *Server) loginFailed(ctx context.Context, username, ip string) {
	s.logins.Fail(ctx, "user:"+username)
	s.logins.Fail(ctx, "ip:"+ip)
}

func (s *Server) loginSucceeded(ctx context.Context, username, ip string) {
	s.logins.Reset(ctx, "user:"+username)
	s.logins.Reset(ctx, "ip:"+ip)
}
