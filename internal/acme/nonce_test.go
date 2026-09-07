package acme

import "testing"

// TestNonceManagerIssueAndConsume covers the basic contract: New() hands out
// a usable, single-use nonce, and does so without panicking under normal
// operation - New() panics on a crypto/rand.Read failure (see nonce.go), and
// this is the test that would catch an accidental regression turning that
// into a spurious panic on the happy path.
func TestNonceManagerIssueAndConsume(t *testing.T) {
	m := NewNonceManager()

	n := m.New()
	if n == "" {
		t.Fatal("New() returned an empty nonce")
	}

	if !m.Consume(n) {
		t.Fatal("Consume() rejected a freshly issued, unused nonce")
	}
	if m.Consume(n) {
		t.Fatal("Consume() accepted the same nonce twice - it must be single-use")
	}
}

// TestNonceManagerNewNeverRepeats is a cheap sanity check that New() is
// actually drawing fresh randomness each call, not returning a fixed or
// degenerate value.
func TestNonceManagerNewNeverRepeats(t *testing.T) {
	m := NewNonceManager()
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		n := m.New()
		if seen[n] {
			t.Fatalf("New() returned a duplicate nonce %q after %d calls", n, i)
		}
		seen[n] = true
	}
}

func TestNonceManagerConsumeRejectsUnknown(t *testing.T) {
	m := NewNonceManager()
	if m.Consume("") {
		t.Fatal("Consume(\"\") accepted an empty nonce")
	}
	if m.Consume("never-issued") {
		t.Fatal("Consume() accepted a nonce it never issued")
	}
}
