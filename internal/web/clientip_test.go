package web

import (
	"net"
	"net/http"
	"testing"
)

// newClientIPServer builds a minimal Server with the given trusted proxy
// CIDRs, just enough to exercise clientIP without a full harness.
func newClientIPServer(t *testing.T, proxies ...string) *Server {
	t.Helper()
	return &Server{trustedProxies: parseTrustedProxies(proxies)}
}

func reqWithIP(remoteAddr, xff string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr}
	if xff != "" {
		r.Header = http.Header{"X-Forwarded-For": []string{xff}}
	}
	return r
}

func TestClientIPNoTrustedProxiesIgnoresXFF(t *testing.T) {
	s := newClientIPServer(t)
	// No trusted proxies: a spoofed X-Forwarded-For must be ignored and the
	// TCP peer returned.
	if got := s.clientIP(reqWithIP("203.0.113.7:51000", "1.2.3.4")); got != "203.0.113.7" {
		t.Fatalf("got %q, want 203.0.113.7 (XFF must be ignored without trusted proxies)", got)
	}
}

func TestClientIPUntrustedPeerIgnoresXFF(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Peer is outside the trusted range: XFF is not credible.
	if got := s.clientIP(reqWithIP("203.0.113.7:51000", "10.1.2.3")); got != "203.0.113.7" {
		t.Fatalf("got %q, want 203.0.113.7 (untrusted peer's XFF must be ignored)", got)
	}
}

func TestClientIPTrustedProxyTakesRealClient(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Proxy at 10.0.0.5 received the request from client 198.51.100.9.
	if got := s.clientIP(reqWithIP("10.0.0.5:443", "198.51.100.9")); got != "198.51.100.9" {
		t.Fatalf("got %q, want 198.51.100.9", got)
	}
}

func TestClientIPTrustedProxyIgnoresSpoofedLeftmost(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Attacker (198.51.100.9) behind a trusted proxy injects a fake leftmost
	// entry. The walk from the right must return the real client, not the
	// forged 1.2.3.4.
	if got := s.clientIP(reqWithIP("10.0.0.5:443", "1.2.3.4, 198.51.100.9")); got != "198.51.100.9" {
		t.Fatalf("got %q, want 198.51.100.9 (spoofed leftmost entry must be ignored)", got)
	}
}

func TestClientIPProxyChainReturnsFirstNonProxyFromRight(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Two trusted proxies in series: client -> 10.0.0.6 -> 10.0.0.5 -> goca.
	// Chain as seen by goca: "198.51.100.9, 10.0.0.6". Walking from the right,
	// 10.0.0.6 is a proxy, so the client 198.51.100.9 is returned.
	if got := s.clientIP(reqWithIP("10.0.0.5:443", "198.51.100.9, 10.0.0.6")); got != "198.51.100.9" {
		t.Fatalf("got %q, want 198.51.100.9", got)
	}
}

func TestClientIPAllTrustedFallsBackToPeer(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Every entry is a trusted proxy; fall back to the direct peer.
	if got := s.clientIP(reqWithIP("10.0.0.5:443", "10.0.0.6")); got != "10.0.0.5" {
		t.Fatalf("got %q, want 10.0.0.5 (all-trusted chain falls back to peer)", got)
	}
}

func TestClientIPTrustedProxyNoXFFReturnsPeer(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8")
	// Trusted peer but no XFF header at all: return the peer.
	if got := s.clientIP(reqWithIP("10.0.0.5:443", "")); got != "10.0.0.5" {
		t.Fatalf("got %q, want 10.0.0.5", got)
	}
}

func TestIsTrustedProxy(t *testing.T) {
	s := newClientIPServer(t, "10.0.0.0/8", "192.168.1.10/32")
	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.1.2.3:443", true},
		{"192.168.1.10", true},
		{"192.168.1.11", false},
		{"203.0.113.7", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := s.isTrustedProxy(c.addr); got != c.want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestParseTrustedProxiesSkipsBadEntries(t *testing.T) {
	got := parseTrustedProxies([]string{"10.0.0.0/8", "garbage", "192.168.1.10"})
	if len(got) != 2 {
		t.Fatalf("got %d networks, want 2 (bad entry skipped)", len(got))
	}
	// The bare IP must have been normalized to a /32 that matches itself.
	if !got[1].Contains(net.ParseIP("192.168.1.10")) {
		t.Fatal("bare IP entry should match its own address")
	}
	if got[1].Contains(net.ParseIP("192.168.1.11")) {
		t.Fatal("bare IP entry must not match a different address")
	}
}
