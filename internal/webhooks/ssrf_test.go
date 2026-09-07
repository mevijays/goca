package webhooks

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://hooks.example.com/goca", false},
		{"http://10.0.0.5:9000/hook", false},    // ordinary private LAN receiver: allowed
		{"http://192.168.1.20/hook", false},     // same
		{"ftp://hooks.example.com", true},       // wrong scheme
		{"not a url at all", true},              // wrong scheme (parses as a relative path with no host)
		{"http://", true},                       // no host
		{"http://127.0.0.1:8080/hook", true},    // loopback
		{"http://[::1]/hook", true},             // loopback, IPv6
		{"http://169.254.169.254/latest", true}, // cloud metadata
	}
	for _, c := range cases {
		err := ValidateWebhookURL(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateWebhookURL(%q) = %v, wantErr %v", c.url, err, c.wantErr)
		}
	}
}

// TestDialerControlBlocksLoopbackAtConnectTime is the real security-boundary
// test: it does not check the URL string, it actually starts a listener on
// loopback and confirms the delivery transport refuses to connect to it. This
// is what a redirect to a blocked address, or a hostname that resolves
// differently after ValidateWebhookURL already ran, still has to go through.
func TestDialerControlBlocksLoopbackAtConnectTime(t *testing.T) {
	// A real server bound to loopback - reachable by address, exactly what a
	// same-host SSRF target looks like.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{Transport: newDeliveryTransport()}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("request to a loopback-bound server succeeded; the dial-time SSRF block did not fire")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("request failed, but not for the reason expected: %v", err)
	}
}

// TestDialerControlAllowsOrdinaryHosts confirms the block is narrow: an
// ordinary, non-loopback, non-link-local destination must still work, or the
// fix would have broken every legitimate webhook receiver on the same LAN
// goca itself runs on.
func TestDialerControlAllowsOrdinaryHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest binds to 127.0.0.1 by default; dial the same port directly
	// against a non-loopback-looking address is awkward to construct
	// portably in a unit test, so this test instead proves the Control hook
	// itself allows an ordinary address, exercising exactly the function the
	// transport installs.
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := dialerControl("tcp", "203.0.113.10:"+port, nil); err != nil {
		t.Errorf("dialerControl blocked an ordinary public address: %v", err)
	}
	if err := dialerControl("tcp", "10.0.0.5:"+port, nil); err != nil {
		t.Errorf("dialerControl blocked an ordinary private-LAN address: %v", err)
	}
}
