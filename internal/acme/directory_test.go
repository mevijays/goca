package acme

import (
	"net/url"
	"testing"
)

// TestDirectoryURLsAreAbsolute guards the failure that made goca's ACME
// endpoint unusable in practice: every directory URL is built by
// concatenating server.base_url, so a base_url without a scheme yields
// entries like "ca.test/acme/new-nonce". RFC 8555 §7.1.1 requires absolute
// URLs, and a Go ACME client (cert-manager included) rejects a scheme-less
// one with `unsupported protocol scheme ""` on its very first request - so
// the break shows up as an ACME client that cannot even fetch a nonce, long
// before anything is logged server-side.
//
// config.NormalizeBaseURL is what now keeps a scheme-less base_url from
// being loaded at all; this asserts the property that actually matters to a
// client, at the layer that serves it.
func TestDirectoryURLsAreAbsolute(t *testing.T) {
	svc := newTestService(t)
	dir := svc.Directory()

	for name, raw := range map[string]string{
		"newNonce":   dir.NewNonce,
		"newAccount": dir.NewAccount,
		"newOrder":   dir.NewOrder,
		"revokeCert": dir.RevokeCert,
	} {
		t.Run(name, func(t *testing.T) {
			if raw == "" {
				t.Fatalf("%s is empty", name)
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("%s = %q: %v", name, raw, err)
			}
			if !u.IsAbs() {
				t.Fatalf("%s = %q, want an absolute URL (RFC 8555 §7.1.1); "+
					"an ACME client fails this with `unsupported protocol scheme %q`", name, raw, u.Scheme)
			}
			if u.Host == "" {
				t.Fatalf("%s = %q, want a host", name, raw)
			}
		})
	}
}
