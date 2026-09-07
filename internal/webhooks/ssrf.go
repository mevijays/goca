package webhooks

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// This file is the SSRF defense for webhook delivery. A webhook URL is
// operator-supplied (admin-only, but still: the server making a request to a
// caller-chosen address is the textbook SSRF shape), and goca is commonly
// deployed on the same private network as everything else it might be asked
// to reach - so the defense here is deliberately narrow: it blocks the
// destinations that can never be a legitimate webhook receiver (the host
// talking to itself, and cloud metadata services, which live at a link-local
// address on every major provider) rather than all of RFC1918, which would
// break the ordinary case of a webhook receiver on the same private LAN or
// VPC goca itself runs in.

// ValidateWebhookURL is the fast, early check run when a webhook is created
// or updated: reject an obviously-bad URL before it is even stored. It is not
// the security boundary - see dialer.go below for why - but it catches
// mistakes immediately with a clear error instead of a delivery failure an
// operator has to go dig for later.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("URL has no host")
	}
	// A literal IP can be checked immediately; a hostname cannot - it may
	// resolve differently by the time a delivery actually dials it (that is
	// exactly what the dialer-level check below exists for), so this only
	// catches the literal-IP case here rather than resolving DNS at
	// validation time.
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("refusing to deliver to %s: this address can never be a legitimate webhook receiver", ip)
	}
	return nil
}

// isBlockedIP reports whether ip must never be a webhook delivery target:
// the host talking to itself, or the link-local range every major cloud
// provider serves its instance-metadata credentials from (169.254.169.254 on
// AWS/GCP/Azure alike; the IPv6 metadata addresses are link-local too).
// Ordinary private addresses (10/8, 172.16/12, 192.168/16) are deliberately
// NOT blocked - see the package-level comment above.
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// dialerControl is installed as net.Dialer.Control, which Go calls after DNS
// resolution but before the connection is made, with the concrete numeric
// address actually being dialed - not the original hostname. This is what
// makes the defense real rather than cosmetic: ValidateWebhookURL only ever
// sees the URL string at creation time, so a hostname that resolves to an
// allowed address today and a blocked one tomorrow (DNS rebinding), or a
// webhook endpoint that 302s to a blocked address (Go's http.Client follows
// redirects through the same Transport, so every hop dials through here too),
// both still get caught at the moment it actually matters: the real connect.
func dialerControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Should not happen - Control receives a resolved numeric address -
		// but refuse rather than guess if it ever does.
		return fmt.Errorf("webhook dial: could not parse resolved address %q", address)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("webhook dial: refusing to connect to %s: this address can never be a legitimate webhook receiver", ip)
	}
	return nil
}

// newDeliveryTransport builds the http.Transport webhook deliveries go
// through, with dialerControl wired in. Split out from the *http.Client
// itself only so it is independently testable.
func newDeliveryTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Control: dialerControl}).DialContext
	return t
}
