package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/mevijays/goca/internal/store"
)

// activeCred loads the EAB credential an account was bootstrapped with and
// refuses the request if that credential has since been disabled.
//
// Disabling is the incident-response lever for a leaked HMAC key: an account
// registered with it authenticates with its own key from then on, so unless
// orders also consult the credential, disabling it would stop only *future*
// registrations and leave whoever already used the leaked key issuing
// certificates indefinitely.
//
// Expiry is deliberately not checked here. A credential's expiry bounds how
// long its HMAC key can bootstrap new accounts - a planned rotation of the
// bootstrap secret, documented as leaving existing accounts working - not a
// revocation. Neither is max_accounts, which caps registrations: an account
// that was the one permitted registration must keep ordering.
func (s *Service) activeCred(ctx context.Context, account *store.AcmeAccount) (*store.EABCred, *Problem) {
	cred, err := s.st.GetEABCred(ctx, account.EABID)
	if err != nil {
		return nil, ServerInternal("%v", err)
	}
	if cred.Disabled {
		s.audit(ctx, fmt.Sprintf("acme:account:%d", account.ID), "acme.order.rejected", cred.Name,
			"external account binding credential is disabled")
		return nil, Unauthorized("the external account binding credential %q this account was registered with has been disabled",
			cred.Name)
	}
	return cred, nil
}

// validDNSIdentifier checks a lower-cased "dns" identifier is a syntactically
// valid hostname, optionally with a single leading "*." wildcard label.
//
// Authorizations here are granted without any domain-control check, so the
// identifier's syntax is the only thing standing between an account and a
// certificate for something that is not a hostname at all: an IP literal
// smuggled in as a DNS name, a bare "*", or "*.com".
func validDNSIdentifier(v string) error {
	if len(v) > 253 {
		return errors.New("is longer than 253 characters")
	}
	if net.ParseIP(v) != nil {
		return errors.New(`is an IP address; only "dns" identifiers are supported`)
	}
	name, wildcard := strings.CutPrefix(v, "*.")
	if strings.Contains(name, "*") {
		return errors.New(`may only use "*" as the entire leftmost label`)
	}
	labels := strings.Split(name, ".")
	if wildcard && len(labels) < 2 {
		return errors.New("is a wildcard over a single-label name, which would cover a whole top-level domain")
	}
	for _, l := range labels {
		if err := validLabel(l); err != nil {
			return err
		}
	}
	return nil
}

func validLabel(l string) error {
	if l == "" {
		return errors.New("has an empty label")
	}
	if len(l) > 63 {
		return fmt.Errorf("has a label longer than 63 characters (%q)", l)
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("has a label that starts or ends with a hyphen (%q)", l)
	}
	for _, r := range l {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("has a label with a character outside a-z, 0-9 and '-' (%q)", l)
		}
	}
	return nil
}

// nonDNSSummary describes the non-DNS names a CSR asked for, for a BadCSR
// problem a human can act on.
func nonDNSSummary(csr *x509.CertificateRequest) string {
	var parts []string
	for _, ip := range csr.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, e := range csr.EmailAddresses {
		parts = append(parts, "email:"+e)
	}
	for _, u := range csr.URIs {
		parts = append(parts, "URI:"+u.String())
	}
	return strings.Join(parts, ", ")
}
