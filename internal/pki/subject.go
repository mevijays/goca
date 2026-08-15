package pki

import (
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
)

// Subject is a distinguished name in a form that is easy to bind from web
// forms, JSON APIs and CLI flags.
type Subject struct {
	CommonName         string `json:"common_name" yaml:"common_name"`
	Organization       string `json:"organization,omitempty" yaml:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" yaml:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty" yaml:"country,omitempty"`
	Province           string `json:"province,omitempty" yaml:"province,omitempty"`
	Locality           string `json:"locality,omitempty" yaml:"locality,omitempty"`
	StreetAddress      string `json:"street_address,omitempty" yaml:"street_address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty" yaml:"postal_code,omitempty"`
	EmailAddress       string `json:"email,omitempty" yaml:"email,omitempty"`
}

// PKIX converts to the standard library representation.
func (s Subject) PKIX() pkix.Name {
	n := pkix.Name{CommonName: strings.TrimSpace(s.CommonName)}
	add := func(dst *[]string, v string) {
		if v = strings.TrimSpace(v); v != "" {
			*dst = append(*dst, v)
		}
	}
	add(&n.Organization, s.Organization)
	add(&n.OrganizationalUnit, s.OrganizationalUnit)
	add(&n.Country, strings.ToUpper(s.Country))
	add(&n.Province, s.Province)
	add(&n.Locality, s.Locality)
	add(&n.StreetAddress, s.StreetAddress)
	add(&n.PostalCode, s.PostalCode)
	return n
}

// SubjectFromPKIX converts back from the standard library representation.
func SubjectFromPKIX(n pkix.Name) Subject {
	first := func(v []string) string {
		if len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return Subject{
		CommonName:         n.CommonName,
		Organization:       first(n.Organization),
		OrganizationalUnit: first(n.OrganizationalUnit),
		Country:            first(n.Country),
		Province:           first(n.Province),
		Locality:           first(n.Locality),
		StreetAddress:      first(n.StreetAddress),
		PostalCode:         first(n.PostalCode),
	}
}

// String renders an OpenSSL-style one-line DN.
func (s Subject) String() string { return DNString(s.PKIX()) }

// JSON serialises the subject for storage.
func (s Subject) JSON() string {
	b, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Validate checks the minimum requirements for a usable subject.
func (s Subject) Validate() error {
	if strings.TrimSpace(s.CommonName) == "" {
		return fmt.Errorf("common name (CN) is required")
	}
	if c := strings.TrimSpace(s.Country); c != "" && len(c) != 2 {
		return fmt.Errorf("country must be a 2-letter code, got %q", c)
	}
	if e := strings.TrimSpace(s.EmailAddress); e != "" {
		if _, err := mail.ParseAddress(e); err != nil {
			return fmt.Errorf("invalid email address %q", e)
		}
	}
	return nil
}

// DNString renders a pkix.Name as "CN=x, O=y, C=z".
func DNString(n pkix.Name) string {
	var parts []string
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	for _, v := range n.OrganizationalUnit {
		parts = append(parts, "OU="+v)
	}
	for _, v := range n.Organization {
		parts = append(parts, "O="+v)
	}
	for _, v := range n.Locality {
		parts = append(parts, "L="+v)
	}
	for _, v := range n.Province {
		parts = append(parts, "ST="+v)
	}
	for _, v := range n.StreetAddress {
		parts = append(parts, "STREET="+v)
	}
	for _, v := range n.PostalCode {
		parts = append(parts, "postalCode="+v)
	}
	for _, v := range n.Country {
		parts = append(parts, "C="+v)
	}
	if len(parts) == 0 {
		return "(empty subject)"
	}
	return strings.Join(parts, ", ")
}

// SANSet holds subject alternative names split by type.
type SANSet struct {
	DNS    []string
	IPs    []net.IP
	Emails []string
	URIs   []*url.URL
}

// Empty reports whether no SANs are present.
func (s SANSet) Empty() bool {
	return len(s.DNS) == 0 && len(s.IPs) == 0 && len(s.Emails) == 0 && len(s.URIs) == 0
}

// Strings renders the set back to the prefixed textual form used for storage
// and display ("DNS:host", "IP:1.2.3.4", ...).
func (s SANSet) Strings() []string {
	var out []string
	for _, d := range s.DNS {
		out = append(out, "DNS:"+d)
	}
	for _, ip := range s.IPs {
		out = append(out, "IP:"+ip.String())
	}
	for _, e := range s.Emails {
		out = append(out, "EMAIL:"+e)
	}
	for _, u := range s.URIs {
		out = append(out, "URI:"+u.String())
	}
	return out
}

// ParseSANs turns free-form user input into a typed SAN set. Entries may be
// prefixed (DNS:, IP:, EMAIL:, URI:) or bare, in which case the type is
// inferred. Input may be comma, space or newline separated.
func ParseSANs(entries []string) (SANSet, error) {
	var set SANSet
	for _, raw := range splitList(entries) {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		lower := strings.ToLower(item)
		switch {
		case strings.HasPrefix(lower, "dns:"):
			set.DNS = append(set.DNS, strings.TrimSpace(item[4:]))
		case strings.HasPrefix(lower, "ip:"):
			v := strings.TrimSpace(item[3:])
			ip := net.ParseIP(v)
			if ip == nil {
				return set, fmt.Errorf("invalid IP SAN %q", v)
			}
			set.IPs = append(set.IPs, ip)
		case strings.HasPrefix(lower, "email:"):
			set.Emails = append(set.Emails, strings.TrimSpace(item[6:]))
		case strings.HasPrefix(lower, "uri:"):
			u, err := url.Parse(strings.TrimSpace(item[4:]))
			if err != nil {
				return set, fmt.Errorf("invalid URI SAN %q: %w", item, err)
			}
			set.URIs = append(set.URIs, u)
		case net.ParseIP(item) != nil:
			set.IPs = append(set.IPs, net.ParseIP(item))
		case strings.Contains(item, "@"):
			set.Emails = append(set.Emails, item)
		case strings.Contains(item, "://"):
			u, err := url.Parse(item)
			if err != nil {
				return set, fmt.Errorf("invalid URI SAN %q: %w", item, err)
			}
			set.URIs = append(set.URIs, u)
		default:
			set.DNS = append(set.DNS, item)
		}
	}
	return set, nil
}

// splitList flattens comma/space/newline separated values.
func splitList(in []string) []string {
	var out []string
	for _, s := range in {
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
		}) {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// SANsFromCert reads the SAN extension values off a parsed certificate.
func sanStringsFrom(dns []string, ips []net.IP, emails []string, uris []*url.URL) []string {
	return SANSet{DNS: dns, IPs: ips, Emails: emails, URIs: uris}.Strings()
}
