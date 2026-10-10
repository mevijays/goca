package acme

import (
	"fmt"
	"path"
	"strings"
)

// domainAllowed reports whether identifier is permitted by an EAB
// credential's allowed-domain patterns. No patterns means unrestricted -
// every EAB credential the operator can bind to a specific CA and profile
// already, so a domain allowlist is an additional, optional constraint.
//
// Patterns use shell-glob syntax, matched case-insensitively. Unlike a TLS
// wildcard certificate's single-label semantics, "*" here matches across dot
// boundaries: "*.svc.cluster-a.internal" permits "foo.svc.cluster-a.internal"
// and also "foo.bar.svc.cluster-a.internal", since this is an access-control
// scope ("what zone does this credential control"), not a certificate SAN.
func domainAllowed(patterns []string, identifier string) bool {
	if len(patterns) == 0 {
		return true
	}
	name := strings.ToLower(strings.TrimSuffix(identifier, "."))
	for _, p := range patterns {
		pat := strings.ToLower(strings.TrimSpace(p))
		if pat == "" {
			continue
		}
		if ok, err := path.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

// normalizeDomainPatterns trims, lower-cases and de-duplicates allowed-domain
// patterns, and rejects ones that are malformed or match everything.
//
// A malformed glob (an unclosed "[") used to be stored as-is and then simply
// never match, which looks exactly like a working, restrictive credential
// until the first order fails. A pattern made only of wildcards ("*", "*.*")
// is the opposite trap: it reads like a restriction but permits any name.
func normalizeDomainPatterns(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if p == "" || seen[p] {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("allowed domain %q is not a valid pattern: %w", raw, err)
		}
		if strings.Trim(p, "*?.") == "" {
			return nil, fmt.Errorf("allowed domain %q matches every hostname; "+
				"to allow any domain, say so explicitly instead", raw)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// describeDomains renders a credential's scope for audit entries and lists.
func describeDomains(domains []string) string {
	if len(domains) == 0 {
		return "ANY (unrestricted)"
	}
	return strings.Join(domains, ",")
}
