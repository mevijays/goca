package acme

import (
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
