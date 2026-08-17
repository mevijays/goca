// Package acme implements an RFC 8555 (ACME) server on top of goca's existing
// certificate service, restricted to External Account Binding (EAB) as the
// sole trust mechanism: there is no HTTP-01 or DNS-01 challenge validation.
// An EAB credential *is* the authorization decision an operator makes -
// everything else (which CA signs, which profile, which domains are in
// scope) is configured on the credential once, up front. See docs/acme-eab.md for
// the full operator-facing story and why this fits a private, internal CA
// better than public-style domain validation.
package acme

import "encoding/json"

// Directory is the RFC 8555 §7.1.1 directory object. goca advertises only the
// endpoints it implements - newAuthz and keyChange are legal to omit.
type Directory struct {
	NewNonce   string         `json:"newNonce"`
	NewAccount string         `json:"newAccount"`
	NewOrder   string         `json:"newOrder"`
	RevokeCert string         `json:"revokeCert"`
	Meta       *DirectoryMeta `json:"meta,omitempty"`
}

// DirectoryMeta carries directory-wide metadata (§7.1.1).
type DirectoryMeta struct {
	// ExternalAccountRequired is always true: goca has no other way to trust
	// a new account.
	ExternalAccountRequired bool   `json:"externalAccountRequired"`
	Website                 string `json:"website,omitempty"`
}

// Identifier is one name an order or authorization concerns (§9.7.7). goca
// supports only the "dns" type.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AccountObject is the account resource returned to clients (§7.1.2).
type AccountObject struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`
}

// OrderObject is the order resource (§7.1.3).
type OrderObject struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

// AuthorizationObject is the authorization resource (§7.1.4). goca creates
// these already "valid" - there is nothing for the client to satisfy.
type AuthorizationObject struct {
	Identifier Identifier        `json:"identifier"`
	Status     string            `json:"status"`
	Expires    string            `json:"expires,omitempty"`
	Challenges []ChallengeObject `json:"challenges"`
	Wildcard   bool              `json:"wildcard,omitempty"`
}

// ChallengeObject is the challenge resource (§8). Exposed for protocol
// completeness only: it is created already valid, since EAB is the entire
// trust decision, and triggering it is a harmless idempotent no-op.
type ChallengeObject struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Status    string `json:"status"`
	Validated string `json:"validated,omitempty"`
	Token     string `json:"token"`
}

//
// ---------- inbound request payloads ----------
//

// NewAccountRequest is the payload of POST /new-account (§7.3).
type NewAccountRequest struct {
	Contact                []string        `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting     bool            `json:"onlyReturnExisting,omitempty"`
	ExternalAccountBinding json.RawMessage `json:"externalAccountBinding,omitempty"`
}

// UpdateAccountRequest is the payload of a POST to an account URL (§7.3.2,
// §7.3.6). Setting Status to "deactivated" deactivates the account; goca does
// not implement key rotation (§7.3.5) or arbitrary status values.
type UpdateAccountRequest struct {
	Contact []string `json:"contact,omitempty"`
	Status  string   `json:"status,omitempty"`
}

// NewOrderRequest is the payload of POST /new-order (§7.4). NotBefore/NotAfter
// are accepted and ignored: goca does not support client-pinned validity
// windows, only per-EAB-credential defaults.
type NewOrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// FinalizeRequest is the payload of POST /order/{id}/finalize (§7.4). CSR is
// base64url-encoded DER, per the spec - not PEM.
type FinalizeRequest struct {
	CSR string `json:"csr"`
}

// RevokeCertRequest is the payload of POST /revoke-cert (§7.6). Certificate is
// base64url-encoded DER; Reason is an RFC 5280 CRLReason code.
type RevokeCertRequest struct {
	Certificate string `json:"certificate"`
	Reason      *int   `json:"reason,omitempty"`
}
