package store

import (
	"encoding/json"
	"strings"
	"time"
)

// Status values used across CAs and certificates.
const (
	StatusActive   = "active"
	StatusRevoked  = "revoked"
	StatusExpired  = "expired"
	StatusDisabled = "disabled"
)

// Role values.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Identity sources.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
)

// CA statuses beyond the shared ones.
const (
	// StatusPending marks a subordinate CA whose CSR has been generated but
	// whose signed certificate has not come back from the external authority.
	StatusPending = "pending"
)

// CA is a certificate authority managed by this server. It may have been
// created here, or imported from an external authority such as pfSense.
type CA struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Subject     string     `json:"subject"`
	SubjectJSON string     `json:"-"`
	SerialHex   string     `json:"serial"`
	KeyType     string     `json:"key_type"`
	CertPEM     string     `json:"-"`
	KeyEnc      string     `json:"-"`
	CSRPEM      string     `json:"-"`
	IsRoot      bool       `json:"is_root"`
	ParentID    *int64     `json:"parent_id,omitempty"`
	PathLen     int        `json:"path_len"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Status      string     `json:"status"`
	CRLNumber   int64      `json:"crl_number"`
	Fingerprint string     `json:"fingerprint_sha256"`
	IsDefault   bool       `json:"is_default"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastCRLAt   *time.Time `json:"last_crl_at,omitempty"`

	// External is true when the certificate was issued outside goca.
	External bool `json:"external"`
	// SubjectKeyID and AuthorityKeyID link an imported chain together.
	SubjectKeyID   string `json:"subject_key_id,omitempty"`
	AuthorityKeyID string `json:"authority_key_id,omitempty"`
}

// Expired reports whether the CA certificate is past its validity window.
func (c *CA) Expired() bool { return time.Now().After(c.NotAfter) }

// DaysLeft returns whole days until expiry (negative when expired).
func (c *CA) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

// HasKey reports whether goca holds this CA's private key. A trust anchor
// imported for chain building has none, and cannot issue.
func (c *CA) HasKey() bool { return c.KeyEnc != "" }

// CanIssue reports whether this CA is usable for signing right now.
func (c *CA) CanIssue() bool {
	return c.HasKey() && c.Status == StatusActive && !c.Expired() && c.CertPEM != ""
}

// Pending reports whether the CA is waiting for an externally signed
// certificate to be imported.
func (c *CA) Pending() bool { return c.Status == StatusPending }

// Kind renders the authority's role for lists and detail pages.
func (c *CA) Kind() string {
	switch {
	case c.Pending():
		return "pending signature"
	case !c.HasKey():
		return "trust anchor"
	case c.IsRoot:
		return "root"
	default:
		return "intermediate"
	}
}

// Origin says where the certificate came from.
func (c *CA) Origin() string {
	if c.External {
		return "imported"
	}
	return "goca"
}

// Certificate is an end-entity certificate issued by one of the CAs.
type Certificate struct {
	ID          int64      `json:"id"`
	CAID        int64      `json:"ca_id"`
	CAName      string     `json:"ca_name,omitempty"`
	SerialHex   string     `json:"serial"`
	CommonName  string     `json:"common_name"`
	Subject     string     `json:"subject"`
	SANsJSON    string     `json:"-"`
	Profile     string     `json:"profile"`
	KeyType     string     `json:"key_type"`
	CertPEM     string     `json:"-"`
	KeyEnc      string     `json:"-"`
	CSRPEM      string     `json:"-"`
	HasKey      bool       `json:"has_key"`
	Fingerprint string     `json:"fingerprint_sha256"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Status      string     `json:"status"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokeCode  int        `json:"revocation_reason,omitempty"`
	RequestedBy string     `json:"requested_by"`
	Note        string     `json:"note,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	// RenewedFrom points at the certificate this one replaced, if any.
	RenewedFrom *int64 `json:"renewed_from,omitempty"`
}

// OnHold reports whether the certificate is revoked reversibly.
func (c *Certificate) OnHold() bool {
	return c.Status == StatusRevoked && c.RevokeCode == 6 // RFC 5280 certificateHold
}

// SANs decodes the stored subject alternative names.
func (c *Certificate) SANs() []string {
	if strings.TrimSpace(c.SANsJSON) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(c.SANsJSON), &out); err != nil {
		return nil
	}
	return out
}

// SANsDisplay renders SANs as a comma separated string for lists.
func (c *Certificate) SANsDisplay() string { return strings.Join(c.SANs(), ", ") }

// EffectiveStatus folds expiry into the stored status.
func (c *Certificate) EffectiveStatus() string {
	if c.Status == StatusRevoked {
		return StatusRevoked
	}
	if time.Now().After(c.NotAfter) {
		return StatusExpired
	}
	return StatusActive
}

// DaysLeft returns whole days until expiry (negative when expired).
func (c *Certificate) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

// EncodeSANs serialises a SAN list for storage.
func EncodeSANs(sans []string) string {
	if len(sans) == 0 {
		return "[]"
	}
	b, err := json.Marshal(sans)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// User is a portal identity, either local or mirrored from LDAP.
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Source      string     `json:"source"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	PassHash    string     `json:"-"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
}

// IsAdmin reports whether the user holds the admin role.
func (u *User) IsAdmin() bool { return u != nil && u.Role == RoleAdmin }

// Session is a browser login session.
type Session struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	IP        string
	UserAgent string
}

// APIToken is a bearer credential for the REST API.
type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	TokenHash  string     `json:"-"`
	Role       string     `json:"role"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

// AuditEntry records a state-changing action.
type AuditEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

// CertFilter narrows a certificate search.
type CertFilter struct {
	Query       string // matches CN, subject, serial, SANs, requester
	CAID        int64
	Status      string // active|revoked|expired|"" for all
	Profile     string
	RequestedBy string
	ExpiringIn  int // days; 0 disables
	Limit       int
	Offset      int
	SortBy      string // created_at|not_after|common_name
	SortDesc    bool
}

// Stats summarises the database for the dashboard.
type Stats struct {
	CAs             int `json:"cas"`
	Certificates    int `json:"certificates"`
	Active          int `json:"active"`
	Revoked         int `json:"revoked"`
	Expired         int `json:"expired"`
	ExpiringSoon    int `json:"expiring_soon"`
	Users           int `json:"users"`
	IssuedLast30Day int `json:"issued_last_30_days"`
}
