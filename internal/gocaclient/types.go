package gocaclient

import (
	"time"

	"github.com/mevijays/goca/internal/pki"
)

// The wire types. These mirror internal/store's JSON rather than importing it,
// because internal/store links both SQL drivers - see the package doc.
// drift_test.go compares these against the real server types field by field,
// which matters more than usual for the request types: the server decodes with
// DisallowUnknownFields, so one stale json tag is a runtime 400 that only a
// user would discover.
//
// pki.Subject and pki.CertInfo are imported rather than copied. internal/pki
// is standalone (157 packages, no database), the client needs it anyway for
// local `csr new` and `inspect`, and reusing them keeps the largest and most
// tedious structs exact for free.

//
// ---------- certificate authorities ----------
//

type CA struct {
	ID             int64      `json:"id"`
	Name           string     `json:"name"`
	Slug           string     `json:"slug"`
	Subject        string     `json:"subject"`
	SerialHex      string     `json:"serial"`
	KeyType        string     `json:"key_type"`
	IsRoot         bool       `json:"is_root"`
	ParentID       *int64     `json:"parent_id,omitempty"`
	PathLen        int        `json:"path_len"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	Status         string     `json:"status"`
	CRLNumber      int64      `json:"crl_number"`
	Fingerprint    string     `json:"fingerprint_sha256"`
	IsDefault      bool       `json:"is_default"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	LastCRLAt      *time.Time `json:"last_crl_at,omitempty"`
	External       bool       `json:"external"`
	SubjectKeyID   string     `json:"subject_key_id,omitempty"`
	AuthorityKeyID string     `json:"authority_key_id,omitempty"`

	CertPEM string        `json:"cert_pem"`
	Info    *pki.CertInfo `json:"info,omitempty"`

	// Computed by the server. These cannot be derived here: they depend on
	// the encrypted signing key, which is never serialized. Before the server
	// sent them, a remote client had no way to tell a real authority from a
	// keyless trust anchor.
	HasKey   bool   `json:"has_key"`
	CanIssue bool   `json:"can_issue"`
	Kind     string `json:"kind"`
	Origin   string `json:"origin"`
	Expired  bool   `json:"expired"`
	DaysLeft int    `json:"days_left"`
}

// Pending reports whether this authority is waiting for an external signature.
func (c *CA) Pending() bool { return c.Status == "pending" }

type CreateCAInput struct {
	Name          string      `json:"name"`
	Subject       pki.Subject `json:"subject"`
	KeyType       string      `json:"key_type"`
	Days          int         `json:"days"`
	ParentRef     string      `json:"parent"`
	PathLen       int         `json:"path_len"`
	CRLDistPoints []string    `json:"crl_distribution_points"`
	OCSPServers   []string    `json:"ocsp_servers"`
	PermittedDNS  []string    `json:"permitted_dns_domains"`
	MakeDefault   bool        `json:"make_default"`
}

type SubordinateCSRInput struct {
	Name      string      `json:"name"`
	Subject   pki.Subject `json:"subject"`
	KeyType   string      `json:"key_type"`
	ParentRef string      `json:"parent"`
}

type ImportCAInput struct {
	Name        string `json:"name"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	ChainPEM    string `json:"chain_pem"`
	MakeDefault bool   `json:"make_default"`
}

type CompleteSubordinateInput struct {
	CARef       string `json:"ca"`
	CertPEM     string `json:"cert_pem"`
	ChainPEM    string `json:"chain_pem"`
	MakeDefault bool   `json:"make_default"`
}

// PendingCA is one entry of GET /cas/pending.
type PendingCA struct {
	CA     *CA    `json:"ca"`
	CSRPEM string `json:"csr_pem"`
}

//
// ---------- certificates ----------
//

type Certificate struct {
	ID          int64      `json:"id"`
	CAID        int64      `json:"ca_id"`
	CAName      string     `json:"ca_name,omitempty"`
	SerialHex   string     `json:"serial"`
	CommonName  string     `json:"common_name"`
	Subject     string     `json:"subject"`
	Profile     string     `json:"profile"`
	KeyType     string     `json:"key_type"`
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
	RenewedFrom *int64     `json:"renewed_from,omitempty"`

	CertPEM string        `json:"cert_pem"`
	Info    *pki.CertInfo `json:"info,omitempty"`
	// SANs is decoded server-side; the stored JSON blob is not serialized, so
	// this field is the only way a client sees them.
	SANs []string `json:"sans"`
}

// EffectiveStatus folds expiry into the stored status, matching
// store.Certificate.EffectiveStatus so both binaries render the same word.
func (c *Certificate) EffectiveStatus() string {
	if c.Status == "revoked" {
		return "revoked"
	}
	if time.Now().After(c.NotAfter) {
		return "expired"
	}
	return "active"
}

// DaysLeft returns whole days until expiry, negative once expired.
func (c *Certificate) DaysLeft() int { return int(time.Until(c.NotAfter).Hours() / 24) }

// OnHold reports a reversible revocation (RFC 5280 certificateHold).
func (c *Certificate) OnHold() bool { return c.Status == "revoked" && c.RevokeCode == 6 }

type IssueInput struct {
	CARef    string      `json:"ca"`
	Mode     string      `json:"mode"`
	Subject  pki.Subject `json:"subject"`
	SANs     []string    `json:"sans"`
	KeyType  string      `json:"key_type"`
	Profile  string      `json:"profile"`
	Days     int         `json:"days"`
	CSRPEM   string      `json:"csr_pem"`
	KeyPEM   string      `json:"key_pem"`
	StoreKey *bool       `json:"store_key"`
	Note     string      `json:"note"`
}

// IssueResult is what POST /certificates returns. PrivateKeyPEM is present
// only in this response, when goca generated the key.
type IssueResult struct {
	Certificate   *Certificate `json:"certificate"`
	PrivateKeyPEM string       `json:"private_key_pem,omitempty"`
	CSRPEM        string       `json:"csr_pem,omitempty"`
	ChainPEM      string       `json:"chain_pem,omitempty"`
}

type RenewInput struct {
	Days      int    `json:"days"`
	SameKey   bool   `json:"same_key"`
	CARef     string `json:"ca"`
	KeyType   string `json:"key_type"`
	RevokeOld bool   `json:"revoke_old"`
	StoreKey  *bool  `json:"store_key"`
	Note      string `json:"note"`
}

// CertFilter narrows a certificate search. These map to query parameters
// rather than a JSON body.
type CertFilter struct {
	Query       string
	CARef       string
	Status      string
	Profile     string
	RequestedBy string
	ExpiringIn  int
	Limit       int
	Offset      int
	SortBy      string
	SortDesc    bool
}

// CertHistoryResult is GET /certificates/{id}/history: the rotation chain a
// certificate belongs to, plus which entry is the one currently in force.
type CertHistoryResult struct {
	CurrentID int64         `json:"current_id"`
	History   []Certificate `json:"history"`
}

// CertPage is one page of search results.
type CertPage struct {
	Certificates []Certificate `json:"certificates"`
	Total        int           `json:"total"`
	Limit        int           `json:"limit"`
	Offset       int           `json:"offset"`
}

//
// ---------- users, tokens, audit ----------
//

type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Source      string     `json:"source"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
}

// IsAdmin reports whether the account holds the admin role. Note this is the
// *account's* role - a user-scoped token owned by an admin is capped to user,
// which Me reports separately in AuthInfo.Role.
func (u *User) IsAdmin() bool { return u != nil && u.Role == "admin" }

type APIToken struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	Username   string     `json:"username,omitempty"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Role       string     `json:"role"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

type AuditEntry struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	IP     string    `json:"ip"`
}

//
// ---------- authentication ----------
//

type LoginInput struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	TokenName string `json:"token_name"`
	Days      int    `json:"days"`
}

type LoginResult struct {
	Token         string     `json:"token"`
	TokenID       int64      `json:"token_id"`
	TokenName     string     `json:"token_name"`
	ExpiresAt     *time.Time `json:"expires_at"`
	Role          string     `json:"role"`
	User          *User      `json:"user"`
	ServerVersion string     `json:"server_version"`
}

// AuthInfo describes the credential a request authenticated with, as opposed
// to its owner. Role here is the *effective* role: an API token's own role
// caps it, so an admin acting through a user-scoped token is a user.
type AuthInfo struct {
	Method    string `json:"method"`
	TokenID   int64  `json:"token_id,omitempty"`
	TokenName string `json:"token_name,omitempty"`
	Role      string `json:"role"`
	// AccountRole is the role stored on the account itself. The embedded
	// User's Role is capped to the token's role by the server, so this is the
	// only way to tell a limited account from a limited credential.
	AccountRole string     `json:"account_role,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// Me is GET /me: the user, plus the credential that identified them.
type Me struct {
	User
	Auth AuthInfo `json:"auth"`
}

//
// ---------- secrets ----------
//

type Secret struct {
	ID             int64             `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Description    string            `json:"description,omitempty"`
	CertID         *int64            `json:"cert_id,omitempty"`
	CurrentVersion int               `json:"current_version"`
	RotationDays   int               `json:"rotation_days,omitempty"`
	Disabled       bool              `json:"disabled"`
	CreatedBy      string            `json:"created_by"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Labels         map[string]string `json:"labels"`
	RotationDue    bool              `json:"rotation_due"`
}

type CreateSecretInput struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Description  string            `json:"description"`
	Labels       map[string]string `json:"labels"`
	RotationDays int               `json:"rotation_days"`
	CertID       *int64            `json:"cert_id,omitempty"`
}

type SecretVersion struct {
	ID            int64     `json:"id"`
	SecretID      int64     `json:"secret_id"`
	Version       int       `json:"version"`
	PayloadSHA256 string    `json:"payload_sha256"`
	SizeBytes     int64     `json:"size_bytes"`
	ContentType   string    `json:"content_type,omitempty"`
	Destroyed     bool      `json:"destroyed"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

type SecretBinding struct {
	ID                int64      `json:"id"`
	SecretID          int64      `json:"secret_id"`
	SecretName        string     `json:"secret_name,omitempty"`
	K8sNamespace      string     `json:"k8s_namespace"`
	K8sServiceAccount string     `json:"k8s_service_account"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedBy         string     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
}

// Usable reports whether a binding is still in effect.
func (b *SecretBinding) Usable() bool {
	return b.ExpiresAt == nil || time.Now().Before(*b.ExpiresAt)
}

// SecretFile is one materialized file. Data is already base64-decoded.
type SecretFile struct {
	Name string
	Data []byte
}

//
// ---------- ACME ----------
//

type EABCred struct {
	ID             int64      `json:"id"`
	KeyID          string     `json:"key_id"`
	Name           string     `json:"name"`
	CAID           *int64     `json:"ca_id,omitempty"`
	Profile        string     `json:"profile"`
	Days           int        `json:"days"`
	AllowedDomains []string   `json:"allowed_domains"`
	MaxAccounts    int        `json:"max_accounts"`
	AccountCount   int        `json:"account_count"`
	Disabled       bool       `json:"disabled"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

// Usable reports whether this credential may still bootstrap new accounts,
// matching store.EABCred.Usable so both binaries agree on the state column.
func (e *EABCred) Usable() bool {
	if e.Disabled {
		return false
	}
	if e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt) {
		return false
	}
	if e.MaxAccounts > 0 && e.AccountCount >= e.MaxAccounts {
		return false
	}
	return true
}

type CreateEABInput struct {
	Name           string   `json:"name"`
	CARef          string   `json:"ca"`
	Profile        string   `json:"profile"`
	Days           int      `json:"days"`
	AllowedDomains []string `json:"allowed_domains"`
	MaxAccounts    int      `json:"max_accounts"`
	ExpiresInDays  int      `json:"expires_in_days"`
}

type CreateEABResult struct {
	Cred       *EABCred `json:"credential"`
	HMACKeyB64 string   `json:"hmac_key"`
}

type AcmeAccount struct {
	ID         int64      `json:"id"`
	EABID      int64      `json:"eab_id"`
	EABName    string     `json:"eab_name,omitempty"`
	Contact    []string   `json:"contact,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type AcmeOrder struct {
	ID            int64  `json:"id"`
	AccountID     int64  `json:"account_id"`
	Status        string `json:"status"`
	CertificateID *int64 `json:"certificate_id,omitempty"`
	Identifiers   []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

//
// ---------- stats ----------
//

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

//
// ---------- response envelopes ----------
//
// The API's list shapes are not uniform - some carry a count, some a total
// with paging, some neither. That is confined here so the exported methods can
// return something consistent.

type caListEnvelope struct {
	CAs   []CA `json:"cas"`
	Count int  `json:"count"`
}

type pendingCAEnvelope struct {
	Pending []PendingCA `json:"pending"`
	Count   int         `json:"count"`
}

type secretListEnvelope struct {
	Secrets []Secret `json:"secrets"`
	Count   int      `json:"count"`
}

type secretVersionsEnvelope struct {
	Versions []SecretVersion `json:"versions"`
}

type secretBindingsEnvelope struct {
	Bindings []SecretBinding `json:"bindings"`
}

type tokenListEnvelope struct {
	Tokens []APIToken `json:"tokens"`
}

type userListEnvelope struct {
	Users []User `json:"users"`
}

type auditEnvelope struct {
	Entries []AuditEntry `json:"entries"`
}

type eabListEnvelope struct {
	Credentials []EABCred `json:"credentials"`
}

type acmeAccountsEnvelope struct {
	Accounts []AcmeAccount `json:"accounts"`
}

type acmeOrdersEnvelope struct {
	Orders []AcmeOrder `json:"orders"`
}
