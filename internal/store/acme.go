package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// This file backs goca's ACME (RFC 8555) support. It is deliberately
// EAB-only: an EAB credential is the entire trust decision an operator makes,
// so there is no HTTP-01/DNS-01 challenge machinery here - authorizations are
// created already "valid". See internal/acme for the protocol implementation
// and ACME-EAB.md for the operator-facing story.

// ACME order/account/authorization/challenge statuses (RFC 8555 §7.1.6).
const (
	AcmeStatusPending     = "pending"
	AcmeStatusProcessing  = "processing"
	AcmeStatusValid       = "valid"
	AcmeStatusInvalid     = "invalid"
	AcmeStatusReady       = "ready"
	AcmeStatusDeactivated = "deactivated"
	AcmeStatusRevoked     = "revoked"
	AcmeStatusExpired     = "expired"
)

//
// ---------- EAB credentials ----------
//

// EABCred is a pre-shared secret an ACME client uses once, at account
// registration, to bootstrap trust. Everything about how goca treats accounts
// created with it - which CA signs their certificates, what profile, what
// domains they may request - is configured here, not negotiated per request.
type EABCred struct {
	ID             int64      `json:"id"`
	KeyID          string     `json:"key_id"`
	HMACKeyEnc     string     `json:"-"`
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

// Usable reports whether this credential may still bootstrap new accounts.
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

const eabCols = `id, key_id, hmac_key_enc, name, ca_id, profile, days, allowed_domains,
 max_accounts, account_count, disabled, expires_at, created_by, created_at, last_used_at`

func scanEABCred(sc interface{ Scan(...any) error }) (*EABCred, error) {
	var e EABCred
	var caID sql.NullInt64
	var domainsJSON string
	var expires, lastUsed sql.NullTime
	err := sc.Scan(&e.ID, &e.KeyID, &e.HMACKeyEnc, &e.Name, &caID, &e.Profile, &e.Days,
		&domainsJSON, &e.MaxAccounts, &e.AccountCount, &e.Disabled, &expires,
		&e.CreatedBy, &e.CreatedAt, &lastUsed)
	if err != nil {
		return nil, err
	}
	if caID.Valid {
		v := caID.Int64
		e.CAID = &v
	}
	e.AllowedDomains = decodeStrings(domainsJSON)
	if expires.Valid {
		v := expires.Time
		e.ExpiresAt = &v
	}
	if lastUsed.Valid {
		v := lastUsed.Time
		e.LastUsedAt = &v
	}
	return &e, nil
}

// CreateEABCred stores a new credential and returns it with its assigned id.
func (s *Store) CreateEABCred(ctx context.Context, e *EABCred) (*EABCred, error) {
	var caID any
	if e.CAID != nil {
		caID = *e.CAID
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO acme_eab_creds
	 (key_id, hmac_key_enc, name, ca_id, profile, days, allowed_domains, max_accounts,
	  disabled, expires_at, created_by, created_at)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		e.KeyID, e.HMACKeyEnc, e.Name, caID, nz(e.Profile, "server"), e.Days,
		encodeStrings(e.AllowedDomains), e.MaxAccounts, e.Disabled, e.ExpiresAt,
		e.CreatedBy, e.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetEABCred(ctx, id)
}

// GetEABCred fetches one credential by id.
func (s *Store) GetEABCred(ctx context.Context, id int64) (*EABCred, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+eabCols+` FROM acme_eab_creds WHERE id = ?`, id)
	e, err := scanEABCred(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// GetEABCredByKeyID looks up a credential by its public keyID - what an ACME
// client presents in the externalAccountBinding of a new-account request.
func (s *Store) GetEABCredByKeyID(ctx context.Context, keyID string) (*EABCred, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+eabCols+` FROM acme_eab_creds WHERE key_id = ?`, keyID)
	e, err := scanEABCred(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// ListEABCreds returns every credential, newest first.
func (s *Store) ListEABCreds(ctx context.Context) ([]*EABCred, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+eabCols+` FROM acme_eab_creds ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EABCred
	for rows.Next() {
		e, err := scanEABCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetEABCredDisabled enables or disables a credential. Disabling it stops new
// accounts from being bootstrapped; accounts it already created keep working,
// since after registration they authenticate with their own key, not the EAB
// secret.
func (s *Store) SetEABCredDisabled(ctx context.Context, id int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE acme_eab_creds SET disabled = ? WHERE id = ?`, disabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteEABCred removes a credential permanently. The foreign key from
// acme_accounts has no ON DELETE action on purpose - a secret being rotated
// away should never silently erase which accounts it once bootstrapped - so
// this fails with a foreign-key error while any account still references it.
// Check ListAcmeAccountsByEAB first, or disable the credential instead.
func (s *Store) DeleteEABCred(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM acme_eab_creds WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchEABCredUse increments the account counter and last-used timestamp,
// called once a new account is successfully bootstrapped with it.
func (s *Store) TouchEABCredUse(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_eab_creds SET account_count = account_count + 1, last_used_at = ? WHERE id = ?`,
		time.Now().UTC(), id)
	return err
}

//
// ---------- ACME accounts ----------
//

// AcmeAccount is a registered ACME account: a public key the client proved
// possession of once via an EAB-signed request, and signs every subsequent
// request with from then on.
type AcmeAccount struct {
	ID            int64      `json:"id"`
	EABID         int64      `json:"eab_id"`
	JWKJSON       string     `json:"-"`
	JWKThumbprint string     `json:"-"`
	Contact       []string   `json:"contact,omitempty"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`

	// EABName is filled in by joined list queries for display; empty otherwise.
	EABName string `json:"eab_name,omitempty"`
}

const acmeAccountCols = `a.id, a.eab_id, a.jwk_json, a.jwk_thumbprint, a.contact_json,
 a.status, a.created_at, a.last_used_at, COALESCE(e.name,'')`

func scanAcmeAccount(sc interface{ Scan(...any) error }) (*AcmeAccount, error) {
	var a AcmeAccount
	var contactJSON string
	var lastUsed sql.NullTime
	err := sc.Scan(&a.ID, &a.EABID, &a.JWKJSON, &a.JWKThumbprint, &contactJSON,
		&a.Status, &a.CreatedAt, &lastUsed, &a.EABName)
	if err != nil {
		return nil, err
	}
	a.Contact = decodeStrings(contactJSON)
	if lastUsed.Valid {
		v := lastUsed.Time
		a.LastUsedAt = &v
	}
	return &a, nil
}

// CreateAcmeAccount registers a new account.
func (s *Store) CreateAcmeAccount(ctx context.Context, a *AcmeAccount) (*AcmeAccount, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO acme_accounts
	 (eab_id, jwk_json, jwk_thumbprint, contact_json, status, created_at)
	 VALUES (?,?,?,?,?,?) RETURNING id`,
		a.EABID, a.JWKJSON, a.JWKThumbprint, encodeStrings(a.Contact),
		nz(a.Status, AcmeStatusValid), a.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetAcmeAccount(ctx, id)
}

// GetAcmeAccount fetches one account by id.
func (s *Store) GetAcmeAccount(ctx context.Context, id int64) (*AcmeAccount, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+acmeAccountCols+` FROM acme_accounts a
		 LEFT JOIN acme_eab_creds e ON e.id = a.eab_id WHERE a.id = ?`, id)
	a, err := scanAcmeAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// GetAcmeAccountByThumbprint finds the account registered with a given public
// key, used to make new-account idempotent per RFC 8555 §7.3.1.
func (s *Store) GetAcmeAccountByThumbprint(ctx context.Context, thumbprint string) (*AcmeAccount, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+acmeAccountCols+` FROM acme_accounts a
		 LEFT JOIN acme_eab_creds e ON e.id = a.eab_id WHERE a.jwk_thumbprint = ?`, thumbprint)
	a, err := scanAcmeAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListAcmeAccounts returns every registered account, newest first.
func (s *Store) ListAcmeAccounts(ctx context.Context) ([]*AcmeAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeAccountCols+` FROM acme_accounts a
		 LEFT JOIN acme_eab_creds e ON e.id = a.eab_id ORDER BY a.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AcmeAccount
	for rows.Next() {
		a, err := scanAcmeAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAcmeAccountsByEAB lists every account bootstrapped from one credential,
// used to warn before deleting a credential still in use.
func (s *Store) ListAcmeAccountsByEAB(ctx context.Context, eabID int64) ([]*AcmeAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeAccountCols+` FROM acme_accounts a
		 LEFT JOIN acme_eab_creds e ON e.id = a.eab_id WHERE a.eab_id = ? ORDER BY a.id DESC`, eabID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AcmeAccount
	for rows.Next() {
		a, err := scanAcmeAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAcmeAccountStatus updates account status (e.g. deactivation).
func (s *Store) SetAcmeAccountStatus(ctx context.Context, id int64, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE acme_accounts SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAcmeAccountContact updates an account's contact list.
func (s *Store) SetAcmeAccountContact(ctx context.Context, id int64, contact []string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET contact_json = ? WHERE id = ?`, encodeStrings(contact), id)
	return err
}

// TouchAcmeAccountUsed stamps last_used_at, called on every authenticated
// ACME request from this account.
func (s *Store) TouchAcmeAccountUsed(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_accounts SET last_used_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

//
// ---------- ACME orders ----------
//

// AcmeIdentifier is one name an order requests a certificate for.
type AcmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AcmeOrder tracks one certificate request through the ACME state machine.
type AcmeOrder struct {
	ID            int64            `json:"id"`
	AccountID     int64            `json:"account_id"`
	Status        string           `json:"status"`
	Identifiers   []AcmeIdentifier `json:"identifiers"`
	CertificateID *int64           `json:"certificate_id,omitempty"`
	Error         string           `json:"error,omitempty"`
	ExpiresAt     time.Time        `json:"expires_at"`
	CreatedAt     time.Time        `json:"created_at"`
}

const acmeOrderCols = `id, account_id, status, identifiers_json, certificate_id,
 error_json, expires_at, created_at`

func scanAcmeOrder(sc interface{ Scan(...any) error }) (*AcmeOrder, error) {
	var o AcmeOrder
	var identifiersJSON string
	var certID sql.NullInt64
	err := sc.Scan(&o.ID, &o.AccountID, &o.Status, &identifiersJSON, &certID,
		&o.Error, &o.ExpiresAt, &o.CreatedAt)
	if err != nil {
		return nil, err
	}
	o.Identifiers = decodeIdentifiers(identifiersJSON)
	if certID.Valid {
		v := certID.Int64
		o.CertificateID = &v
	}
	return &o, nil
}

// CreateAcmeOrder stores a new order.
func (s *Store) CreateAcmeOrder(ctx context.Context, o *AcmeOrder) (*AcmeOrder, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO acme_orders
	 (account_id, status, identifiers_json, expires_at, created_at)
	 VALUES (?,?,?,?,?) RETURNING id`,
		o.AccountID, nz(o.Status, AcmeStatusPending), encodeIdentifiers(o.Identifiers),
		o.ExpiresAt.UTC(), o.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetAcmeOrder(ctx, id)
}

// GetAcmeOrder fetches one order by id.
func (s *Store) GetAcmeOrder(ctx context.Context, id int64) (*AcmeOrder, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+acmeOrderCols+` FROM acme_orders WHERE id = ?`, id)
	o, err := scanAcmeOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return o, err
}

// ListAcmeOrdersByAccount lists an account's orders, newest first.
func (s *Store) ListAcmeOrdersByAccount(ctx context.Context, accountID int64) ([]*AcmeOrder, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeOrderCols+` FROM acme_orders WHERE account_id = ? ORDER BY id DESC`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AcmeOrder
	for rows.Next() {
		o, err := scanAcmeOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetAcmeOrderStatus transitions an order's status.
func (s *Store) SetAcmeOrderStatus(ctx context.Context, id int64, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE acme_orders SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAcmeOrderError marks an order invalid with an RFC 7807-shaped problem
// document (already JSON-encoded by the caller).
func (s *Store) SetAcmeOrderError(ctx context.Context, id int64, problemJSON string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = ?, error_json = ? WHERE id = ?`,
		AcmeStatusInvalid, problemJSON, id)
	return err
}

// SetAcmeOrderCertificate links an order to the certificate finalize produced
// and marks it valid.
func (s *Store) SetAcmeOrderCertificate(ctx context.Context, id, certID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = ?, certificate_id = ? WHERE id = ?`,
		AcmeStatusValid, certID, id)
	return err
}

//
// ---------- ACME authorizations & challenges ----------
//

// AcmeAuthorization is one identifier's authorization within an order. In
// goca's EAB-only model these are created already valid.
type AcmeAuthorization struct {
	ID              int64     `json:"id"`
	OrderID         int64     `json:"order_id"`
	IdentifierType  string    `json:"identifier_type"`
	IdentifierValue string    `json:"identifier_value"`
	Wildcard        bool      `json:"wildcard"`
	Status          string    `json:"status"`
	ExpiresAt       time.Time `json:"expires_at"`
	CreatedAt       time.Time `json:"created_at"`
}

const acmeAuthzCols = `id, order_id, identifier_type, identifier_value, wildcard,
 status, expires_at, created_at`

func scanAcmeAuthz(sc interface{ Scan(...any) error }) (*AcmeAuthorization, error) {
	var a AcmeAuthorization
	err := sc.Scan(&a.ID, &a.OrderID, &a.IdentifierType, &a.IdentifierValue, &a.Wildcard,
		&a.Status, &a.ExpiresAt, &a.CreatedAt)
	return &a, err
}

// CreateAcmeAuthorization stores an authorization, pre-validated.
func (s *Store) CreateAcmeAuthorization(ctx context.Context, a *AcmeAuthorization) (*AcmeAuthorization, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO acme_authorizations
	 (order_id, identifier_type, identifier_value, wildcard, status, expires_at, created_at)
	 VALUES (?,?,?,?,?,?,?) RETURNING id`,
		a.OrderID, nz(a.IdentifierType, "dns"), a.IdentifierValue, a.Wildcard,
		nz(a.Status, AcmeStatusValid), a.ExpiresAt.UTC(), a.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetAcmeAuthorization(ctx, id)
}

// GetAcmeAuthorization fetches one authorization by id.
func (s *Store) GetAcmeAuthorization(ctx context.Context, id int64) (*AcmeAuthorization, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+acmeAuthzCols+` FROM acme_authorizations WHERE id = ?`, id)
	a, err := scanAcmeAuthz(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListAcmeAuthorizationsByOrder lists an order's authorizations, in creation order.
func (s *Store) ListAcmeAuthorizationsByOrder(ctx context.Context, orderID int64) ([]*AcmeAuthorization, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeAuthzCols+` FROM acme_authorizations WHERE order_id = ? ORDER BY id`, orderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AcmeAuthorization
	for rows.Next() {
		a, err := scanAcmeAuthz(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AcmeChallenge is the (pre-satisfied) challenge object exposed for an
// authorization, kept for protocol-object completeness - clients that walk
// authz -> challenge -> POST-to-trigger still get a well-formed response.
type AcmeChallenge struct {
	ID              int64      `json:"id"`
	AuthorizationID int64      `json:"authorization_id"`
	Type            string     `json:"type"`
	Token           string     `json:"token"`
	Status          string     `json:"status"`
	ValidatedAt     *time.Time `json:"validated_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

const acmeChallengeCols = `id, authorization_id, type, token, status, validated_at, created_at`

func scanAcmeChallenge(sc interface{ Scan(...any) error }) (*AcmeChallenge, error) {
	var c AcmeChallenge
	var validated sql.NullTime
	err := sc.Scan(&c.ID, &c.AuthorizationID, &c.Type, &c.Token, &c.Status, &validated, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	if validated.Valid {
		v := validated.Time
		c.ValidatedAt = &v
	}
	return &c, nil
}

// CreateAcmeChallenge stores a challenge, pre-satisfied.
func (s *Store) CreateAcmeChallenge(ctx context.Context, c *AcmeChallenge) (*AcmeChallenge, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO acme_challenges
	 (authorization_id, type, token, status, validated_at, created_at)
	 VALUES (?,?,?,?,?,?) RETURNING id`,
		c.AuthorizationID, nz(c.Type, "http-01"), c.Token, nz(c.Status, AcmeStatusValid),
		c.ValidatedAt, c.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetAcmeChallenge(ctx, id)
}

// GetAcmeChallenge fetches one challenge by id.
func (s *Store) GetAcmeChallenge(ctx context.Context, id int64) (*AcmeChallenge, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+acmeChallengeCols+` FROM acme_challenges WHERE id = ?`, id)
	c, err := scanAcmeChallenge(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ListAcmeChallengesByAuthorization lists an authorization's challenges.
func (s *Store) ListAcmeChallengesByAuthorization(ctx context.Context, authzID int64) ([]*AcmeChallenge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+acmeChallengeCols+` FROM acme_challenges WHERE authorization_id = ? ORDER BY id`, authzID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AcmeChallenge
	for rows.Next() {
		c, err := scanAcmeChallenge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

//
// ---------- small JSON codecs ----------
//

func encodeStrings(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

func encodeIdentifiers(v []AcmeIdentifier) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeIdentifiers(s string) []AcmeIdentifier {
	if s == "" {
		return nil
	}
	var out []AcmeIdentifier
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
