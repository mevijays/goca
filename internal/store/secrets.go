package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// This file backs goca's secret manager: named, versioned secrets sealed
// with the hybrid ML-KEM-768 + X25519 envelope in internal/pqcrypt, and
// exposed to Kubernetes workloads through the Secrets Store CSI Driver
// provider. See internal/vault for the service layer that calls these
// queries, and docs/secrets.md for the operator-facing story.

//
// ---------- secrets ----------
//

const secretCols = `id, name, type, description, labels_json, cert_id, current_version,
 rotation_days, disabled, created_by, created_at, updated_at`

func scanSecret(sc interface{ Scan(...any) error }) (*Secret, error) {
	var s Secret
	var certID sql.NullInt64
	err := sc.Scan(&s.ID, &s.Name, &s.Type, &s.Description, &s.LabelsJSON, &certID,
		&s.CurrentVersion, &s.RotationDays, &s.Disabled, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if certID.Valid {
		v := certID.Int64
		s.CertID = &v
	}
	return &s, nil
}

// CreateSecret stores a new secret's metadata. It has no version yet - call
// CreateSecretVersion next to give it a payload. Name must be unique; the
// database's UNIQUE constraint surfaces a duplicate as a raw driver error.
func (s *Store) CreateSecret(ctx context.Context, sec *Secret) (*Secret, error) {
	if sec.CreatedAt.IsZero() {
		sec.CreatedAt = time.Now().UTC()
	}
	if sec.UpdatedAt.IsZero() {
		sec.UpdatedAt = sec.CreatedAt
	}
	var certID any
	if sec.CertID != nil {
		certID = *sec.CertID
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO secrets
	 (name, type, description, labels_json, cert_id, current_version, rotation_days,
	  disabled, created_by, created_at, updated_at)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		sec.Name, nz(sec.Type, SecretTypeKV), sec.Description, nz(sec.LabelsJSON, "{}"), certID,
		sec.CurrentVersion, sec.RotationDays, sec.Disabled, sec.CreatedBy,
		sec.CreatedAt.UTC(), sec.UpdatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetSecret(ctx, id)
}

// GetSecret fetches one secret by id.
func (s *Store) GetSecret(ctx context.Context, id int64) (*Secret, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+secretCols+` FROM secrets WHERE id = ?`, id)
	sec, err := scanSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sec, err
}

// GetSecretByName fetches one secret by its unique path-like name.
func (s *Store) GetSecretByName(ctx context.Context, name string) (*Secret, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+secretCols+` FROM secrets WHERE name = ?`, name)
	sec, err := scanSecret(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return sec, err
}

// ListSecrets returns every secret, newest first. typ narrows to one secret
// type (kv|file|certificate); empty returns all types.
func (s *Store) ListSecrets(ctx context.Context, typ string) ([]*Secret, error) {
	q := `SELECT ` + secretCols + ` FROM secrets`
	args := []any{}
	if typ != "" {
		q += ` WHERE type = ?`
		args = append(args, typ)
	}
	q += ` ORDER BY name ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Secret
	for rows.Next() {
		sec, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sec)
	}
	return out, rows.Err()
}

// UpdateSecretMeta updates a secret's description, labels and rotation
// policy. It never touches versions.
func (s *Store) UpdateSecretMeta(ctx context.Context, id int64, description, labelsJSON string, rotationDays int) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE secrets SET description = ?, labels_json = ?, rotation_days = ?, updated_at = ? WHERE id = ?`,
		description, nz(labelsJSON, "{}"), rotationDays, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetSecretDisabled enables or disables a secret. A disabled secret is
// refused by both the CLI/API read path and the CSI provider, without
// destroying any version.
func (s *Store) SetSecretDisabled(ctx context.Context, id int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE secrets SET disabled = ? WHERE id = ?`, disabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSecret removes a secret, its versions and its bindings permanently
// (ON DELETE CASCADE). There is no soft-delete at this level; callers that
// want an audit trail of the deletion should record it themselves before
// calling this, since the row will be gone afterward.
func (s *Store) DeleteSecret(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

//
// ---------- secret versions ----------
//

const secretVersionCols = `id, secret_id, version, payload_enc, payload_sha256, size_bytes,
 content_type, destroyed, created_by, created_at`

func scanSecretVersion(sc interface{ Scan(...any) error }) (*SecretVersion, error) {
	var v SecretVersion
	err := sc.Scan(&v.ID, &v.SecretID, &v.Version, &v.PayloadEnc, &v.PayloadSHA256, &v.SizeBytes,
		&v.ContentType, &v.Destroyed, &v.CreatedBy, &v.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// SealedVersion is what a SealFunc produces: the already-sealed payload
// (a pqcrypt.Seal() envelope) plus the bookkeeping columns that describe it.
type SealedVersion struct {
	PayloadEnc    string
	PayloadSHA256 string
	SizeBytes     int64
}

// SealFunc seals a plaintext payload for one exact (secretID, version) pair.
// It exists so CreateSecretVersion can hand the caller the version number it
// reserved *before* the caller encrypts - see CreateSecretVersion's comment
// for why that ordering matters.
type SealFunc func(secretID int64, version int) (SealedVersion, error)

// CreateSecretVersion reserves the next version number for a secret, calls
// seal with that exact number, and persists the result - all inside one
// transaction, with the parent secret's current_version and updated_at
// bumped in the same commit.
//
// The version number is not knowable until the store reserves it here, and
// internal/pqcrypt's AAD binds every ciphertext to "secretID|version" (see
// docs/secrets.md), so encryption cannot happen before this method decides the
// version - sealing ahead of time and merely passing the result in would
// let a concurrent writer race the reservation and silently persist a
// ciphertext bound to the wrong version, which would then fail to decrypt.
// contentType and createdBy describe the version and are stored as given;
// seal is only responsible for the encrypted payload and its digest.
func (s *Store) CreateSecretVersion(ctx context.Context, secretID int64, contentType, createdBy string, seal SealFunc) (*SecretVersion, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var current int
	if err := tx.QueryRowContext(ctx, `SELECT current_version FROM secrets WHERE id = ?`, secretID).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	next := current + 1

	sealed, err := seal(secretID, next)
	if err != nil {
		return nil, err
	}

	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO secret_versions
	 (secret_id, version, payload_enc, payload_sha256, size_bytes, content_type, created_by, created_at)
	 VALUES (?,?,?,?,?,?,?,?) RETURNING id`,
		secretID, next, sealed.PayloadEnc, sealed.PayloadSHA256, sealed.SizeBytes, contentType,
		createdBy, now).Scan(&id)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE secrets SET current_version = ?, updated_at = ? WHERE id = ?`,
		next, now, secretID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetSecretVersion(ctx, secretID, next)
}

// GetSecretVersion fetches one specific version of a secret.
func (s *Store) GetSecretVersion(ctx context.Context, secretID int64, version int) (*SecretVersion, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+secretVersionCols+` FROM secret_versions WHERE secret_id = ? AND version = ?`, secretID, version)
	v, err := scanSecretVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// GetLatestSecretVersion fetches the newest, non-destroyed version of a
// secret - what a plain "goca secret get" or a CSI Mount resolves to.
func (s *Store) GetLatestSecretVersion(ctx context.Context, secretID int64) (*SecretVersion, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+secretVersionCols+` FROM secret_versions
		 WHERE secret_id = ? AND destroyed = 0 ORDER BY version DESC LIMIT 1`, secretID)
	v, err := scanSecretVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// ListSecretVersions returns every version of a secret, newest first,
// including destroyed ones (shown with their payload already scrubbed).
func (s *Store) ListSecretVersions(ctx context.Context, secretID int64) ([]*SecretVersion, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+secretVersionCols+` FROM secret_versions WHERE secret_id = ? ORDER BY version DESC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SecretVersion
	for rows.Next() {
		v, err := scanSecretVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DestroySecretVersion permanently scrubs one version's ciphertext (true
// crypto-shredding, not just a status flag) while leaving the row itself for
// history - so version numbers and audit trails stay intact.
func (s *Store) DestroySecretVersion(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE secret_versions SET destroyed = 1, payload_enc = '' WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

//
// ---------- secret bindings ----------
//

const secretBindingCols = `b.id, b.secret_id, COALESCE(s.name,''), b.k8s_namespace,
 b.k8s_service_account, b.expires_at, b.created_by, b.created_at`

func scanSecretBinding(sc interface{ Scan(...any) error }) (*SecretBinding, error) {
	var b SecretBinding
	var expires sql.NullTime
	err := sc.Scan(&b.ID, &b.SecretID, &b.SecretName, &b.K8sNamespace, &b.K8sServiceAccount,
		&expires, &b.CreatedBy, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		v := expires.Time
		b.ExpiresAt = &v
	}
	return &b, nil
}

// CreateSecretBinding authorizes a Kubernetes (namespace, ServiceAccount)
// pair to fetch a secret.
func (s *Store) CreateSecretBinding(ctx context.Context, b *SecretBinding) (*SecretBinding, error) {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO secret_bindings
	 (secret_id, k8s_namespace, k8s_service_account, expires_at, created_by, created_at)
	 VALUES (?,?,?,?,?,?) RETURNING id`,
		b.SecretID, nz(b.K8sNamespace, "*"), nz(b.K8sServiceAccount, "*"), b.ExpiresAt,
		b.CreatedBy, b.CreatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT `+secretBindingCols+` FROM secret_bindings b LEFT JOIN secrets s ON s.id = b.secret_id WHERE b.id = ?`, id)
	return scanSecretBinding(row)
}

// ListSecretBindings returns every binding for one secret.
func (s *Store) ListSecretBindings(ctx context.Context, secretID int64) ([]*SecretBinding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+secretBindingCols+` FROM secret_bindings b LEFT JOIN secrets s ON s.id = b.secret_id
		 WHERE b.secret_id = ? ORDER BY b.id ASC`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SecretBinding
	for rows.Next() {
		b, err := scanSecretBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListAllSecretBindings returns every binding across every secret, for the
// CSI provider to glob-match (path.Match syntax) against a requesting pod's
// namespace and ServiceAccount - see internal/vault.
func (s *Store) ListAllSecretBindings(ctx context.Context) ([]*SecretBinding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+secretBindingCols+` FROM secret_bindings b LEFT JOIN secrets s ON s.id = b.secret_id ORDER BY b.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SecretBinding
	for rows.Next() {
		b, err := scanSecretBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteSecretBinding revokes one binding.
func (s *Store) DeleteSecretBinding(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secret_bindings WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
