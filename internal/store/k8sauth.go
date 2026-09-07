package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

//
// ---------- k8s auth methods (CSI trust domains) ----------
//

// k8sAuthMethodCols is the column list every k8s_auth_methods SELECT uses.
// reviewer_token_enc is deliberately excluded: it is only ever read by the
// web layer, which decrypts it before building a k8sauth.Verifier, and it
// must never leak into a JSON response or a list view.
const k8sAuthMethodCols = `id, name, audience, issuer_url, api_server_url, ca_cert,
 insecure_skip_verify, disabled, created_by, created_at, updated_at`

// k8sAuthMethodColsWithToken adds the encrypted reviewer token, in its
// table position (after ca_cert), for the single-row lookups that need it.
const k8sAuthMethodColsWithToken = `id, name, audience, issuer_url, api_server_url, ca_cert,
 reviewer_token_enc, insecure_skip_verify, disabled, created_by, created_at, updated_at`

func scanK8sAuthMethod(sc interface{ Scan(...any) error }) (*K8sAuthMethod, error) {
	var m K8sAuthMethod
	err := sc.Scan(&m.ID, &m.Name, &m.Audience, &m.IssuerURL, &m.APIServerURL, &m.CACert,
		&m.InsecureSkipVerify, &m.Disabled, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// CreateK8sAuthMethod stores a new trust domain. m.ReviewerTokenEnc must
// already be encrypted (enc: prefix) by the caller.
func (s *Store) CreateK8sAuthMethod(ctx context.Context, m *K8sAuthMethod) (*K8sAuthMethod, error) {
	now := time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO k8s_auth_methods
	 (name, audience, issuer_url, api_server_url, ca_cert, reviewer_token_enc,
	  insecure_skip_verify, disabled, created_by, created_at, updated_at)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		m.Name, nz(m.Audience, "goca-csi"), m.IssuerURL, m.APIServerURL, m.CACert,
		m.ReviewerTokenEnc, m.InsecureSkipVerify, m.Disabled, m.CreatedBy,
		m.CreatedAt.UTC(), m.UpdatedAt.UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetK8sAuthMethod(ctx, id)
}

// GetK8sAuthMethod fetches one trust domain by id, including the encrypted
// reviewer token.
func (s *Store) GetK8sAuthMethod(ctx context.Context, id int64) (*K8sAuthMethod, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+k8sAuthMethodColsWithToken+` FROM k8s_auth_methods WHERE id = ?`, id)
	m, err := scanK8sAuthMethodWithToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// GetK8sAuthMethodByName fetches one trust domain by its unique name.
func (s *Store) GetK8sAuthMethodByName(ctx context.Context, name string) (*K8sAuthMethod, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+k8sAuthMethodColsWithToken+` FROM k8s_auth_methods WHERE name = ?`, name)
	m, err := scanK8sAuthMethodWithToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// ListK8sAuthMethods returns every trust domain, oldest first. The reviewer
// token is not included.
func (s *Store) ListK8sAuthMethods(ctx context.Context) ([]*K8sAuthMethod, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+k8sAuthMethodCols+` FROM k8s_auth_methods ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*K8sAuthMethod
	for rows.Next() {
		m, err := scanK8sAuthMethod(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListK8sAuthMethodsWithToken is ListK8sAuthMethods but includes the encrypted
// reviewer token. It exists only for the web layer, which must decrypt the
// token to build each trust domain's Verifier; the REST list endpoint keeps
// using the token-less variant so the secret never leaves the server.
func (s *Store) ListK8sAuthMethodsWithToken(ctx context.Context) ([]*K8sAuthMethod, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+k8sAuthMethodColsWithToken+` FROM k8s_auth_methods ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*K8sAuthMethod
	for rows.Next() {
		m, err := scanK8sAuthMethodWithToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// m.ReviewerTokenEnc, when non-empty, replaces the stored token; when empty
// the existing token is kept.
func (s *Store) UpdateK8sAuthMethod(ctx context.Context, m *K8sAuthMethod) (*K8sAuthMethod, error) {
	token := m.ReviewerTokenEnc
	if token == "" {
		// Preserve the existing token: read it back first.
		existing, err := s.GetK8sAuthMethod(ctx, m.ID)
		if err != nil {
			return nil, err
		}
		token = existing.ReviewerTokenEnc
	}
	m.UpdatedAt = time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE k8s_auth_methods SET
	 audience = ?, issuer_url = ?, api_server_url = ?, ca_cert = ?,
	 reviewer_token_enc = ?, insecure_skip_verify = ?, disabled = ?, updated_at = ?
	 WHERE id = ?`,
		nz(m.Audience, "goca-csi"), m.IssuerURL, m.APIServerURL, m.CACert,
		token, m.InsecureSkipVerify, m.Disabled, m.UpdatedAt.UTC(), m.ID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetK8sAuthMethod(ctx, m.ID)
}

// SetK8sAuthMethodDisabled enables or disables a trust domain. A disabled
// domain rejects every token presented under its name.
func (s *Store) SetK8sAuthMethodDisabled(ctx context.Context, id int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE k8s_auth_methods SET disabled = ?, updated_at = ? WHERE id = ?`,
		disabled, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteK8sAuthMethod removes a trust domain. It fails with a foreign-key
// error while any secret binding still references it by name, so a domain in
// use cannot be silently deleted out from under a binding.
func (s *Store) DeleteK8sAuthMethod(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM k8s_auth_methods WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountSecretBindingsByAuthMethod reports how many secret bindings reference
// the named trust domain, so the API can refuse to delete a domain that is
// still in use.
func (s *Store) CountSecretBindingsByAuthMethod(ctx context.Context, name string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_bindings WHERE k8s_auth_method = ?`, name).Scan(&n)
	return n, err
}

// scanK8sAuthMethodWithToken is scanK8sAuthMethod plus the encrypted reviewer
// token (in its table position, after ca_cert), for the single-row lookups
// that need it.
func scanK8sAuthMethodWithToken(sc interface{ Scan(...any) error }) (*K8sAuthMethod, error) {
	var m K8sAuthMethod
	err := sc.Scan(&m.ID, &m.Name, &m.Audience, &m.IssuerURL, &m.APIServerURL, &m.CACert,
		&m.ReviewerTokenEnc, &m.InsecureSkipVerify, &m.Disabled, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}
