// Package store persists CAs, certificates, identities and audit records in a
// single SQLite database file (pure Go driver, no cgo).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite connection.
type Store struct {
	db   *sql.DB
	path string
}

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cas (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL UNIQUE,
  slug          TEXT NOT NULL UNIQUE,
  subject       TEXT NOT NULL,
  subject_json  TEXT NOT NULL DEFAULT '{}',
  serial_hex    TEXT NOT NULL,
  key_type      TEXT NOT NULL,
  cert_pem      TEXT NOT NULL,
  key_enc       TEXT NOT NULL,
  is_root       INTEGER NOT NULL DEFAULT 1,
  parent_id     INTEGER REFERENCES cas(id),
  path_len      INTEGER NOT NULL DEFAULT 0,
  not_before    TIMESTAMP NOT NULL,
  not_after     TIMESTAMP NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  crl_number    INTEGER NOT NULL DEFAULT 0,
  fingerprint   TEXT NOT NULL DEFAULT '',
  is_default    INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMP NOT NULL,
  last_crl_at   TIMESTAMP,
  -- Set while a subordinate CA is waiting for an external authority (pfSense,
  -- a corporate root, ...) to sign the request goca generated.
  csr_pem       TEXT NOT NULL DEFAULT '',
  -- 1 when the certificate came from outside goca.
  external      INTEGER NOT NULL DEFAULT 0,
  -- Subject key identifier, used to link an imported chain together.
  subject_key_id TEXT NOT NULL DEFAULT '',
  authority_key_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS certificates (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ca_id         INTEGER NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
  serial_hex    TEXT NOT NULL,
  common_name   TEXT NOT NULL,
  subject       TEXT NOT NULL,
  sans_json     TEXT NOT NULL DEFAULT '[]',
  profile       TEXT NOT NULL DEFAULT 'server',
  key_type      TEXT NOT NULL DEFAULT '',
  cert_pem      TEXT NOT NULL,
  key_enc       TEXT NOT NULL DEFAULT '',
  csr_pem       TEXT NOT NULL DEFAULT '',
  fingerprint   TEXT NOT NULL DEFAULT '',
  not_before    TIMESTAMP NOT NULL,
  not_after     TIMESTAMP NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  revoked_at    TIMESTAMP,
  revoke_code   INTEGER NOT NULL DEFAULT 0,
  requested_by  TEXT NOT NULL DEFAULT '',
  note          TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMP NOT NULL,
  -- Certificate this one replaced, so a rotation history can be walked.
  renewed_from  INTEGER,
  UNIQUE(ca_id, serial_hex)
);
CREATE INDEX IF NOT EXISTS idx_cert_cn ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_cert_requested_by ON certificates(requested_by);

-- Revoked subordinate CA certificates. A CA lives in the cas table rather than
-- certificates, so retiring one needs its own record to reach the parent's CRL.
CREATE TABLE IF NOT EXISTS ca_revocations (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ca_id      INTEGER NOT NULL REFERENCES cas(id) ON DELETE CASCADE, -- the issuer whose CRL lists it
  serial_hex TEXT NOT NULL,
  subject    TEXT NOT NULL DEFAULT '',
  revoked_at TIMESTAMP NOT NULL,
  reason     INTEGER NOT NULL DEFAULT 0,
  UNIQUE(ca_id, serial_hex)
);

CREATE TABLE IF NOT EXISTS users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL UNIQUE,
  source       TEXT NOT NULL DEFAULT 'local',
  display_name TEXT NOT NULL DEFAULT '',
  email        TEXT NOT NULL DEFAULT '',
  role         TEXT NOT NULL DEFAULT 'user',
  disabled     INTEGER NOT NULL DEFAULT 0,
  pass_hash    TEXT NOT NULL DEFAULT '',
  created_at   TIMESTAMP NOT NULL,
  last_login   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMP NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  ip          TEXT NOT NULL DEFAULT '',
  user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_tokens (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'user',
  expires_at   TIMESTAMP,
  created_at   TIMESTAMP NOT NULL,
  last_used_at TIMESTAMP,
  revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      TIMESTAMP NOT NULL,
  actor   TEXT NOT NULL DEFAULT '',
  action  TEXT NOT NULL,
  target  TEXT NOT NULL DEFAULT '',
  detail  TEXT NOT NULL DEFAULT '',
  ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- ACME (RFC 8555), External Account Binding only: no HTTP-01/DNS-01 challenge
-- validation is performed. An EAB credential is the entire trust decision -
-- see internal/acme for the protocol implementation.
CREATE TABLE IF NOT EXISTS acme_eab_creds (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id          TEXT NOT NULL UNIQUE,     -- public "keyID" handed to the ACME client
  hmac_key_enc    TEXT NOT NULL,            -- encrypted base64url HMAC-SHA256 key
  name            TEXT NOT NULL,
  ca_id           INTEGER REFERENCES cas(id), -- NULL = the default issuing CA, resolved per order
  profile         TEXT NOT NULL DEFAULT 'server',
  days            INTEGER NOT NULL DEFAULT 0,  -- 0 = the CA/global default certificate validity
  allowed_domains TEXT NOT NULL DEFAULT '[]',  -- JSON array of glob patterns; empty = unrestricted
  max_accounts    INTEGER NOT NULL DEFAULT 0,  -- 0 = unlimited
  account_count   INTEGER NOT NULL DEFAULT 0,
  disabled        INTEGER NOT NULL DEFAULT 0,
  expires_at      TIMESTAMP,
  created_by      TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMP NOT NULL,
  last_used_at    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS acme_accounts (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  eab_id         INTEGER NOT NULL REFERENCES acme_eab_creds(id),
  jwk_json       TEXT NOT NULL,             -- the account's public key, canonical JWK JSON
  jwk_thumbprint TEXT NOT NULL UNIQUE,      -- RFC 7638 thumbprint; detects re-registration of the same key
  contact_json   TEXT NOT NULL DEFAULT '[]',
  status         TEXT NOT NULL DEFAULT 'valid', -- valid | deactivated
  created_at     TIMESTAMP NOT NULL,
  last_used_at   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS acme_orders (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id       INTEGER NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
  status           TEXT NOT NULL DEFAULT 'pending', -- pending|ready|processing|valid|invalid
  identifiers_json TEXT NOT NULL,           -- [{"type":"dns","value":"..."}]
  certificate_id   INTEGER REFERENCES certificates(id),
  error_json       TEXT NOT NULL DEFAULT '',
  expires_at       TIMESTAMP NOT NULL,
  created_at       TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);

CREATE TABLE IF NOT EXISTS acme_authorizations (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id         INTEGER NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
  identifier_type  TEXT NOT NULL DEFAULT 'dns',
  identifier_value TEXT NOT NULL,
  wildcard         INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'valid', -- pre-validated: EAB is the entire trust decision
  expires_at       TIMESTAMP NOT NULL,
  created_at       TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  authorization_id  INTEGER NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
  type              TEXT NOT NULL DEFAULT 'http-01',
  token             TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'valid',
  validated_at      TIMESTAMP,
  created_at        TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authorization_id);
`

// schemaPostgres is the PostgreSQL equivalent of schema above. The two are
// kept in lockstep by hand: same tables, same columns, same order, differing
// only where the dialects require it -
//
//   - INTEGER PRIMARY KEY AUTOINCREMENT -> BIGSERIAL PRIMARY KEY
//   - TIMESTAMP -> TIMESTAMPTZ, so a value keeps meaning a specific instant
//     regardless of the server's session time zone
//   - no PRAGMA lines; PostgreSQL manages concurrency and foreign keys itself
//
// "Boolean" columns (is_root, is_default, disabled, revoked, wildcard, ...)
// stay INTEGER on purpose: store.go and acme.go's query text already embeds
// literal comparisons like "is_default = 0" and "revoked = 1" that both
// dialects need to accept identically, and normalizeBoolArgs in pgrebind.go
// converts Go bool parameters to match. See its doc comment for the full
// reasoning.
const schemaPostgres = `
CREATE TABLE IF NOT EXISTS cas (
  id            BIGSERIAL PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  slug          TEXT NOT NULL UNIQUE,
  subject       TEXT NOT NULL,
  subject_json  TEXT NOT NULL DEFAULT '{}',
  serial_hex    TEXT NOT NULL,
  key_type      TEXT NOT NULL,
  cert_pem      TEXT NOT NULL,
  key_enc       TEXT NOT NULL,
  is_root       INTEGER NOT NULL DEFAULT 1,
  parent_id     BIGINT REFERENCES cas(id),
  path_len      INTEGER NOT NULL DEFAULT 0,
  not_before    TIMESTAMPTZ NOT NULL,
  not_after     TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  crl_number    INTEGER NOT NULL DEFAULT 0,
  fingerprint   TEXT NOT NULL DEFAULT '',
  is_default    INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL,
  last_crl_at   TIMESTAMPTZ,
  csr_pem       TEXT NOT NULL DEFAULT '',
  external      INTEGER NOT NULL DEFAULT 0,
  subject_key_id TEXT NOT NULL DEFAULT '',
  authority_key_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS certificates (
  id            BIGSERIAL PRIMARY KEY,
  ca_id         BIGINT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
  serial_hex    TEXT NOT NULL,
  common_name   TEXT NOT NULL,
  subject       TEXT NOT NULL,
  sans_json     TEXT NOT NULL DEFAULT '[]',
  profile       TEXT NOT NULL DEFAULT 'server',
  key_type      TEXT NOT NULL DEFAULT '',
  cert_pem      TEXT NOT NULL,
  key_enc       TEXT NOT NULL DEFAULT '',
  csr_pem       TEXT NOT NULL DEFAULT '',
  fingerprint   TEXT NOT NULL DEFAULT '',
  not_before    TIMESTAMPTZ NOT NULL,
  not_after     TIMESTAMPTZ NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active',
  revoked_at    TIMESTAMPTZ,
  revoke_code   INTEGER NOT NULL DEFAULT 0,
  requested_by  TEXT NOT NULL DEFAULT '',
  note          TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL,
  renewed_from  BIGINT,
  UNIQUE(ca_id, serial_hex)
);
CREATE INDEX IF NOT EXISTS idx_cert_cn ON certificates(common_name);
CREATE INDEX IF NOT EXISTS idx_cert_serial ON certificates(serial_hex);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_cert_requested_by ON certificates(requested_by);

CREATE TABLE IF NOT EXISTS ca_revocations (
  id         BIGSERIAL PRIMARY KEY,
  ca_id      BIGINT NOT NULL REFERENCES cas(id) ON DELETE CASCADE,
  serial_hex TEXT NOT NULL,
  subject    TEXT NOT NULL DEFAULT '',
  revoked_at TIMESTAMPTZ NOT NULL,
  reason     INTEGER NOT NULL DEFAULT 0,
  UNIQUE(ca_id, serial_hex)
);

CREATE TABLE IF NOT EXISTS users (
  id           BIGSERIAL PRIMARY KEY,
  username     TEXT NOT NULL UNIQUE,
  source       TEXT NOT NULL DEFAULT 'local',
  display_name TEXT NOT NULL DEFAULT '',
  email        TEXT NOT NULL DEFAULT '',
  role         TEXT NOT NULL DEFAULT 'user',
  disabled     INTEGER NOT NULL DEFAULT 0,
  pass_hash    TEXT NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL,
  last_login   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL,
  ip          TEXT NOT NULL DEFAULT '',
  user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_tokens (
  id           BIGSERIAL PRIMARY KEY,
  user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'user',
  expires_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ,
  revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
  id      BIGSERIAL PRIMARY KEY,
  ts      TIMESTAMPTZ NOT NULL,
  actor   TEXT NOT NULL DEFAULT '',
  action  TEXT NOT NULL,
  target  TEXT NOT NULL DEFAULT '',
  detail  TEXT NOT NULL DEFAULT '',
  ip      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_eab_creds (
  id              BIGSERIAL PRIMARY KEY,
  key_id          TEXT NOT NULL UNIQUE,
  hmac_key_enc    TEXT NOT NULL,
  name            TEXT NOT NULL,
  ca_id           BIGINT REFERENCES cas(id),
  profile         TEXT NOT NULL DEFAULT 'server',
  days            INTEGER NOT NULL DEFAULT 0,
  allowed_domains TEXT NOT NULL DEFAULT '[]',
  max_accounts    INTEGER NOT NULL DEFAULT 0,
  account_count   INTEGER NOT NULL DEFAULT 0,
  disabled        INTEGER NOT NULL DEFAULT 0,
  expires_at      TIMESTAMPTZ,
  created_by      TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL,
  last_used_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS acme_accounts (
  id             BIGSERIAL PRIMARY KEY,
  eab_id         BIGINT NOT NULL REFERENCES acme_eab_creds(id),
  jwk_json       TEXT NOT NULL,
  jwk_thumbprint TEXT NOT NULL UNIQUE,
  contact_json   TEXT NOT NULL DEFAULT '[]',
  status         TEXT NOT NULL DEFAULT 'valid',
  created_at     TIMESTAMPTZ NOT NULL,
  last_used_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS acme_orders (
  id               BIGSERIAL PRIMARY KEY,
  account_id       BIGINT NOT NULL REFERENCES acme_accounts(id) ON DELETE CASCADE,
  status           TEXT NOT NULL DEFAULT 'pending',
  identifiers_json TEXT NOT NULL,
  certificate_id   BIGINT REFERENCES certificates(id),
  error_json       TEXT NOT NULL DEFAULT '',
  expires_at       TIMESTAMPTZ NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_orders_account ON acme_orders(account_id);

CREATE TABLE IF NOT EXISTS acme_authorizations (
  id               BIGSERIAL PRIMARY KEY,
  order_id         BIGINT NOT NULL REFERENCES acme_orders(id) ON DELETE CASCADE,
  identifier_type  TEXT NOT NULL DEFAULT 'dns',
  identifier_value TEXT NOT NULL,
  wildcard         INTEGER NOT NULL DEFAULT 0,
  status           TEXT NOT NULL DEFAULT 'valid',
  expires_at       TIMESTAMPTZ NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_authz_order ON acme_authorizations(order_id);

CREATE TABLE IF NOT EXISTS acme_challenges (
  id                BIGSERIAL PRIMARY KEY,
  authorization_id  BIGINT NOT NULL REFERENCES acme_authorizations(id) ON DELETE CASCADE,
  type              TEXT NOT NULL DEFAULT 'http-01',
  token             TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'valid',
  validated_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_acme_challenges_authz ON acme_challenges(authorization_id);
`

// Open connects to (and migrates) the SQLite database at path.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	dsn := path + "?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite tolerates one writer; keep the pool small and predictable.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	// The DB holds encrypted private keys; keep it owner-only.
	_ = os.Chmod(path, 0o600)
	return &Store{db: db, path: path}, nil
}

// addedColumns are columns introduced after the first release. CREATE TABLE IF
// NOT EXISTS leaves an older table untouched, so each one is added on open when
// it is missing. Every entry must be nullable or carry a DEFAULT.
var addedColumns = []struct{ table, column, ddl string }{
	{"cas", "csr_pem", "TEXT NOT NULL DEFAULT ''"},
	{"cas", "external", "INTEGER NOT NULL DEFAULT 0"},
	{"cas", "subject_key_id", "TEXT NOT NULL DEFAULT ''"},
	{"cas", "authority_key_id", "TEXT NOT NULL DEFAULT ''"},
	{"certificates", "renewed_from", "INTEGER"},
}

// migrate brings an existing database up to the current schema.
func migrate(db *sql.DB) error {
	for _, c := range addedColumns {
		has, err := hasColumn(db, c.table, c.column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.column, c.ddl)
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name, typ  string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultVal, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// PostgresParams are the connection details for OpenPostgres.
type PostgresParams struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	SSLMode  string // disable|require|verify-ca|verify-full; default require
}

// OpenPostgres connects to (and migrates) a PostgreSQL database. It is the
// PostgreSQL counterpart to Open; store.go and acme.go's queries run
// unchanged against either backend, rewired by the driver registered in
// pgrebind.go.
func OpenPostgres(p PostgresParams) (*Store, error) {
	if p.Port == 0 {
		p.Port = 5432
	}
	if p.SSLMode == "" {
		p.SSLMode = "require"
	}
	dsn := postgresDSN(p)
	db, err := sql.Open("goca-postgres", dsn)
	if err != nil {
		return nil, err
	}
	// Unlike SQLite, PostgreSQL handles concurrent writers itself.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database %s:%d/%s: %w", p.Host, p.Port, p.Name, err)
	}
	if err := execStatements(db, schemaPostgres); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migratePostgres(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	summary := fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=%s", p.User, p.Host, p.Port, p.Name, p.SSLMode)
	return &Store{db: db, path: summary}, nil
}

// postgresDSN builds a libpq keyword/value connection string, quoting every
// value so hosts, names, users or passwords containing spaces or quotes
// round-trip correctly.
func postgresDSN(p PostgresParams) string {
	q := func(v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `'`, `\'`)
		return "'" + v + "'"
	}
	return fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		q(p.Host), p.Port, q(p.Name), q(p.User), q(p.Password), q(p.SSLMode))
}

// execStatements runs each ";"-separated statement in schema individually.
// The schema has no semicolons inside string literals, so a plain split is
// safe, and it sidesteps any ambiguity in whether the driver's query-exec
// mode of the moment supports multiple statements in one call.
func execStatements(db *sql.DB, schema string) error {
	for _, stmt := range strings.Split(schema, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// migratePostgres brings an existing PostgreSQL database up to the current
// schema. Unlike SQLite, PostgreSQL supports "ADD COLUMN IF NOT EXISTS"
// natively, so this reuses the same addedColumns table without needing a
// separate existence check.
func migratePostgres(db *sql.DB) error {
	for _, c := range addedColumns {
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s", c.table, c.column, c.ddl)
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file location.
func (s *Store) Path() string { return s.path }

// DB exposes the raw handle for advanced use.
func (s *Store) DB() *sql.DB { return s.db }

//
// ---------- CAs ----------
//

const caCols = `id, name, slug, subject, subject_json, serial_hex, key_type, cert_pem, key_enc,
 is_root, parent_id, path_len, not_before, not_after, status, crl_number, fingerprint,
 is_default, created_by, created_at, last_crl_at, csr_pem, external, subject_key_id,
 authority_key_id`

func scanCA(sc interface{ Scan(...any) error }) (*CA, error) {
	var c CA
	var parent sql.NullInt64
	var lastCRL sql.NullTime
	err := sc.Scan(&c.ID, &c.Name, &c.Slug, &c.Subject, &c.SubjectJSON, &c.SerialHex, &c.KeyType,
		&c.CertPEM, &c.KeyEnc, &c.IsRoot, &parent, &c.PathLen, &c.NotBefore, &c.NotAfter,
		&c.Status, &c.CRLNumber, &c.Fingerprint, &c.IsDefault, &c.CreatedBy, &c.CreatedAt, &lastCRL,
		&c.CSRPEM, &c.External, &c.SubjectKeyID, &c.AuthorityKeyID)
	if err != nil {
		return nil, err
	}
	if parent.Valid {
		v := parent.Int64
		c.ParentID = &v
	}
	if lastCRL.Valid {
		t := lastCRL.Time
		c.LastCRLAt = &t
	}
	return &c, nil
}

// CreateCA inserts a CA and returns it with its assigned ID.
func (s *Store) CreateCA(ctx context.Context, c *CA) (*CA, error) {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	var parent any
	if c.ParentID != nil {
		parent = *c.ParentID
	}
	// The first CA that can actually issue becomes the default. A trust anchor
	// (no key) or a CA still awaiting an external signature must never take
	// that slot, or issuance would fail with a confusing error.
	if c.KeyEnc != "" && nz(c.Status, StatusActive) == StatusActive {
		if n, err := s.CountIssuingCAs(ctx); err == nil && n == 0 {
			c.IsDefault = true
		}
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO cas
	 (name, slug, subject, subject_json, serial_hex, key_type, cert_pem, key_enc, is_root,
	  parent_id, path_len, not_before, not_after, status, crl_number, fingerprint, is_default,
	  created_by, created_at, csr_pem, external, subject_key_id, authority_key_id)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		c.Name, c.Slug, c.Subject, nz(c.SubjectJSON, "{}"), c.SerialHex, c.KeyType, c.CertPEM, c.KeyEnc,
		c.IsRoot, parent, c.PathLen, c.NotBefore.UTC(), c.NotAfter.UTC(), nz(c.Status, StatusActive),
		c.CRLNumber, c.Fingerprint, c.IsDefault, c.CreatedBy, c.CreatedAt.UTC(),
		c.CSRPEM, c.External, c.SubjectKeyID, c.AuthorityKeyID).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert CA: %w", err)
	}
	return s.GetCA(ctx, id)
}

// GetCA fetches a CA by ID.
func (s *Store) GetCA(ctx context.Context, id int64) (*CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caCols+` FROM cas WHERE id = ?`, id)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// GetCABySlug fetches a CA by its URL-safe slug.
func (s *Store) GetCABySlug(ctx context.Context, slug string) (*CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caCols+` FROM cas WHERE slug = ?`, slug)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// GetCAByRef resolves a CA by numeric ID, slug or exact name.
func (s *Store) GetCAByRef(ctx context.Context, ref string) (*CA, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return s.DefaultCA(ctx)
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT `+caCols+` FROM cas WHERE slug = ? OR name = ? OR CAST(id AS TEXT) = ? LIMIT 1`,
		ref, ref, ref)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// DefaultCA returns the CA marked default, preferring one that can actually
// issue, and falling back to the oldest issuing CA.
func (s *Store) DefaultCA(ctx context.Context) (*CA, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+caCols+` FROM cas
		 WHERE key_enc != '' AND status = 'active'
		 ORDER BY is_default DESC, id ASC LIMIT 1`)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// CountIssuingCAs counts authorities that hold a key and are active, i.e. those
// that can sign something.
func (s *Store) CountIssuingCAs(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cas WHERE key_enc != '' AND status = 'active'`).Scan(&n)
	return n, err
}

// ClearDefaultCA removes the default marker from every authority.
func (s *Store) ClearDefaultCA(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE cas SET is_default = 0`)
	return err
}

// PendingCAs lists subordinate authorities waiting for an external signature.
func (s *Store) PendingCAs(ctx context.Context) ([]*CA, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+caCols+` FROM cas WHERE status = 'pending' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCAs returns every CA, newest last.
func (s *Store) ListCAs(ctx context.Context) ([]*CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caCols+` FROM cas ORDER BY is_default DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountCAs returns the number of CAs.
func (s *Store) CountCAs(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cas`).Scan(&n)
	return n, err
}

// SetDefaultCA marks one CA as the issuance default.
func (s *Store) SetDefaultCA(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE cas SET is_default = 0`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cas SET is_default = 1 WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetCAStatus enables or disables a CA for further issuance.
func (s *Store) SetCAStatus(ctx context.Context, id int64, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE cas SET status = ? WHERE id = ?`, status, id)
	return err
}

// NextCRLNumber increments and returns the CRL counter for a CA.
func (s *Store) NextCRLNumber(ctx context.Context, caID int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int64
	if err := tx.QueryRowContext(ctx, `SELECT crl_number FROM cas WHERE id = ?`, caID).Scan(&n); err != nil {
		return 0, err
	}
	n++
	if _, err := tx.ExecContext(ctx,
		`UPDATE cas SET crl_number = ?, last_crl_at = ? WHERE id = ?`, n, time.Now().UTC(), caID); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// CompleteCA fills in the certificate of a pending subordinate CA once the
// external authority has signed its request.
func (s *Store) CompleteCA(ctx context.Context, id int64, c *CA) error {
	var parent any
	if c.ParentID != nil {
		parent = *c.ParentID
	}
	res, err := s.db.ExecContext(ctx, `UPDATE cas SET
	  cert_pem = ?, serial_hex = ?, subject = ?, not_before = ?, not_after = ?,
	  fingerprint = ?, status = ?, is_root = ?, parent_id = ?, path_len = ?,
	  subject_key_id = ?, authority_key_id = ?, external = ?
	  WHERE id = ?`,
		c.CertPEM, c.SerialHex, c.Subject, c.NotBefore.UTC(), c.NotAfter.UTC(),
		c.Fingerprint, nz(c.Status, StatusActive), c.IsRoot, parent, c.PathLen,
		c.SubjectKeyID, c.AuthorityKeyID, c.External, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetCAParent links a CA to its issuer once that issuer is known.
func (s *Store) SetCAParent(ctx context.Context, id, parentID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE cas SET parent_id = ?, is_root = 0 WHERE id = ?`, parentID, id)
	return err
}

// FindCABySubjectKeyID locates a CA by its subject key identifier, which is how
// an imported chain is stitched to what is already stored.
func (s *Store) FindCABySubjectKeyID(ctx context.Context, ski string) (*CA, error) {
	if ski == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT `+caCols+` FROM cas WHERE subject_key_id = ? AND subject_key_id != '' LIMIT 1`, ski)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// FindCABySubject locates a CA by its distinguished name.
func (s *Store) FindCABySubject(ctx context.Context, subject string) (*CA, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+caCols+` FROM cas WHERE subject = ? LIMIT 1`, subject)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// FindCAByFingerprint locates a CA by its SHA-256 fingerprint, used to avoid
// importing the same certificate twice.
func (s *Store) FindCAByFingerprint(ctx context.Context, fp string) (*CA, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+caCols+` FROM cas WHERE fingerprint = ? LIMIT 1`, fp)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// ChildCAs lists the authorities directly beneath one CA.
func (s *Store) ChildCAs(ctx context.Context, parentID int64) ([]*CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caCols+` FROM cas WHERE parent_id = ?`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCA removes a CA and (by cascade) its issued certificates.
func (s *Store) DeleteCA(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cas WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

//
// ---------- Certificates ----------
//

const certCols = `c.id, c.ca_id, c.serial_hex, c.common_name, c.subject, c.sans_json, c.profile,
 c.key_type, c.cert_pem, c.key_enc, c.csr_pem, c.fingerprint, c.not_before, c.not_after,
 c.status, c.revoked_at, c.revoke_code, c.requested_by, c.note, c.created_at,
 c.renewed_from, COALESCE(a.name,'')`

func scanCert(sc interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var revoked sql.NullTime
	var renewedFrom sql.NullInt64
	err := sc.Scan(&c.ID, &c.CAID, &c.SerialHex, &c.CommonName, &c.Subject, &c.SANsJSON, &c.Profile,
		&c.KeyType, &c.CertPEM, &c.KeyEnc, &c.CSRPEM, &c.Fingerprint, &c.NotBefore, &c.NotAfter,
		&c.Status, &revoked, &c.RevokeCode, &c.RequestedBy, &c.Note, &c.CreatedAt,
		&renewedFrom, &c.CAName)
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		t := revoked.Time
		c.RevokedAt = &t
	}
	if renewedFrom.Valid {
		v := renewedFrom.Int64
		c.RenewedFrom = &v
	}
	c.HasKey = c.KeyEnc != ""
	return &c, nil
}

// CreateCertificate stores a newly issued certificate.
func (s *Store) CreateCertificate(ctx context.Context, c *Certificate) (*Certificate, error) {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	var renewedFrom any
	if c.RenewedFrom != nil {
		renewedFrom = *c.RenewedFrom
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `INSERT INTO certificates
	 (ca_id, serial_hex, common_name, subject, sans_json, profile, key_type, cert_pem, key_enc,
	  csr_pem, fingerprint, not_before, not_after, status, requested_by, note, created_at,
	  renewed_from)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`,
		c.CAID, c.SerialHex, c.CommonName, c.Subject, nz(c.SANsJSON, "[]"), nz(c.Profile, "server"),
		c.KeyType, c.CertPEM, c.KeyEnc, c.CSRPEM, c.Fingerprint, c.NotBefore.UTC(), c.NotAfter.UTC(),
		nz(c.Status, StatusActive), c.RequestedBy, c.Note, c.CreatedAt.UTC(), renewedFrom).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("insert certificate: %w", err)
	}
	return s.GetCertificate(ctx, id)
}

// GetCertificate fetches one certificate by ID.
func (s *Store) GetCertificate(ctx context.Context, id int64) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certCols+` FROM certificates c LEFT JOIN cas a ON a.id = c.ca_id WHERE c.id = ?`, id)
	c, err := scanCert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// GetCertificateBySerial finds a certificate by its hex serial.
func (s *Store) GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error) {
	serial = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(serial), ":", ""))
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certCols+` FROM certificates c LEFT JOIN cas a ON a.id = c.ca_id
		 WHERE UPPER(c.serial_hex) = ?`, serial)
	c, err := scanCert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// SearchCertificates runs a filtered, paginated certificate query and returns
// the page plus the total number of matches.
func (s *Store) SearchCertificates(ctx context.Context, f CertFilter) ([]*Certificate, int, error) {
	var where []string
	var args []any

	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		bare := strings.ToUpper(strings.ReplaceAll(q, ":", ""))
		where = append(where, `(LOWER(c.common_name) LIKE ? OR LOWER(c.subject) LIKE ?
			OR LOWER(c.sans_json) LIKE ? OR LOWER(c.requested_by) LIKE ?
			OR UPPER(c.serial_hex) LIKE ? OR UPPER(c.fingerprint) LIKE ?)`)
		args = append(args, like, like, like, like, "%"+bare+"%", "%"+bare+"%")
	}
	if f.CAID > 0 {
		where = append(where, `c.ca_id = ?`)
		args = append(args, f.CAID)
	}
	if f.Profile != "" {
		where = append(where, `c.profile = ?`)
		args = append(args, f.Profile)
	}
	if f.RequestedBy != "" {
		where = append(where, `c.requested_by = ?`)
		args = append(args, f.RequestedBy)
	}
	now := time.Now().UTC()
	switch f.Status {
	case StatusActive:
		where = append(where, `c.status = 'active' AND c.not_after > ?`)
		args = append(args, now)
	case StatusExpired:
		where = append(where, `c.status != 'revoked' AND c.not_after <= ?`)
		args = append(args, now)
	case StatusRevoked:
		where = append(where, `c.status = 'revoked'`)
	}
	if f.ExpiringIn > 0 {
		where = append(where, `c.status = 'active' AND c.not_after > ? AND c.not_after <= ?`)
		args = append(args, now, now.AddDate(0, 0, f.ExpiringIn))
	}

	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM certificates c`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortCol := "c.created_at"
	switch f.SortBy {
	case "not_after", "expiry":
		sortCol = "c.not_after"
	case "common_name", "cn":
		sortCol = "c.common_name"
	case "serial":
		sortCol = "c.serial_hex"
	}
	dir := "ASC"
	if f.SortDesc {
		dir = "DESC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT ` + certCols + ` FROM certificates c LEFT JOIN cas a ON a.id = c.ca_id` + clause +
		fmt.Sprintf(" ORDER BY %s %s, c.id %s LIMIT ? OFFSET ?", sortCol, dir, dir)
	args = append(args, limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// RevokeCertificate marks a certificate revoked with an RFC 5280 reason code.
func (s *Store) RevokeCertificate(ctx context.Context, id int64, reason int) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET status = 'revoked', revoked_at = ?, revoke_code = ?
		 WHERE id = ? AND status != 'revoked'`, time.Now().UTC(), reason, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("certificate %d not found or already revoked", id)
	}
	return nil
}

// UnrevokeCertificate lifts a revocation. Only a certificate placed on hold may
// be reinstated: any other reason is a permanent statement about the key.
func (s *Store) UnrevokeCertificate(ctx context.Context, id int64) error {
	var code int
	var status string
	err := s.db.QueryRowContext(ctx,
		`SELECT status, revoke_code FROM certificates WHERE id = ?`, id).Scan(&status, &code)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != StatusRevoked {
		return fmt.Errorf("certificate %d is not revoked", id)
	}
	if code != 6 { // RFC 5280 certificateHold
		return fmt.Errorf("only certificates on hold can be reinstated; this one was revoked as %q",
			revokeReasonName(code))
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE certificates SET status = 'active', revoked_at = NULL, revoke_code = 0 WHERE id = ?`, id)
	return err
}

// revokeReasonName is a local copy of the reason labels, kept here so the store
// does not depend on the pki package.
func revokeReasonName(code int) string {
	names := map[int]string{
		0: "unspecified", 1: "key compromise", 2: "CA compromise",
		3: "affiliation changed", 4: "superseded", 5: "cessation of operation",
		6: "certificate hold", 9: "privilege withdrawn", 10: "AA compromise",
	}
	if n, ok := names[code]; ok {
		return n
	}
	return fmt.Sprintf("code %d", code)
}

// RevokedCertificates lists revoked certificates for one CA (used for CRLs).
func (s *Store) RevokedCertificates(ctx context.Context, caID int64) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certCols+` FROM certificates c LEFT JOIN cas a ON a.id = c.ca_id
		 WHERE c.ca_id = ? AND c.status = 'revoked' ORDER BY c.revoked_at ASC`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetRenewedFrom links a replacement certificate to its predecessor.
func (s *Store) SetRenewedFrom(ctx context.Context, id, predecessorID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certificates SET renewed_from = ? WHERE id = ?`, predecessorID, id)
	return err
}

// CertificateRenewedFrom returns the certificate that replaced the given one,
// or nil when it has not been renewed.
func (s *Store) CertificateRenewedFrom(ctx context.Context, id int64) (*Certificate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certCols+` FROM certificates c LEFT JOIN cas a ON a.id = c.ca_id
		 WHERE c.renewed_from = ? ORDER BY c.id ASC LIMIT 1`, id)
	c, err := scanCert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// RecordCARevocation adds a subordinate CA's serial to its issuer's CRL.
func (s *Store) RecordCARevocation(ctx context.Context, issuerCAID int64, serial string, reason int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ca_revocations (ca_id, serial_hex, revoked_at, reason) VALUES (?,?,?,?)
		 ON CONFLICT(ca_id, serial_hex) DO UPDATE SET revoked_at = excluded.revoked_at,
		   reason = excluded.reason`,
		issuerCAID, serial, time.Now().UTC(), reason)
	return err
}

// CARevocation is a retired subordinate CA listed on an issuer's CRL.
type CARevocation struct {
	SerialHex string
	Subject   string
	RevokedAt time.Time
	Reason    int
}

// CARevocations lists subordinate CAs revoked by one issuer.
func (s *Store) CARevocations(ctx context.Context, issuerCAID int64) ([]CARevocation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT serial_hex, subject, revoked_at, reason FROM ca_revocations
		 WHERE ca_id = ? ORDER BY revoked_at`, issuerCAID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CARevocation
	for rows.Next() {
		var r CARevocation
		if err := rows.Scan(&r.SerialHex, &r.Subject, &r.RevokedAt, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteCertificate permanently removes a certificate record.
func (s *Store) DeleteCertificate(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SerialExists reports whether a serial is already used by a CA.
func (s *Store) SerialExists(ctx context.Context, caID int64, serial string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM certificates WHERE ca_id = ? AND serial_hex = ?`, caID, serial).Scan(&n)
	return n > 0, err
}

//
// ---------- Users ----------
//

const userCols = `id, username, source, display_name, email, role, disabled, pass_hash, created_at, last_login`

func scanUser(sc interface{ Scan(...any) error }) (*User, error) {
	var u User
	var last sql.NullTime
	err := sc.Scan(&u.ID, &u.Username, &u.Source, &u.DisplayName, &u.Email, &u.Role,
		&u.Disabled, &u.PassHash, &u.CreatedAt, &last)
	if err != nil {
		return nil, err
	}
	if last.Valid {
		t := last.Time
		u.LastLogin = &t
	}
	return &u, nil
}

// UpsertUser creates or refreshes a user record (used after each LDAP login).
func (s *Store) UpsertUser(ctx context.Context, u *User) (*User, error) {
	existing, err := s.GetUserByName(ctx, u.Username)
	switch {
	case err == nil:
		_, err = s.db.ExecContext(ctx,
			`UPDATE users SET source=?, display_name=?, email=?, role=? WHERE id=?`,
			nz(u.Source, existing.Source), nz(u.DisplayName, existing.DisplayName),
			nz(u.Email, existing.Email), nz(u.Role, existing.Role), existing.ID)
		if err != nil {
			return nil, err
		}
		return s.GetUser(ctx, existing.ID)
	case errors.Is(err, ErrNotFound):
		var id int64
		err := s.db.QueryRowContext(ctx,
			`INSERT INTO users (username, source, display_name, email, role, disabled, pass_hash, created_at)
			 VALUES (?,?,?,?,?,?,?,?) RETURNING id`,
			u.Username, nz(u.Source, SourceLocal), u.DisplayName, u.Email, nz(u.Role, RoleUser),
			u.Disabled, u.PassHash, time.Now().UTC()).Scan(&id)
		if err != nil {
			return nil, err
		}
		return s.GetUser(ctx, id)
	default:
		return nil, err
	}
}

// GetUser fetches a user by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// GetUserByName fetches a user by username (case-insensitive).
func (s *Store) GetUserByName(ctx context.Context, name string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE LOWER(username) = LOWER(?)`, name)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// ListUsers returns all known users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserRole changes a user's role.
func (s *Store) SetUserRole(ctx context.Context, id int64, role string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

// SetUserDisabled enables or disables an account.
func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)
	return err
}

// SetUserPassword stores a bcrypt hash for a local user.
func (s *Store) SetUserPassword(ctx context.Context, id int64, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET pass_hash = ? WHERE id = ?`, hash, id)
	return err
}

// DeleteUser removes a user account.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLogin records a successful login timestamp.
func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

//
// ---------- Sessions ----------
//

// CreateSession stores a hashed session token.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at, created_at, ip, user_agent)
		 VALUES (?,?,?,?,?,?)`,
		sess.UserID, sess.TokenHash, sess.ExpiresAt.UTC(), time.Now().UTC(), sess.IP, sess.UserAgent)
	return err
}

// SessionUser resolves a session token hash to its (enabled) user.
func (s *Store) SessionUser(ctx context.Context, tokenHash string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+prefixCols(userCols, "u.")+` FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, time.Now().UTC())
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// DeleteSession removes one session (logout).
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteUserSessions removes every session belonging to a user.
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// PurgeExpiredSessions deletes stale sessions and returns how many went away.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

//
// ---------- API tokens ----------
//

const tokenCols = `t.id, t.user_id, t.name, t.prefix, t.token_hash, t.role, t.expires_at,
 t.created_at, t.last_used_at, t.revoked, COALESCE(u.username,'')`

func scanToken(sc interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	var exp, last sql.NullTime
	err := sc.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &t.TokenHash, &t.Role, &exp,
		&t.CreatedAt, &last, &t.Revoked, &t.Username)
	if err != nil {
		return nil, err
	}
	if exp.Valid {
		v := exp.Time
		t.ExpiresAt = &v
	}
	if last.Valid {
		v := last.Time
		t.LastUsedAt = &v
	}
	return &t, nil
}

// CreateAPIToken stores a new bearer token record.
func (s *Store) CreateAPIToken(ctx context.Context, t *APIToken) (*APIToken, error) {
	var exp any
	if t.ExpiresAt != nil {
		exp = t.ExpiresAt.UTC()
	}
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO api_tokens (user_id, name, prefix, token_hash, role, expires_at, created_at)
		 VALUES (?,?,?,?,?,?,?) RETURNING id`,
		t.UserID, t.Name, t.Prefix, t.TokenHash, nz(t.Role, RoleUser), exp, time.Now().UTC()).Scan(&id)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id WHERE t.id = ?`, id)
	return scanToken(row)
}

// LookupAPIToken resolves a token hash to its record and owner.
func (s *Store) LookupAPIToken(ctx context.Context, hash string) (*APIToken, *User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = ? AND t.revoked = 0`, hash)
	t, err := scanToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, nil, ErrNotFound
	}
	u, err := s.GetUser(ctx, t.UserID)
	if err != nil {
		return nil, nil, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, time.Now().UTC(), t.ID)
	return t, u, nil
}

// ListAPITokens lists tokens, optionally filtered to one owner.
func (s *Store) ListAPITokens(ctx context.Context, userID int64) ([]*APIToken, error) {
	q := `SELECT ` + tokenCols + ` FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id`
	var args []any
	if userID > 0 {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	q += ` ORDER BY t.created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken disables a bearer token.
func (s *Store) RevokeAPIToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

//
// ---------- Audit ----------
//

// Audit appends an entry to the audit log. Failures are non-fatal by design;
// callers log them rather than aborting the operation being recorded.
func (s *Store) Audit(ctx context.Context, actor, action, target, detail, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, detail, ip) VALUES (?,?,?,?,?,?)`,
		time.Now().UTC(), actor, action, target, detail, ip)
	return err
}

// ListAudit returns the most recent audit entries.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]*AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, target, detail, ip FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.IP); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

//
// ---------- Settings & stats ----------
//

// GetSetting reads a key/value setting, returning "" when unset.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting writes a key/value setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Stats computes dashboard counters.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	var st Stats
	now := time.Now().UTC()
	q := func(dst *int, query string, args ...any) error {
		return s.db.QueryRowContext(ctx, query, args...).Scan(dst)
	}
	if err := q(&st.CAs, `SELECT COUNT(*) FROM cas`); err != nil {
		return nil, err
	}
	if err := q(&st.Certificates, `SELECT COUNT(*) FROM certificates`); err != nil {
		return nil, err
	}
	if err := q(&st.Active, `SELECT COUNT(*) FROM certificates WHERE status='active' AND not_after > ?`, now); err != nil {
		return nil, err
	}
	if err := q(&st.Revoked, `SELECT COUNT(*) FROM certificates WHERE status='revoked'`); err != nil {
		return nil, err
	}
	if err := q(&st.Expired, `SELECT COUNT(*) FROM certificates WHERE status!='revoked' AND not_after <= ?`, now); err != nil {
		return nil, err
	}
	if err := q(&st.ExpiringSoon,
		`SELECT COUNT(*) FROM certificates WHERE status='active' AND not_after > ? AND not_after <= ?`,
		now, now.AddDate(0, 0, 30)); err != nil {
		return nil, err
	}
	if err := q(&st.Users, `SELECT COUNT(*) FROM users`); err != nil {
		return nil, err
	}
	if err := q(&st.IssuedLast30Day, `SELECT COUNT(*) FROM certificates WHERE created_at >= ?`,
		now.AddDate(0, 0, -30)); err != nil {
		return nil, err
	}
	return &st, nil
}

// nz returns v, or def when v is empty.
func nz(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// prefixCols rewrites a bare column list with a table alias prefix.
func prefixCols(cols, prefix string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}
