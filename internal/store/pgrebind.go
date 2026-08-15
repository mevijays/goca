package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/stdlib"
)

// Every query in this package is written once, using SQLite/MySQL-style "?"
// positional placeholders. PostgreSQL only understands "$1, $2, ..." numbered
// placeholders, and rewriting all ~90 call sites (including every query run
// inside a transaction) would mean maintaining two dialects by hand.
//
// Instead we register a driver, "goca-postgres", that wraps pgx's stdlib
// driver and rewrites "?" to "$N" in the query text right before handing it
// to pgx - transparently, for every code path database/sql can take (Prepare,
// PrepareContext, ExecContext, QueryContext), so every existing call site
// works unchanged against either backend.
func init() {
	sql.Register("goca-postgres", &rebindingDriver{underlying: stdlib.GetDefaultDriver()})
}

// rebindingDriver wraps another driver.Driver, rewriting placeholders in every
// connection it opens.
type rebindingDriver struct {
	underlying driver.Driver
}

func (d *rebindingDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.underlying.Open(name)
	if err != nil {
		return nil, err
	}
	return &rebindingConn{conn: conn}, nil
}

// rebindingConn wraps a single pgx connection. It implements every optional
// driver.Conn interface pgx's stdlib.Conn implements (verified against
// jackc/pgx/v5/stdlib/sql.go), delegating as-is except for the four methods
// that carry query text, which get rebound first.
type rebindingConn struct {
	conn driver.Conn
}

func (c *rebindingConn) Prepare(query string) (driver.Stmt, error) {
	return c.conn.Prepare(rebindQuery(query))
}

func (c *rebindingConn) Close() error { return c.conn.Close() }

// Begin satisfies driver.Conn itself; database/sql only calls it when the
// connection doesn't implement the preferred driver.ConnBeginTx.
func (c *rebindingConn) Begin() (driver.Tx, error) { return c.conn.Begin() }

func (c *rebindingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return nil, driver.ErrSkip
}

func (c *rebindingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if p, ok := c.conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, rebindQuery(query))
	}
	return c.Prepare(query)
}

func (c *rebindingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := c.conn.(driver.ExecerContext); ok {
		return e.ExecContext(ctx, rebindQuery(query), normalizeBoolArgs(args))
	}
	return nil, driver.ErrSkip
}

func (c *rebindingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if q, ok := c.conn.(driver.QueryerContext); ok {
		return q.QueryContext(ctx, rebindQuery(query), normalizeBoolArgs(args))
	}
	return nil, driver.ErrSkip
}

func (c *rebindingConn) Ping(ctx context.Context) error {
	if p, ok := c.conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *rebindingConn) CheckNamedValue(nv *driver.NamedValue) error {
	if n, ok := c.conn.(driver.NamedValueChecker); ok {
		return n.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func (c *rebindingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

// normalizeBoolArgs converts Go bool argument values to int64 0/1.
//
// Every "boolean" column in this package's schema (is_root, is_default,
// disabled, revoked, wildcard, ...) is declared INTEGER, matching what
// SQLite has always stored and what the query text's own literals
// ("SET revoked = 1", "WHERE is_default = 0", ...) already assume on both
// backends. pgx, unlike modernc.org/sqlite, sends parameters with an
// explicit PostgreSQL type derived from the Go value, so a bare Go bool
// would arrive typed "boolean" and PostgreSQL would reject binding it to an
// "integer" column. Converting here, once, keeps every INSERT/UPDATE call
// site free of that detail.
func normalizeBoolArgs(args []driver.NamedValue) []driver.NamedValue {
	for i, a := range args {
		if b, ok := a.Value.(bool); ok {
			if b {
				args[i].Value = int64(1)
			} else {
				args[i].Value = int64(0)
			}
		}
	}
	return args
}

// rebindQuery rewrites "?" placeholders into PostgreSQL's "$1, $2, ..." form,
// skipping "?" that appears inside a single-quoted SQL string literal or a
// double-quoted identifier so it never mistakes literal text for a
// placeholder. None of goca's queries currently contain such a "?", but
// getting this right costs nothing.
func rebindQuery(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		switch {
		case inSingle:
			b.WriteByte(ch)
			if ch == '\'' {
				inSingle = false
			}
		case inDouble:
			b.WriteByte(ch)
			if ch == '"' {
				inDouble = false
			}
		case ch == '\'':
			inSingle = true
			b.WriteByte(ch)
		case ch == '"':
			inDouble = true
			b.WriteByte(ch)
		case ch == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
