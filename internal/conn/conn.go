// Package conn is the Connection Manager: it owns the single pgx connection
// agent-db-scan uses to talk to Postgres, and enforces the tool's core
// safety invariant — every query runs inside a read-only, timeout-bound
// transaction. Nothing in this package (or anything that only receives a
// conn.Manager) is able to issue a write.
package conn

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DefaultStatementTimeout bounds how long any single statement may run.
// Introspection queries against system catalogs should be fast; a short
// timeout keeps a hung scan from holding a connection (and a transaction)
// open indefinitely.
const DefaultStatementTimeout = 5 * time.Second

// Manager owns one pgx connection and mediates all access to it.
type Manager struct {
	conn             *pgx.Conn
	statementTimeout time.Duration
}

// Option configures a Manager at Open time.
type Option func(*Manager)

// WithStatementTimeout overrides DefaultStatementTimeout.
func WithStatementTimeout(d time.Duration) Option {
	return func(m *Manager) {
		m.statementTimeout = d
	}
}

// Open establishes a connection to dsn and applies opts.
func Open(ctx context.Context, dsn string, opts ...Option) (*Manager, error) {
	m := &Manager{statementTimeout: DefaultStatementTimeout}
	for _, opt := range opts {
		opt(m)
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	m.conn = conn

	return m, nil
}

// Close releases the underlying connection.
func (m *Manager) Close(ctx context.Context) error {
	return m.conn.Close(ctx)
}

// CurrentUser returns the role the connection authenticated as.
func (m *Manager) CurrentUser(ctx context.Context) (string, error) {
	var user string

	row := m.conn.QueryRow(ctx, "SELECT current_user")

	err := row.Scan(&user)
	if err != nil {
		return "", err
	}

	return user, nil
}

// Query runs fn inside a transaction that is:
//  1. BEGIN'd
//  2. set to SET TRANSACTION READ ONLY
//  3. bound by SET LOCAL statement_timeout (m.statementTimeout)
//
// fn must not attempt any write — the READ ONLY transaction mode makes that
// a hard guarantee at the Postgres level, not just a convention here. The
// transaction is always rolled back (never committed) once fn returns,
// since a pure read has nothing to persist.
func (m *Manager) Query(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := m.conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", m.statementTimeout.Milliseconds()))
	if err != nil {
		return err
	}

	return fn(ctx, tx)
}
