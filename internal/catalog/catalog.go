// Package catalog is the Catalog Introspector: read-only queries against
// Postgres system catalogs (pg_roles, pg_class, pg_namespace, pg_default_acl,
// pg_policy, ...). Every reader here takes an Executor rather than opening
// its own connection, so it only ever runs inside the read-only transaction
// set up by internal/conn.
package catalog

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Executor is the subset of pgx.Tx the catalog readers need. A *pgx.Tx
// obtained from conn.Manager.Query satisfies this directly, and tests can
// supply a fake.
type Executor interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}
