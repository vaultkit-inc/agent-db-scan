// Package agentdbscan is agent-db-scan's public API: it wraps
// internal/scan with a small functional-options entrypoint, used both by
// cmd/agent-db-scan and by anything importing this module as a library.
package agentdbscan

import (
	"context"
	"time"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/scan"
)

// Option configures a Scan call.
type Option func(*scan.Options)

// WithSchema restricts the scan to a single schema. An empty string (the
// default) scans every schema.
func WithSchema(schema string) Option {
	return func(o *scan.Options) {
		o.SchemaFilter = schema
	}
}

// WithStatementTimeout overrides the default per-statement timeout used
// while introspecting the database.
func WithStatementTimeout(d time.Duration) Option {
	return func(o *scan.Options) {
		o.StatementTimeout = d
	}
}

// WithSystemSchemas includes pg_catalog, information_schema, and
// pg_toast/pg_temp schemas in the scan. By default these are excluded
// — Postgres grants PUBLIC read access to nearly its entire system
// catalog, so including them without asking buries real findings
// under system noise on every scan.
func WithSystemSchemas() Option {
	return func(o *scan.Options) {
		o.IncludeSystemSchemas = true
	}
}

// Scan opens dsn, introspects its effective privileges, and returns a
// Report.
func Scan(ctx context.Context, dsn string, opts ...Option) (*domain.Report, error) {
	var options scan.Options
	for _, opt := range opts {
		opt(&options)
	}
	return scan.Scan(ctx, dsn, options)
}
