// Package scan is the top-level orchestrator: it wires the connection
// manager, catalog readers, role graph, resolver, and classifier together
// into a single Scan call.
package scan

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/classify"
	"github.com/vaultkit-inc/agent-db-scan/internal/conn"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/privileges"
	"github.com/vaultkit-inc/agent-db-scan/internal/roles"
)

// Options configures a scan.
type Options struct {
	SchemaFilter         string
	StatementTimeout     time.Duration
	IncludeSystemSchemas bool
}

// Scan opens dsn, introspects it under a single read-only transaction, and
// returns the resulting Report.
func Scan(ctx context.Context, dsn string, opts Options) (*domain.Report, error) {
	var connOpts []conn.Option
	if opts.StatementTimeout > 0 {
		connOpts = append(connOpts, conn.WithStatementTimeout(opts.StatementTimeout))
	}

	mgr, err := conn.Open(ctx, dsn, connOpts...)
	if err != nil {
		return nil, err
	}
	defer mgr.Close(ctx)

	scannedAt := time.Now().UTC()

	login, err := mgr.CurrentUser(ctx)
	if err != nil {
		return nil, err
	}

	var (
		allRoles    []domain.Role
		objects     []domain.DBObject
		defaultACLs []catalog.DefaultACLEntry
		rlsInfo     []domain.RLSInfo
	)

	err = mgr.Query(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var qerr error

		allRoles, qerr = catalog.NewRoleReader(tx).ListRoles(ctx)
		if qerr != nil {
			return qerr
		}

		objects, qerr = catalog.NewObjectReader(tx).ListObjects(ctx, opts.SchemaFilter, opts.IncludeSystemSchemas)
		if qerr != nil {
			return qerr
		}

		defaultACLs, qerr = catalog.NewDefaultACLReader(tx).ListDefaultACLs(ctx)
		if qerr != nil {
			return qerr
		}

		rlsInfo, qerr = catalog.NewRLSReader(tx).ListRLS(ctx)
		return qerr
	})
	if err != nil {
		return nil, err
	}

	graph := roles.BuildGraph(allRoles)
	effectiveRoles, err := graph.Resolve(login)
	if err != nil {
		return nil, err
	}

	isSuperuser := false
	for _, r := range allRoles {
		if r.Name == login {
			isSuperuser = r.Superuser
			break
		}
	}

	input := privileges.Input{
		Login:          login,
		IsSuperuser:    isSuperuser,
		EffectiveRoles: effectiveRoles,
		Objects:        objects,
		DefaultACLs:    defaultACLs,
		RLS:            rlsInfo,
	}

	resolver := privileges.NewResolver()

	access, err := resolver.Resolve(ctx, input)
	if err != nil {
		return nil, err
	}

	futureAccess, err := resolver.ResolveFuture(ctx, input)
	if err != nil {
		return nil, err
	}

	access, warnings, err := classify.NewClassifier().Classify(access, login)
	if err != nil {
		return nil, err
	}

	return &domain.Report{
		Login:        login,
		ScannedAt:    scannedAt,
		Access:       access,
		FutureAccess: futureAccess,
		Warnings:     warnings,
	}, nil
}
