package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// FunctionReader reads SECURITY DEFINER functions and procedures from pg_proc.
type FunctionReader struct {
	exec Executor
}

// NewFunctionReader constructs a FunctionReader bound to exec.
func NewFunctionReader(exec Executor) *FunctionReader {
	return &FunctionReader{exec: exec}
}

// ListSecurityDefinerFunctions returns every SECURITY DEFINER function or
// procedure, optionally filtered to one schema. System schemas are skipped
// unless includeSystem is true or schemaFilter names one, matching ListObjects.
//
// Unlike tables, a function with a NULL ACL is NOT owner-only: Postgres
// grants EXECUTE to PUBLIC by default. acldefault('f', owner) expands that
// implicit default into real entries, so parseACL sees the PUBLIC grant.
func (f *FunctionReader) ListSecurityDefinerFunctions(ctx context.Context, schemaFilter string, includeSystem bool) ([]domain.SecurityDefinerFunction, error) {
	rows, err := f.exec.Query(ctx, `
    SELECT
        n.nspname,
        p.proname,
        p.oid::regprocedure::text,
        p.prokind::text,
        p.proowner::regrole::text,
        o.rolsuper,
        COALESCE(p.proacl, acldefault('f', p.proowner))::text[],
        COALESCE(p.proconfig, '{}'::text[])
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_roles o     ON o.oid = p.proowner
    WHERE p.prosecdef
      AND ($1 = '' OR n.nspname = $1)
      AND (
        $1 <> ''
        OR $2 = true
        OR (
          n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
          AND n.nspname NOT LIKE 'pg_temp%'
        )
      )
	`, schemaFilter, includeSystem)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var functions []domain.SecurityDefinerFunction
	for rows.Next() {
		var (
			schema, name, signature, prokind, owner string
			ownerSuperuser                          bool
			aclText, config                         []string
		)
		if err := rows.Scan(&schema, &name, &signature, &prokind, &owner, &ownerSuperuser, &aclText, &config); err != nil {
			return nil, err
		}

		acl, err := parseACL(aclText)
		if err != nil {
			return nil, fmt.Errorf("parsing acl for %s: %w", signature, err)
		}

		functions = append(functions, domain.SecurityDefinerFunction{
			Object: domain.DBObject{
				Schema: schema,
				Name:   name,
				Kind:   domain.KindFunction,
				Owner:  owner,
				ACL:    acl,
			},
			Signature:        signature,
			IsProcedure:      prokind == "p",
			OwnerSuperuser:   ownerSuperuser,
			PinnedSearchPath: hasPinnedSearchPath(config),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return functions, nil
}

// hasPinnedSearchPath reports whether a function's proconfig sets its own
// search_path. Entries look like "search_path=public, pg_temp".
func hasPinnedSearchPath(config []string) bool {
	for _, entry := range config {
		if strings.HasPrefix(entry, "search_path=") {
			return true
		}
	}
	return false
}
