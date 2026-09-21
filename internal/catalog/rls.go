package catalog

import (
	"context"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// RLSReader reads row-level security state from pg_class and pg_policies.
type RLSReader struct {
	exec Executor
}

// NewRLSReader constructs an RLSReader bound to exec.
func NewRLSReader(exec Executor) *RLSReader {
	return &RLSReader{exec: exec}
}

// ListRLS returns RLS state for every table that has it enabled and/or has
// policies defined.
func (r *RLSReader) ListRLS(ctx context.Context) ([]domain.RLSInfo, error) {
	rows, err := r.exec.Query(ctx, `
		SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r'
		  AND (
		    c.relrowsecurity
		    OR EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
		  )
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type key struct{ schema, table string }
	infos := make(map[key]*domain.RLSInfo)
	var order []key

	for rows.Next() {
		var schema, table string
		var enabled, forced bool
		if err := rows.Scan(&schema, &table, &enabled, &forced); err != nil {
			return nil, err
		}
		k := key{schema, table}
		infos[k] = &domain.RLSInfo{Schema: schema, Table: table, Enabled: enabled, Forced: forced}
		order = append(order, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	policyRows, err := r.exec.Query(ctx, `
		SELECT schemaname, tablename, policyname, permissive, roles::text[],
		       cmd, COALESCE(qual, ''), COALESCE(with_check, '')
		FROM pg_policies
	`)
	if err != nil {
		return nil, err
	}
	defer policyRows.Close()

	for policyRows.Next() {
		var schema, table, name, permissive, cmd, usingExpr, checkExpr string
		var roles []string
		if err := policyRows.Scan(&schema, &table, &name, &permissive, &roles, &cmd, &usingExpr, &checkExpr); err != nil {
			return nil, err
		}
		k := key{schema, table}
		info, ok := infos[k]
		if !ok {
			continue // a policy on a table our first query didn't surface — shouldn't happen, but stay defensive
		}
		info.Policies = append(info.Policies, domain.RLSPolicy{
			Name:       name,
			Command:    cmd,
			Roles:      roles,
			Permissive: permissive == "PERMISSIVE",
			UsingExpr:  usingExpr,
			CheckExpr:  checkExpr,
		})
	}
	if err := policyRows.Err(); err != nil {
		return nil, err
	}

	result := make([]domain.RLSInfo, 0, len(order))
	for _, k := range order {
		result = append(result, *infos[k])
	}
	return result, nil
}
