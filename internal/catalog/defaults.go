package catalog

import (
	"context"
	"fmt"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// DefaultACLEntry mirrors one row of pg_default_acl: a standing grant that
// applies to objects a given role creates in the future, in a given schema
// (or database-wide if Schema is empty).
type DefaultACLEntry struct {
	Schema     string // "" means database-wide (defaclnamespace IS NULL)
	Role       string // defaclrole: whose future objects this applies to
	ObjectKind domain.ObjectKind
	ACL        []domain.ACLEntry
}

// DefaultACLReader reads pg_default_acl.
type DefaultACLReader struct {
	exec Executor
}

// NewDefaultACLReader constructs a DefaultACLReader bound to exec.
func NewDefaultACLReader(exec Executor) *DefaultACLReader {
	return &DefaultACLReader{exec: exec}
}

// defaclObjTypeToKind maps pg_default_acl.defaclobjtype to domain.ObjectKind.
// "T" (types) has no equivalent in domain.ObjectKind yet, so rows with that
// type are skipped rather than mismapped.
var defaclObjTypeToKind = map[string]domain.ObjectKind{
	"r": domain.KindTable,
	"S": domain.KindSequence,
	"f": domain.KindFunction,
}

// ListDefaultACLs returns every default ACL visible to the current
// connection. These matter because they grant access to objects that don't
// exist yet at scan time (e.g. "any table app_admin creates in schema app
// will be readable by app_reader") — the resolver must surface these as
// forward-looking access, not silently drop them because ListObjects never
// saw a matching object.
func (d *DefaultACLReader) ListDefaultACLs(ctx context.Context) ([]DefaultACLEntry, error) {
	rows, err := d.exec.Query(ctx, `
		SELECT
			r.rolname,
			n.nspname,
			a.defaclobjtype::text,
			a.defaclacl::text[]
		FROM pg_default_acl a
		JOIN pg_roles r ON r.oid = a.defaclrole
		LEFT JOIN pg_namespace n ON n.oid = a.defaclnamespace
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []DefaultACLEntry
	for rows.Next() {
		var (
			role, objType string
			schema        *string // nullable: defaclnamespace can be NULL (database-wide)
			aclText       []string
		)
		if err := rows.Scan(&role, &schema, &objType, &aclText); err != nil {
			return nil, err
		}

		kind, ok := defaclObjTypeToKind[objType]
		if !ok {
			continue // e.g. "T" (types) — no domain.ObjectKind equivalent yet
		}

		acl, err := parseACL(aclText)
		if err != nil {
			return nil, fmt.Errorf("parsing default acl for role %s: %w", role, err)
		}

		schemaVal := ""
		if schema != nil {
			schemaVal = *schema
		}

		entries = append(entries, DefaultACLEntry{
			Schema:     schemaVal,
			Role:       role,
			ObjectKind: kind,
			ACL:        acl,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
