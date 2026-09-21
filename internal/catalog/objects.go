package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// ObjectReader reads relations (tables, views, sequences, functions) from
// pg_class / pg_namespace, including their ACLs.
type ObjectReader struct {
	exec Executor
}

// NewObjectReader constructs an ObjectReader bound to exec.
func NewObjectReader(exec Executor) *ObjectReader {
	return &ObjectReader{exec: exec}
}

// relkindToKind maps pg_class.relkind to domain.ObjectKind. Functions live
// in pg_proc, not pg_class, so they're deliberately not covered here — a
// KindFunction object would need its own reader against pg_proc.
var relkindToKind = map[string]domain.ObjectKind{
	"r": domain.KindTable,
	"v": domain.KindView,
	"m": domain.KindMaterializedView,
	"S": domain.KindSequence,
	"f": domain.KindForeignTable,
}

// aclPrivilegeNames maps a single aclitem privilege letter to its SQL name.
var aclPrivilegeNames = map[byte]string{
	'r': "SELECT",
	'a': "INSERT",
	'w': "UPDATE",
	'd': "DELETE",
	'D': "TRUNCATE",
	'x': "REFERENCES",
	't': "TRIGGER",
	'X': "EXECUTE",
	'U': "USAGE",
	'C': "CREATE",
	'c': "CONNECT",
	'T': "TEMPORARY",
}

// ListObjects returns every table/view/materialized view/sequence/foreign
// table visible to the current connection, optionally filtered to a single
// schema (pass "" for no filter). ACL is parsed from relacl into
// domain.ACLEntry.
//
// System schemas (pg_catalog, information_schema, pg_toast*, pg_temp*) are
// excluded by default, since Postgres grants PUBLIC read on nearly all of
// them and they bury real findings. They are included when includeSystem is
// true, or when schemaFilter explicitly names one.
func (o *ObjectReader) ListObjects(ctx context.Context, schemaFilter string, includeSystem bool) ([]domain.DBObject, error) {
	rows, err := o.exec.Query(ctx, `
    SELECT
        n.nspname,
        c.relname,
        c.relkind::text,
        c.relowner::regrole::text,
        c.relacl::text[],
        c.relrowsecurity,
        c.relforcerowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f')
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

	var objects []domain.DBObject
	for rows.Next() {
		var (
			schema, name, relkind, owner string
			aclText                      []string
			rlsEnabled, rlsForced        bool
		)
		if err := rows.Scan(&schema, &name, &relkind, &owner, &aclText, &rlsEnabled, &rlsForced); err != nil {
			return nil, err
		}

		kind, ok := relkindToKind[relkind]
		if !ok {
			continue // shouldn't happen given the WHERE clause, but skip rather than fail
		}

		acl, err := parseACL(aclText)
		if err != nil {
			return nil, fmt.Errorf("parsing acl for %s.%s: %w", schema, name, err)
		}

		objects = append(objects, domain.DBObject{
			Schema:     schema,
			Name:       name,
			Kind:       kind,
			Owner:      owner,
			ACL:        acl,
			RLSEnabled: rlsEnabled,
			RLSForced:  rlsForced,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return objects, nil
}

// parseACL parses a Postgres aclitem[] (cast to text[] in the query) into
// ACLEntry values. A NULL relacl decodes to a nil/empty aclText, which
// correctly yields an empty, non-error result — that's the "owner-only
// default" case, not a parse failure.
//
// Each element looks like "grantee=privileges/grantor", e.g.
// "app_reader=r/app_admin", or "=r/app_admin" for a PUBLIC grant (empty
// grantee before the '=').
func parseACL(aclText []string) ([]domain.ACLEntry, error) {
	entries := make([]domain.ACLEntry, 0, len(aclText))
	for _, item := range aclText {
		eq := strings.Index(item, "=")
		slash := strings.LastIndex(item, "/")
		if eq == -1 || slash == -1 || slash < eq {
			return nil, fmt.Errorf("malformed aclitem: %q", item)
		}

		grantee := item[:eq]
		privChars := item[eq+1 : slash]
		grantor := item[slash+1:]

		var privileges []string
		grantOption := false
		for i := 0; i < len(privChars); i++ {
			c := privChars[i]
			if c == '*' {
				grantOption = true
				continue
			}
			if name, ok := aclPrivilegeNames[c]; ok {
				privileges = append(privileges, name)
			}
		}

		entries = append(entries, domain.ACLEntry{
			Grantee:     grantee, // "" means PUBLIC
			Privileges:  privileges,
			GrantedBy:   grantor,
			GrantOption: grantOption,
		})
	}
	return entries, nil
}
