package catalog_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/conn"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func listDefaultACLs(t *testing.T) []catalog.DefaultACLEntry {
	t.Helper()

	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	var entries []catalog.DefaultACLEntry
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		d := catalog.NewDefaultACLReader(tx)
		var qerr error
		entries, qerr = d.ListDefaultACLs(ctx)
		return qerr
	})
	require.NoError(t, err)
	return entries
}

func findDefaultACL(entries []catalog.DefaultACLEntry, role, schema string) (catalog.DefaultACLEntry, bool) {
	for _, e := range entries {
		if e.Role == role && e.Schema == schema {
			return e, true
		}
	}
	return catalog.DefaultACLEntry{}, false
}

func TestDefaultACLReader_ListDefaultACLs(t *testing.T) {
	entries := listDefaultACLs(t)
	require.NotEmpty(t, entries)

	t.Run("a schema-scoped default ACL reports the correct Schema", func(t *testing.T) {
		entry, ok := findDefaultACL(entries, "app_admin", "app")
		require.True(t, ok, "expected a schema-scoped default ACL for app_admin in schema app")
		require.Equal(t, domain.KindTable, entry.ObjectKind)

		readerEntry, ok := findACLEntry(entry.ACL, "app_reader")
		require.True(t, ok)
		require.Contains(t, readerEntry.Privileges, "SELECT")
	})

	t.Run("a database-wide default ACL (no namespace) reports Schema == \"\"", func(t *testing.T) {
		entry, ok := findDefaultACL(entries, "app_admin", "")
		require.True(t, ok, "expected a database-wide default ACL for app_admin")
		require.Equal(t, domain.KindTable, entry.ObjectKind)

		readerEntry, ok := findACLEntry(entry.ACL, "app_reader")
		require.True(t, ok)
		require.Contains(t, readerEntry.Privileges, "SELECT")
	})

	t.Run("defaclobjtype maps to the right domain.ObjectKind", func(t *testing.T) {
		for _, e := range entries {
			require.NotEmpty(t, string(e.ObjectKind))
		}
	})
}
