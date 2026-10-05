package catalog_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/conn"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func findFunction(fns []domain.SecurityDefinerFunction, schema, name string) (domain.SecurityDefinerFunction, bool) {
	for _, f := range fns {
		if f.Object.Schema == schema && f.Object.Name == name {
			return f, true
		}
	}
	return domain.SecurityDefinerFunction{}, false
}

func listSecurityDefinerFunctions(t *testing.T, schemaFilter string, includeSystem bool) []domain.SecurityDefinerFunction {
	t.Helper()

	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	var fns []domain.SecurityDefinerFunction
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		r := catalog.NewFunctionReader(tx)
		var qerr error
		fns, qerr = r.ListSecurityDefinerFunctions(ctx, schemaFilter, includeSystem)
		return qerr
	})
	require.NoError(t, err)
	return fns
}

func TestFunctionReader_ListSecurityDefinerFunctions(t *testing.T) {
	t.Run("only SECURITY DEFINER functions are returned", func(t *testing.T) {
		fns := listSecurityDefinerFunctions(t, "app", false)

		_, ok := findFunction(fns, "app", "widget_count")
		assert.False(t, ok, "a normal function must not be returned")

		_, ok = findFunction(fns, "app", "purge_widgets")
		assert.True(t, ok, "app.purge_widgets is SECURITY DEFINER and should be returned")
	})

	t.Run("a NULL proacl expands to the default PUBLIC EXECUTE grant", func(t *testing.T) {
		fns := listSecurityDefinerFunctions(t, "app", false)
		purge, ok := findFunction(fns, "app", "purge_widgets")
		require.True(t, ok)

		pub, ok := findACLEntry(purge.Object.ACL, "")
		require.True(t, ok, "expected a PUBLIC entry: functions are executable by PUBLIC by default")
		assert.Contains(t, pub.Privileges, "EXECUTE")
	})

	t.Run("superuser owner, unpinned search_path", func(t *testing.T) {
		fns := listSecurityDefinerFunctions(t, "app", false)
		purge, ok := findFunction(fns, "app", "purge_widgets")
		require.True(t, ok)

		assert.True(t, purge.OwnerSuperuser)
		assert.False(t, purge.PinnedSearchPath)
		assert.False(t, purge.IsProcedure)
		assert.Equal(t, domain.KindFunction, purge.Object.Kind)
		assert.Contains(t, purge.Signature, "purge_widgets()")
	})

	t.Run("explicit grants replace the PUBLIC default", func(t *testing.T) {
		fns := listSecurityDefinerFunctions(t, "app", false)
		rotate, ok := findFunction(fns, "app", "rotate_secret")
		require.True(t, ok)

		_, ok = findACLEntry(rotate.Object.ACL, "")
		assert.False(t, ok, "PUBLIC was revoked, so there should be no PUBLIC entry")

		reader, ok := findACLEntry(rotate.Object.ACL, "app_reader")
		require.True(t, ok)
		assert.Contains(t, reader.Privileges, "EXECUTE")

		assert.Equal(t, "app_admin", rotate.Object.Owner)
		assert.False(t, rotate.OwnerSuperuser)
		assert.True(t, rotate.PinnedSearchPath)
	})
}
