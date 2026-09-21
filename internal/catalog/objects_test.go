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

func findObject(objects []domain.DBObject, schema, name string) (domain.DBObject, bool) {
	for _, o := range objects {
		if o.Schema == schema && o.Name == name {
			return o, true
		}
	}
	return domain.DBObject{}, false
}

func findACLEntry(acl []domain.ACLEntry, grantee string) (domain.ACLEntry, bool) {
	for _, e := range acl {
		if e.Grantee == grantee {
			return e, true
		}
	}
	return domain.ACLEntry{}, false
}

func listObjects(t *testing.T, schemaFilter string, includeSystem bool) []domain.DBObject {
	t.Helper()

	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	var objects []domain.DBObject
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		r := catalog.NewObjectReader(tx)
		var qerr error
		objects, qerr = r.ListObjects(ctx, schemaFilter, includeSystem)
		return qerr
	})
	require.NoError(t, err)
	return objects
}

func TestObjectReader_ListObjects(t *testing.T) {
	t.Run("no filter returns objects across all schemas", func(t *testing.T) {
		objects := listObjects(t, "", false)
		require.NotEmpty(t, objects)

		_, ok := findObject(objects, "app", "widgets")
		require.True(t, ok, "app.widgets should be present with no filter")
	})

	t.Run("schema filter restricts to matching namespace", func(t *testing.T) {
		objects := listObjects(t, "app", false)
		require.NotEmpty(t, objects)

		for _, o := range objects {
			require.Equal(t, "app", o.Schema)
		}

		_, ok := findObject(objects, "app", "widgets")
		require.True(t, ok, "app.widgets should be present when filtering to schema app")
	})

	t.Run("relacl is parsed into ACLEntry per grantee, including PUBLIC", func(t *testing.T) {
		objects := listObjects(t, "app", false)
		widgets, ok := findObject(objects, "app", "widgets")
		require.True(t, ok)

		pub, ok := findACLEntry(widgets.ACL, "")
		require.True(t, ok, "expected a PUBLIC (empty grantee) entry on app.widgets")
		require.Contains(t, pub.Privileges, "SELECT")

		reader, ok := findACLEntry(widgets.ACL, "app_reader")
		require.True(t, ok, "expected an app_reader entry on app.widgets")
		require.Contains(t, reader.Privileges, "SELECT")

		writer, ok := findACLEntry(widgets.ACL, "app_writer")
		require.True(t, ok, "expected an app_writer entry on app.widgets")
		require.Contains(t, writer.Privileges, "SELECT")
		require.Contains(t, writer.Privileges, "INSERT")
		require.Contains(t, writer.Privileges, "UPDATE")
		require.Contains(t, writer.Privileges, "DELETE")
	})

	t.Run("a NULL relacl (owner-only default) yields an empty ACL, not an error", func(t *testing.T) {
		objects := listObjects(t, "app", false)
		secrets, ok := findObject(objects, "app", "secrets")
		require.True(t, ok)

		require.Empty(t, secrets.ACL)
		require.Equal(t, "app_admin", secrets.Owner)
	})

	t.Run("system schemas are excluded by default when no schema filter is given", func(t *testing.T) {
		objects := listObjects(t, "", false)
		for _, o := range objects {
			assert.NotEqual(t, "pg_catalog", o.Schema)
			assert.NotEqual(t, "information_schema", o.Schema)
		}
		// app.widgets should still be present — only system schemas are excluded
		_, ok := findObject(objects, "app", "widgets")
		require.True(t, ok)
	})

	t.Run("includeSystem=true surfaces pg_catalog objects", func(t *testing.T) {
		objects := listObjects(t, "pg_catalog", true)
		assert.NotEmpty(t, objects, "explicitly requesting pg_catalog with includeSystem=true should return system objects")
	})
}
