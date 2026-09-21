package catalog_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/conn"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func testDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("AGENT_DB_SCAN_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://agent_db_scan:agent_db_scan@localhost:55432/agent_db_scan_test?sslmode=disable"
}

func findRole(roles []domain.Role, name string) (domain.Role, bool) {
	for _, r := range roles {
		if r.Name == name {
			return r, true
		}
	}
	return domain.Role{}, false
}

func listRoles(t *testing.T) []domain.Role {
	t.Helper()

	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	var roles []domain.Role
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		r := catalog.NewRoleReader(tx)
		var qerr error
		roles, qerr = r.ListRoles(ctx)
		return qerr
	})
	require.NoError(t, err)
	return roles
}

func TestRoleReader_ListRoles(t *testing.T) {
	roles := listRoles(t)
	require.NotEmpty(t, roles)

	t.Run("returns every role with rolinherit/rolsuper/rolcanlogin populated", func(t *testing.T) {
		service, ok := findRole(roles, "app_service")
		require.True(t, ok, "app_service should be present")
		require.True(t, service.CanLogin)
		require.True(t, service.Inherit)
		require.False(t, service.Superuser)
		require.False(t, service.BypassRLS)

		reader, ok := findRole(roles, "app_reader")
		require.True(t, ok, "app_reader should be present")
		require.False(t, reader.CanLogin)
	})

	t.Run("populates MemberOf from pg_auth_members", func(t *testing.T) {
		service, ok := findRole(roles, "app_service")
		require.True(t, ok)
		require.Contains(t, service.MemberOf, "app_writer")
		require.NotContains(t, service.MemberOf, "app_reader") // transitive, not direct — that's Graph's job

		writer, ok := findRole(roles, "app_writer")
		require.True(t, ok)
		require.Contains(t, writer.MemberOf, "app_reader")
	})

	t.Run("a NOINHERIT role is still listed, just flagged Inherit=false", func(t *testing.T) {
		noinherit, ok := findRole(roles, "app_noinherit")
		require.True(t, ok)
		require.False(t, noinherit.Inherit)
		require.Contains(t, noinherit.MemberOf, "app_admin") // membership exists even though it's dormant
	})
}
