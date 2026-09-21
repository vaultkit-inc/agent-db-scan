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

func listRLS(t *testing.T) []domain.RLSInfo {
	t.Helper()

	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	var infos []domain.RLSInfo
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		r := catalog.NewRLSReader(tx)
		var qerr error
		infos, qerr = r.ListRLS(ctx)
		return qerr
	})
	require.NoError(t, err)
	return infos
}

func findRLSInfo(infos []domain.RLSInfo, schema, table string) (domain.RLSInfo, bool) {
	for _, i := range infos {
		if i.Schema == schema && i.Table == table {
			return i, true
		}
	}
	return domain.RLSInfo{}, false
}

func TestRLSReader_ListRLS(t *testing.T) {
	infos := listRLS(t)
	require.NotEmpty(t, infos)

	t.Run("a table with RLS enabled and one policy is reported correctly", func(t *testing.T) {
		secrets, ok := findRLSInfo(infos, "app", "secrets")
		require.True(t, ok)
		require.True(t, secrets.Enabled)
		require.False(t, secrets.Forced)
		require.Len(t, secrets.Policies, 1)

		policy := secrets.Policies[0]
		require.Equal(t, "secrets_owner_only", policy.Name)
		require.True(t, policy.Permissive)
		require.Contains(t, policy.UsingExpr, "app_admin")
	})

	t.Run("FORCE ROW LEVEL SECURITY sets Forced=true", func(t *testing.T) {
		auditLog, ok := findRLSInfo(infos, "app", "audit_log")
		require.True(t, ok)
		require.True(t, auditLog.Enabled)
		require.True(t, auditLog.Forced)
		require.Len(t, auditLog.Policies, 1)
	})

	t.Run("a table with no RLS and no policies is omitted", func(t *testing.T) {
		_, ok := findRLSInfo(infos, "app", "widgets")
		require.False(t, ok, "app.widgets has no RLS and should not appear in ListRLS results")
	})
}
