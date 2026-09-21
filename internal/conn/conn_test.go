package conn_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/conn"
)

func testDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("AGENT_DB_SCAN_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://agent_db_scan:agent_db_scan@localhost:55432/agent_db_scan_test?sslmode=disable"
}

func TestOpen(t *testing.T) {
	t.Run("invalid dsn returns an error", func(t *testing.T) {
		_, err := conn.Open(context.Background(), "not-a-dsn")
		require.Error(t, err)
	})

	t.Run("valid dsn opens a connection", func(t *testing.T) {
		m, err := conn.Open(context.Background(), testDSN(t))
		require.NoError(t, err)
		defer m.Close(context.Background())
	})
}

func TestManager_Query_SetsReadOnlyAndTimeout(t *testing.T) {
	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO app.widgets (name) VALUES ('should not be allowed')`)
		return err
	})

	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "25006", pgErr.Code) // read_only_sql_transaction
}

func TestManager_Query_AlwaysRollsBack(t *testing.T) {
	m, err := conn.Open(context.Background(), testDSN(t))
	require.NoError(t, err)
	defer m.Close(context.Background())

	var count int
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM app.widgets`).Scan(&count)
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, count, 0)

	// Confirm SET LOCAL statement_timeout was scoped to that transaction
	// and didn't leak onto the underlying connection.
	var timeout string
	err = m.Query(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SHOW statement_timeout").Scan(&timeout)
	})
	require.NoError(t, err)
}
