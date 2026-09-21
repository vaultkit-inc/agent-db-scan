package scan_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/scan"
)

// testDSN mirrors the helper used in internal/catalog's tests — each _test
// package needs its own copy since Go doesn't share unexported helpers
// across package boundaries, even between two _test packages for the same
// module.
func testDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("AGENT_DB_SCAN_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://agent_db_scan:agent_db_scan@localhost:55432/agent_db_scan_test?sslmode=disable"
}

// appServiceDSN connects as app_service instead of the superuser — this is
// what actually exercises real ACL-based resolution end-to-end, since the
// superuser DSN short-circuits through Resolve's superuser path and never
// touches the ACL-walking logic at all.
func appServiceDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("AGENT_DB_SCAN_TEST_APP_SERVICE_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://app_service:app_service@localhost:55432/agent_db_scan_test?sslmode=disable"
}

func findAccess(access []domain.EffectiveAccess, schema, name string) (domain.EffectiveAccess, bool) {
	for _, a := range access {
		if a.Object.Schema == schema && a.Object.Name == name {
			return a, true
		}
	}
	return domain.EffectiveAccess{}, false
}

func TestScan(t *testing.T) {
	t.Run("end-to-end scan against docker-compose fixture returns a populated Report", func(t *testing.T) {
		rep, err := scan.Scan(context.Background(), testDSN(t), scan.Options{})
		require.NoError(t, err)
		require.NotNil(t, rep)

		assert.Equal(t, "agent_db_scan", rep.Login)
		assert.NotEmpty(t, rep.Access, "scanning as the superuser should still return access entries for every object")
	})

	t.Run("schema filter restricts Access to that schema's objects", func(t *testing.T) {
		rep, err := scan.Scan(context.Background(), testDSN(t), scan.Options{SchemaFilter: "app"})
		require.NoError(t, err)
		require.NotEmpty(t, rep.Access)

		for _, a := range rep.Access {
			assert.Equal(t, "app", a.Object.Schema)
		}
	})

	t.Run("an invalid dsn returns an error, not a panic", func(t *testing.T) {
		// If Scan panicked on a bad DSN, this subtest would fail with a
		// panic trace rather than completing — the test needing no
		// explicit recover() is itself part of what "not a panic" means.
		rep, err := scan.Scan(context.Background(), "not-a-dsn", scan.Options{})
		require.Error(t, err)
		assert.Nil(t, rep)
	})

	t.Run("scanning as a non-superuser login resolves real ACL-based access", func(t *testing.T) {
		rep, err := scan.Scan(context.Background(), appServiceDSN(t), scan.Options{SchemaFilter: "app"})
		require.NoError(t, err)

		assert.Equal(t, "app_service", rep.Login)

		widgets, ok := findAccess(rep.Access, "app", "widgets")
		require.True(t, ok, "app_service should have access to app.widgets via inherited app_writer grant")
		assert.Equal(t, domain.AccessWrite, widgets.Level)
	})
}
