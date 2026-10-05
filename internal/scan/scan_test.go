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

// roleDSN connects as one of the fixture's LOGIN roles (whose password is
// its name), overridable via envVar.
func roleDSN(t *testing.T, envVar, role string) string {
	t.Helper()
	if dsn := os.Getenv(envVar); dsn != "" {
		return dsn
	}
	return "postgres://" + role + ":" + role + "@localhost:55432/agent_db_scan_test?sslmode=disable"
}

func findAccess(access []domain.EffectiveAccess, schema, name string) (domain.EffectiveAccess, bool) {
	for _, a := range access {
		if a.Object.Schema == schema && a.Object.Name == name {
			return a, true
		}
	}
	return domain.EffectiveAccess{}, false
}

func findIndirect(paths []domain.IndirectWritePath, schema, name string) (domain.IndirectWritePath, bool) {
	for _, p := range paths {
		if p.Function.Object.Schema == schema && p.Function.Object.Name == name {
			return p, true
		}
	}
	return domain.IndirectWritePath{}, false
}

func TestScan(t *testing.T) {
	t.Run("end-to-end scan against docker-compose fixture returns a populated Report", func(t *testing.T) {
		rep, err := scan.Scan(context.Background(), testDSN(t), scan.Options{})
		require.NoError(t, err)
		require.NotNil(t, rep)

		assert.Equal(t, "agent_db_scan", rep.Login)
		assert.NotEmpty(t, rep.Access, "scanning as the superuser should still return access entries for every object")
		assert.Empty(t, rep.IndirectWritePaths, "a superuser has no *indirect* access: it already has everything")
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

	t.Run("a login inheriting the owning role is admin via ownership", func(t *testing.T) {
		dsn := roleDSN(t, "AGENT_DB_SCAN_TEST_APP_OWNER_MEMBER_DSN", "app_owner_member")
		rep, err := scan.Scan(context.Background(), dsn, scan.Options{SchemaFilter: "app"})
		require.NoError(t, err)

		assert.Equal(t, "app_owner_member", rep.Login)

		secrets, ok := findAccess(rep.Access, "app", "secrets")
		require.True(t, ok, "app_owner_member inherits app_admin, which owns app.secrets")
		assert.Equal(t, domain.AccessAdmin, secrets.Level)
		require.Len(t, secrets.Sources, 1)
		assert.Equal(t, "ownership", secrets.Sources[0].Kind)
		assert.Equal(t, "app_admin", secrets.Sources[0].Role)
		assert.True(t, secrets.Sources[0].Inherited)
	})

	t.Run("a NOINHERIT member of the owning role is not reported as owner", func(t *testing.T) {
		dsn := roleDSN(t, "AGENT_DB_SCAN_TEST_APP_NOINHERIT_DSN", "app_noinherit")
		rep, err := scan.Scan(context.Background(), dsn, scan.Options{SchemaFilter: "app"})
		require.NoError(t, err)

		assert.Equal(t, "app_noinherit", rep.Login)

		if secrets, ok := findAccess(rep.Access, "app", "secrets"); ok {
			for _, s := range secrets.Sources {
				assert.NotEqual(t, "ownership", s.Kind, "NOINHERIT must block app_admin's owner rights")
			}
			assert.NotEqual(t, domain.AccessAdmin, secrets.Level)
		}
	})

		t.Run("a login with no table writes still reports indirect write paths", func(t *testing.T) {
		dsn := roleDSN(t, "AGENT_DB_SCAN_TEST_AGENT_RO_DSN", "agent_ro")
		rep, err := scan.Scan(context.Background(), dsn, scan.Options{SchemaFilter: "app"})
		require.NoError(t, err)

		assert.Equal(t, "agent_ro", rep.Login)

		// The premise: judged by table privileges alone, agent_ro is read-only.
		for _, a := range rep.Access {
			assert.LessOrEqual(t,
				domain.AccessLevelRank[a.Level], domain.AccessLevelRank[domain.AccessRead],
				"agent_ro should have no direct write access, but %s.%s is %s",
				a.Object.Schema, a.Object.Name, a.Level,
			)
		}

		// The finding: it can still write through SECURITY DEFINER functions.
		require.Len(t, rep.IndirectWritePaths, 2)

		purge, ok := findIndirect(rep.IndirectWritePaths, "app", "purge_widgets")
		require.True(t, ok, "purge_widgets is executable via the default PUBLIC grant")
		assert.Equal(t, domain.AccessSuperuserEquivalent, purge.Level)
		assert.Equal(t, "public", purge.Sources[0].Kind)
		assert.False(t, purge.Function.PinnedSearchPath)

		rotate, ok := findIndirect(rep.IndirectWritePaths, "app", "rotate_secret")
		require.True(t, ok, "rotate_secret is executable via inherited app_reader")
		assert.Equal(t, domain.AccessWrite, rotate.Level)
		assert.Equal(t, "inherited", rotate.Sources[0].Kind)
		assert.Equal(t, "app_reader", rotate.Sources[0].Role)
	})
}
