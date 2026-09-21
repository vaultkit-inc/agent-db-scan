package privileges_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/privileges"
)

func widgetsObject(owner string, acl []domain.ACLEntry) domain.DBObject {
	return domain.DBObject{
		Schema: "app",
		Name:   "widgets",
		Kind:   domain.KindTable,
		Owner:  owner,
		ACL:    acl,
	}
}

func secretsObject(owner string) domain.DBObject {
	return domain.DBObject{
		Schema: "app",
		Name:   "secrets",
		Kind:   domain.KindTable,
		Owner:  owner,
	}
}

func findAccess(access []domain.EffectiveAccess, schema, name string) (domain.EffectiveAccess, bool) {
	for _, a := range access {
		if a.Object.Schema == schema && a.Object.Name == name {
			return a, true
		}
	}
	return domain.EffectiveAccess{}, false
}

func findSource(sources []domain.AccessSource, kind string) (domain.AccessSource, bool) {
	for _, s := range sources {
		if s.Kind == kind {
			return s, true
		}
	}
	return domain.AccessSource{}, false
}

func functionObject(owner string, acl []domain.ACLEntry) domain.DBObject {
	return domain.DBObject{
		Schema: "app",
		Name:   "calculate_invoice",
		Kind:   domain.KindFunction,
		Owner:  owner,
		ACL:    acl,
	}
}

func sequenceObject(owner string, acl []domain.ACLEntry) domain.DBObject {
	return domain.DBObject{
		Schema: "app",
		Name:   "orders_id_seq",
		Kind:   domain.KindSequence,
		Owner:  owner,
		ACL:    acl,
	}
}

func TestResolver_Resolve(t *testing.T) {
	r := privileges.NewResolver()

	t.Run("ownership grants full access regardless of ACL", func(t *testing.T) {
		obj := widgetsObject("app_admin", nil) // no ACL entries at all — ownership is the only path
		in := privileges.Input{
			Login:          "app_admin",
			EffectiveRoles: []string{"app_admin"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		entry := access[0]
		assert.Equal(t, domain.AccessAdmin, entry.Level)
		assert.Contains(t, entry.Privileges, "TRUNCATE") // only ownerPrivileges contributes this — proves the ownership path ran, not an ACL match
		source, ok := findSource(entry.Sources, "ownership")
		require.True(t, ok)
		assert.Equal(t, "app_admin", source.Role)
	})

	t.Run("a direct grant to the login is recorded as a direct source", func(t *testing.T) {
		obj := widgetsObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}},
		})
		in := privileges.Input{
			Login:          "app_writer",
			EffectiveRoles: []string{"app_writer"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		entry := access[0]
		assert.Equal(t, domain.AccessWrite, entry.Level)
		require.Len(t, entry.Sources, 1)
		assert.Equal(t, "direct", entry.Sources[0].Kind)
		assert.Equal(t, "app_writer", entry.Sources[0].Role)
	})

	t.Run("a grant to an inherited role is recorded with the role name in Sources", func(t *testing.T) {
		obj := widgetsObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}},
		})
		in := privileges.Input{
			Login:          "app_service",
			EffectiveRoles: []string{"app_service", "app_writer"}, // resolved via roles.Graph
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		source, ok := findSource(access[0].Sources, "inherited")
		require.True(t, ok, "expected an inherited source since app_service isn't granted directly")
		assert.Equal(t, "app_writer", source.Role)
	})

	t.Run("a PUBLIC grant is recorded distinctly from role-based grants", func(t *testing.T) {
		obj := widgetsObject("someone_else", []domain.ACLEntry{
			{Grantee: "", Privileges: []string{"SELECT"}}, // "" == PUBLIC, per catalog's aclitem parsing convention
		})
		in := privileges.Input{
			Login:          "random_login",
			EffectiveRoles: []string{"random_login"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		entry := access[0]
		assert.Equal(t, domain.AccessRead, entry.Level)
		require.Len(t, entry.Sources, 1)
		assert.Equal(t, "public", entry.Sources[0].Kind)
		assert.Equal(t, "PUBLIC", entry.Sources[0].Role)
	})

	t.Run("multiple sources for the same object are merged into one EffectiveAccess", func(t *testing.T) {
		obj := widgetsObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}},
			{Grantee: "", Privileges: []string{"SELECT"}}, // PUBLIC also grants SELECT
		})
		in := privileges.Input{
			Login:          "app_writer",
			EffectiveRoles: []string{"app_writer"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1, "one object should produce exactly one EffectiveAccess, not one per source")

		entry := access[0]
		assert.Len(t, entry.Sources, 2, "both the direct grant and the PUBLIC grant should be preserved as separate sources")
		_, hasDirect := findSource(entry.Sources, "direct")
		_, hasPublic := findSource(entry.Sources, "public")
		assert.True(t, hasDirect)
		assert.True(t, hasPublic)
	})

	t.Run("RLS-enabled objects report the restriction rather than overstating access", func(t *testing.T) {
		obj := secretsObject("app_admin")
		in := privileges.Input{
			Login:          "app_admin",
			EffectiveRoles: []string{"app_admin"},
			Objects:        []domain.DBObject{obj},
			RLS: []domain.RLSInfo{
				{
					Schema:  "app",
					Table:   "secrets",
					Enabled: true,
					Forced:  false,
					Policies: []domain.RLSPolicy{
						{Name: "secrets_owner_only", Command: "ALL", Permissive: true},
					},
				},
			},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)

		entry, ok := findAccess(access, "app", "secrets")
		require.True(t, ok)

		// Ownership still resolves to Admin — RLS is attached as separate
		// metadata, not folded into (or suppressing) the access level.
		assert.Equal(t, domain.AccessAdmin, entry.Level)

		require.NotNil(t, entry.RLS, "an RLS-enabled table should carry its RLS info on EffectiveAccess")
		assert.True(t, entry.RLS.Enabled)
		assert.False(t, entry.RLS.Forced)
		assert.Len(t, entry.RLS.Policies, 1)
	})

	t.Run("EXECUTE on a function is classified as Write, not None", func(t *testing.T) {
		obj := functionObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"EXECUTE"}},
		})
		in := privileges.Input{
			Login:          "app_writer",
			EffectiveRoles: []string{"app_writer"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		entry := access[0]
		assert.Equal(t, domain.AccessWrite, entry.Level)
		assert.Contains(t, entry.Privileges, "EXECUTE")
	})

	t.Run("USAGE on a sequence is classified as Write, not None", func(t *testing.T) {
		obj := sequenceObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"USAGE"}},
		})
		in := privileges.Input{
			Login:          "app_writer",
			EffectiveRoles: []string{"app_writer"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		entry := access[0]
		assert.Equal(t, domain.AccessWrite, entry.Level)
		assert.Contains(t, entry.Privileges, "USAGE")
	})

	t.Run("SELECT on a sequence is classified as Read", func(t *testing.T) {
		obj := sequenceObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_reader", Privileges: []string{"SELECT"}},
		})
		in := privileges.Input{
			Login:          "app_reader",
			EffectiveRoles: []string{"app_reader"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		assert.Equal(t, domain.AccessRead, access[0].Level)
	})

	t.Run("REFERENCES on a table (no other privileges, not the owner) is classified as Admin", func(t *testing.T) {
		obj := widgetsObject("someone_else", []domain.ACLEntry{
			{Grantee: "app_writer", Privileges: []string{"REFERENCES"}},
		})
		in := privileges.Input{
			Login:          "app_writer",
			EffectiveRoles: []string{"app_writer"},
			Objects:        []domain.DBObject{obj},
		}

		access, err := r.Resolve(context.Background(), in)
		require.NoError(t, err)
		require.Len(t, access, 1)

		assert.Equal(t, domain.AccessAdmin, access[0].Level)
	})
}

func TestResolver_ResolveFuture(t *testing.T) {
	defaultACL := func(schema string) []catalog.DefaultACLEntry {
		return []catalog.DefaultACLEntry{{
			Schema:     schema,
			Role:       "app_admin",
			ObjectKind: domain.KindTable,
			ACL:        []domain.ACLEntry{{Grantee: "app_reader", Privileges: []string{"SELECT"}}},
		}}
	}
	resolve := func(t *testing.T, login string, acls []catalog.DefaultACLEntry) []domain.ForwardLookingAccess {
		t.Helper()
		got, err := privileges.NewResolver().ResolveFuture(context.Background(), privileges.Input{
			Login:          login,
			EffectiveRoles: []string{login},
			DefaultACLs:    acls,
		})
		require.NoError(t, err)
		return got
	}

	t.Run("a default ACL granting the login surfaces as forward-looking access", func(t *testing.T) {
		got := resolve(t, "app_reader", defaultACL("app"))
		require.Len(t, got, 1)
		assert.Equal(t, "app_admin", got[0].CreatorRole)
		assert.Equal(t, "app", got[0].Schema)
		assert.Equal(t, domain.KindTable, got[0].ObjectKind)
		assert.Contains(t, got[0].Privileges, "SELECT")
		require.Len(t, got[0].Sources, 1)
		assert.Equal(t, "direct", got[0].Sources[0].Kind)
	})

	t.Run("a default ACL that doesn't apply to the login yields nothing", func(t *testing.T) {
		assert.Empty(t, resolve(t, "app_writer", defaultACL("app")))
	})

	t.Run("a database-wide default ACL keeps Schema empty", func(t *testing.T) {
		got := resolve(t, "app_reader", defaultACL(""))
		require.Len(t, got, 1)
		assert.Equal(t, "", got[0].Schema)
	})

	t.Run("a superuser gets no forward-looking access", func(t *testing.T) {
		got, err := privileges.NewResolver().ResolveFuture(context.Background(), privileges.Input{
			Login:       "postgres",
			IsSuperuser: true,
			DefaultACLs: defaultACL("app"),
		})
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}
