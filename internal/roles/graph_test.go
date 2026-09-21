package roles_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/roles"
)

func TestGraph_Resolve(t *testing.T) {
	tests := []struct {
		name    string
		roles   []domain.Role
		login   string
		wantSet []string
	}{
		{
			name: "a role with no memberships resolves to just itself",
			roles: []domain.Role{
				{Name: "solo", Inherit: true, MemberOf: nil},
			},
			login:   "solo",
			wantSet: []string{"solo"},
		},
		{
			name: "an INHERIT role transitively picks up every ancestor's grants",
			// app_service -> app_writer -> app_reader, all three should
			// appear in the resolved set.
			roles: []domain.Role{
				{Name: "app_service", Inherit: true, MemberOf: []string{"app_writer"}},
				{Name: "app_writer", Inherit: true, MemberOf: []string{"app_reader"}},
				{Name: "app_reader", Inherit: true, MemberOf: nil},
			},
			login:   "app_service",
			wantSet: []string{"app_service", "app_writer", "app_reader"},
		},
		{
			name: "a NOINHERIT role's memberships do not contribute access",
			// app_noinherit -> app_admin should NOT pull app_admin into
			// the resolved set, even though the membership row exists.
			roles: []domain.Role{
				{Name: "app_noinherit", Inherit: false, MemberOf: []string{"app_admin"}},
				{Name: "app_admin", Inherit: true, MemberOf: nil},
			},
			login:   "app_noinherit",
			wantSet: []string{"app_noinherit"},
		},
		{
			name: "a cycle in the membership graph does not infinite-loop",
			roles: []domain.Role{
				{Name: "a", Inherit: true, MemberOf: []string{"b"}},
				{Name: "b", Inherit: true, MemberOf: []string{"a"}},
			},
			login:   "a",
			wantSet: []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := roles.BuildGraph(tt.roles)
			got, err := g.Resolve(tt.login)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.wantSet, got)
		})
	}
}
