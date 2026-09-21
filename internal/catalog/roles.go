package catalog

import (
	"context"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// RoleReader reads role and membership info from pg_roles / pg_auth_members.
type RoleReader struct {
	exec Executor
}

// NewRoleReader constructs a RoleReader bound to exec.
func NewRoleReader(exec Executor) *RoleReader {
	return &RoleReader{exec: exec}
}

// ListRoles returns every role visible to the current connection, with
// MemberOf populated from direct pg_auth_members edges (not recursively
// resolved — that's internal/roles.Graph's job).
func (r *RoleReader) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.exec.Query(ctx, `
		SELECT oid, rolname, rolinherit, rolsuper, rolcanlogin, rolbypassrls
		FROM pg_roles
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byOID := make(map[uint32]*domain.Role)
	var order []uint32 // preserves query order for deterministic output

	for rows.Next() {
		var oid uint32
		var role domain.Role
		if err := rows.Scan(&oid, &role.Name, &role.Inherit, &role.Superuser, &role.CanLogin, &role.BypassRLS); err != nil {
			return nil, err
		}
		byOID[oid] = &role
		order = append(order, oid)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	memberRows, err := r.exec.Query(ctx, `
		SELECT roleid, member
		FROM pg_auth_members
	`)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()

	for memberRows.Next() {
		var roleID, memberID uint32
		if err := memberRows.Scan(&roleID, &memberID); err != nil {
			return nil, err
		}
		group, ok := byOID[roleID]
		if !ok {
			continue
		}
		member, ok := byOID[memberID]
		if !ok {
			continue
		}
		member.MemberOf = append(member.MemberOf, group.Name)
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}

	roles := make([]domain.Role, 0, len(order))
	for _, oid := range order {
		roles = append(roles, *byOID[oid])
	}
	return roles, nil
}
