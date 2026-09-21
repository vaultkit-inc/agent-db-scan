// Package roles builds the Role Graph: given the flat set of roles and
// direct memberships read by internal/catalog, it recursively resolves the
// full set of roles a login effectively has — respecting rolinherit, which
// stops the walk at any role that doesn't automatically use its memberships.
package roles

import (
	"fmt"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// Graph is a resolved membership graph over a fixed set of roles.
type Graph struct {
	byName map[string]domain.Role
}

// BuildGraph indexes all into a Graph for repeated Resolve calls.
func BuildGraph(all []domain.Role) *Graph {
	byName := make(map[string]domain.Role, len(all))
	for _, r := range all {
		byName[r.Name] = r
	}
	return &Graph{byName: byName}
}

// Resolve returns the full set of role names that login effectively has:
// login itself, plus every role reachable by walking MemberOf edges, but
// only descending through a role if the role doing the inheriting has
// rolinherit = true. A NOINHERIT role's memberships are real (SET ROLE can
// still reach them) but don't confer automatic access, so the walk must
// stop there rather than silently granting it.
func (g *Graph) Resolve(login string) ([]string, error) {
	start, ok := g.byName[login]
	if !ok {
		return nil, fmt.Errorf("role %q not found", login)
	}

	visited := map[string]bool{login: true}
	result := []string{login}

	queue := []domain.Role{start}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if !current.Inherit {
			continue // this role doesn't auto-use its own memberships; stop the walk here
		}

		for _, groupName := range current.MemberOf {
			if visited[groupName] {
				continue // cycle guard, also avoids re-processing a role reached two ways
			}
			visited[groupName] = true
			result = append(result, groupName)

			group, ok := g.byName[groupName]
			if !ok {
				continue // referenced role not in our index — shouldn't happen, but stay defensive
			}
			queue = append(queue, group)
		}
	}

	return result, nil
}
