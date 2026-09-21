// Package privileges is the Privilege Resolver: it combines everything the
// catalog and role graph packages read — direct grants, inherited grants,
// PUBLIC grants, ownership, and default privileges — into one
// domain.EffectiveAccess per object, with a human-readable explanation of
// why the access exists.
package privileges

import (
	"context"
	"sort"

	"github.com/vaultkit-inc/agent-db-scan/internal/catalog"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// Input bundles everything the resolver needs. It intentionally takes
// already-read data rather than an Executor — the resolver does no I/O.
type Input struct {
	Login          string
	IsSuperuser    bool     // true if Login (or any role it inherits) is a Postgres superuser
	EffectiveRoles []string // from roles.Graph.Resolve(Login); includes Login itself
	Objects        []domain.DBObject
	DefaultACLs    []catalog.DefaultACLEntry
	RLS            []domain.RLSInfo
}

// Resolver turns an Input into a slice of domain.EffectiveAccess.
type Resolver struct{}

// NewResolver constructs a Resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

// ownerPrivileges is the implicit privilege set an object's owner has,
// regardless of any explicit ACL entry.
var ownerPrivileges = map[domain.ObjectKind][]string{
	domain.KindTable:            {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"},
	domain.KindView:             {"SELECT", "INSERT", "UPDATE", "DELETE"},
	domain.KindMaterializedView: {"SELECT"},
	domain.KindSequence:         {"SELECT", "UPDATE", "USAGE"},
	domain.KindFunction:         {"EXECUTE"},
	domain.KindForeignTable:     {"SELECT", "INSERT", "UPDATE", "DELETE"},
}

// Resolve computes one EffectiveAccess per object in in.Objects that the
// login has any access to. Objects with no applicable grant are omitted —
// this reports access, not the absence of it.
//
// Default privileges (in.DefaultACLs) are deliberately NOT handled here —
// they describe access to objects that don't exist yet, which doesn't fit
// EffectiveAccess's Object field. That needs its own method and a new
// domain type once we design it — see the note below the code.
func (r *Resolver) Resolve(ctx context.Context, in Input) ([]domain.EffectiveAccess, error) {
	if in.IsSuperuser {
		return r.resolveSuperuser(in), nil
	}

	rlsByTable := make(map[string]domain.RLSInfo, len(in.RLS))
	for _, info := range in.RLS {
		rlsByTable[info.Schema+"."+info.Table] = info
	}

	effectiveRoleSet := make(map[string]bool, len(in.EffectiveRoles))
	for _, role := range in.EffectiveRoles {
		effectiveRoleSet[role] = true
	}

	var results []domain.EffectiveAccess

	for _, obj := range in.Objects {
		var sources []domain.AccessSource
		var privileges []string
		hasGrantOption := false
		isOwner := obj.Owner == in.Login

		if isOwner {
			privs := ownerPrivileges[obj.Kind]
			sources = append(sources, domain.AccessSource{
				Role:       in.Login,
				Privileges: privs,
				Kind:       "ownership",
			})
			privileges = unionPrivileges(privileges, privs)
		}

		for _, entry := range obj.ACL {
			kind, matched := classifyGrantee(entry.Grantee, in.Login, effectiveRoleSet)
			if !matched {
				continue
			}
			role := entry.Grantee
			if kind == "public" {
				role = "PUBLIC"
			}
			sources = append(sources, domain.AccessSource{
				Role:       role,
				Privileges: entry.Privileges,
				Kind:       kind,
			})
			privileges = unionPrivileges(privileges, entry.Privileges)
			if entry.GrantOption {
				hasGrantOption = true
			}
		}

		if len(sources) == 0 {
			continue // no access at all — omit rather than report AccessNone
		}

		sort.Strings(privileges)

		var rls *domain.RLSInfo
		if info, ok := rlsByTable[obj.Schema+"."+obj.Name]; ok {
			rlsCopy := info
			rls = &rlsCopy
		}

		results = append(results, domain.EffectiveAccess{
			Object:     obj,
			Level:      accessLevelFor(obj.Kind, privileges, isOwner, hasGrantOption),
			Privileges: privileges,
			Sources:    sources,
			RLS:        rls,
		})
	}

	return results, nil
}

// ResolveFuture computes forward-looking access: default privileges
// (in.DefaultACLs) that will automatically apply to objects that don't
// exist yet. Unlike Resolve, there's no ownership or RLS concept here —
// neither applies to something that hasn't been created.
//
// If the login is a superuser, this returns nil: a superuser already
// has full access to everything, present and future, so there's
// nothing meaningful to report as a forward-looking *gain*.
func (r *Resolver) ResolveFuture(ctx context.Context, in Input) ([]domain.ForwardLookingAccess, error) {
	if in.IsSuperuser {
		return nil, nil
	}

	effectiveRoleSet := make(map[string]bool, len(in.EffectiveRoles))
	for _, role := range in.EffectiveRoles {
		effectiveRoleSet[role] = true
	}

	var results []domain.ForwardLookingAccess

	for _, def := range in.DefaultACLs {
		var sources []domain.AccessSource
		var privileges []string

		for _, entry := range def.ACL {
			kind, matched := classifyGrantee(entry.Grantee, in.Login, effectiveRoleSet)
			if !matched {
				continue
			}
			role := entry.Grantee
			if kind == "public" {
				role = "PUBLIC"
			}
			sources = append(sources, domain.AccessSource{
				Role:       role,
				Privileges: entry.Privileges,
				Kind:       kind,
			})
			privileges = unionPrivileges(privileges, entry.Privileges)
		}

		if len(sources) == 0 {
			continue
		}

		sort.Strings(privileges)

		results = append(results, domain.ForwardLookingAccess{
			Schema:      def.Schema,
			CreatorRole: def.Role,
			ObjectKind:  def.ObjectKind,
			Privileges:  privileges,
			Sources:     sources,
		})
	}

	return results, nil
}

// resolveSuperuser short-circuits: a superuser bypasses every ACL and RLS
// check Postgres has, so computing a "real" per-privilege breakdown would
// misrepresent restrictions that don't actually apply.
func (r *Resolver) resolveSuperuser(in Input) []domain.EffectiveAccess {
	results := make([]domain.EffectiveAccess, 0, len(in.Objects))
	for _, obj := range in.Objects {
		results = append(results, domain.EffectiveAccess{
			Object:     obj,
			Level:      domain.AccessSuperuserEquivalent,
			Privileges: []string{"ALL"},
			Sources: []domain.AccessSource{
				{Role: in.Login, Kind: "superuser"},
			},
			RLS: nil, // RLS doesn't apply to a superuser
		})
	}
	return results
}

// classifyGrantee determines whether an ACL entry's grantee applies to
// login, and if so, how.
func classifyGrantee(grantee, login string, effectiveRoles map[string]bool) (kind string, matched bool) {
	switch {
	case grantee == "":
		return "public", true
	case grantee == login:
		return "direct", true
	case effectiveRoles[grantee]:
		return "inherited", true
	default:
		return "", false
	}
}

// unionPrivileges merges add into existing, deduplicating.
func unionPrivileges(existing, add []string) []string {
	seen := make(map[string]bool, len(existing))
	for _, p := range existing {
		seen[p] = true
	}
	for _, p := range add {
		if !seen[p] {
			existing = append(existing, p)
			seen[p] = true
		}
	}
	return existing
}

// TODO: accessLevelFor silently returns AccessNone for any privilege
// string it doesn't recognize for a given kind. For a security scanner
// that's misleading — "None" should mean "verified no access," not
// "we don't know how to classify what we saw." Eventually this should
// distinguish those two cases explicitly (e.g. a separate
// Unclassified []string on EffectiveAccess, or a Warning) rather than
// collapsing unrecognized privileges into the same bucket as no access
// at all.
//
// accessLevelFor derives a coarse AccessLevel from a login's union of raw
// privileges on an object, classified per object kind.
//
//   - Ownership, or holding a grant option on anything, always implies
//     Admin — both mean the login can control the object or re-grant
//     access, regardless of which specific privileges are listed.
//   - Tables/views/foreign tables: TRUNCATE, REFERENCES and TRIGGER are
//     Admin (schema-shape/control-adjacent, not ordinary row DML);
//     INSERT/UPDATE/DELETE -> Write; SELECT -> Read.
//   - Sequences: UPDATE and USAGE (consuming/advancing) -> Write; SELECT -> Read.
//   - Functions: EXECUTE -> Write, conservatively, since the function's
//     side effects are unknown. The raw privilege is still reported in
//     EffectiveAccess.Privileges.
func accessLevelFor(
	kind domain.ObjectKind,
	privileges []string,
	isOwner bool,
	hasGrantOption bool,
) domain.AccessLevel {
	if isOwner || hasGrantOption {
		return domain.AccessAdmin
	}

	hasWrite, hasRead := false, false
	for _, p := range privileges {
		switch kind {
		case domain.KindTable, domain.KindView, domain.KindMaterializedView, domain.KindForeignTable:
			switch p {
			case "TRUNCATE", "REFERENCES", "TRIGGER":
				return domain.AccessAdmin
			case "INSERT", "UPDATE", "DELETE":
				hasWrite = true
			case "SELECT":
				hasRead = true
			}
		case domain.KindSequence:
			switch p {
			case "UPDATE", "USAGE":
				hasWrite = true
			case "SELECT":
				hasRead = true
			}
		case domain.KindFunction:
			if p == "EXECUTE" {
				hasWrite = true
			}
		}
	}

	switch {
	case hasWrite:
		return domain.AccessWrite
	case hasRead:
		return domain.AccessRead
	default:
		return domain.AccessNone
	}
}
