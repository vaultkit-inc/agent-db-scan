// Package classify is the Risk Classifier: it flags cases where a role's
// name implies less access than the role actually has — e.g. a role named
// "readonly_app" that can actually INSERT/UPDATE/DELETE. It does not
// compute AccessLevel itself; internal/privileges already resolved that
// fully before Classify ever sees the access slice.
package classify

import (
	"fmt"
	"strings"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// Classifier flags naming/access mismatches.
type Classifier struct{}

// NewClassifier constructs a Classifier.
func NewClassifier() *Classifier {
	return &Classifier{}
}

// namingCeilings maps a substring commonly found in a role name to the
// maximum AccessLevel that name implies. Checked in order; the first match
// wins. Names not matching any pattern here (including admin/superuser-
// sounding names) get no ceiling and produce no warning — there's no
// meaningful "too much access" to flag against a name that already implies
// broad access.
var namingCeilings = []struct {
	substr  string
	ceiling domain.AccessLevel
}{
	{"readonly", domain.AccessRead},
	{"reporting", domain.AccessRead},
	{"_ro", domain.AccessRead},
	{"writer", domain.AccessWrite},
	{"_rw", domain.AccessWrite},
}

// Classify compares roleName against access and returns warnings for any
// object where the actual access level exceeds what the name implies. It
// does not modify access — Level, Privileges, and Sources are already
// final by the time this runs.
func (c *Classifier) Classify(access []domain.EffectiveAccess, roleName string) ([]domain.EffectiveAccess, []string, error) {
	ceiling, hasCeiling := namingCeilingFor(roleName)
	if !hasCeiling {
		return access, nil, nil
	}

	var warnings []string
	for _, a := range access {
		if domain.AccessLevelRank[a.Level] > domain.AccessLevelRank[ceiling] {
			warnings = append(warnings, fmt.Sprintf(
				"role %q has %s access to %s.%s, but its name implies at most %s",
				roleName, a.Level, a.Object.Schema, a.Object.Name, ceiling,
			))
		}
	}

	return access, warnings, nil
}

// namingCeilingFor checks roleName (case-insensitively) against known
// naming conventions and returns the access level that name implies, if
// any pattern matches.
func namingCeilingFor(roleName string) (domain.AccessLevel, bool) {
	lower := strings.ToLower(roleName)
	for _, nc := range namingCeilings {
		if strings.Contains(lower, nc.substr) {
			return nc.ceiling, true
		}
	}
	return "", false
}
