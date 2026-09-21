package classify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/classify"
	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func accessEntry(level domain.AccessLevel, schema, name string) domain.EffectiveAccess {
	return domain.EffectiveAccess{
		Object: domain.DBObject{Schema: schema, Name: name, Kind: domain.KindTable},
		Level:  level,
	}
}

func TestClassifier_Classify(t *testing.T) {
	c := classify.NewClassifier()

	t.Run("a role named readonly_* with Write access produces a warning", func(t *testing.T) {
		access := []domain.EffectiveAccess{
			accessEntry(domain.AccessWrite, "app", "widgets"),
		}

		got, warnings, err := c.Classify(access, "app_readonly_service")
		require.NoError(t, err)
		require.NotEmpty(t, warnings, "a readonly-named role with Write access should produce a warning")
		assert.Contains(t, warnings[0], "app_readonly_service")
		assert.Contains(t, warnings[0], "app.widgets")
		assert.Equal(t, access, got, "Classify should not alter the access it was given")
	})

	t.Run("a role name that matches its actual access produces no warning", func(t *testing.T) {
		access := []domain.EffectiveAccess{
			accessEntry(domain.AccessRead, "app", "widgets"),
		}

		_, warnings, err := c.Classify(access, "app_readonly_service")
		require.NoError(t, err)
		assert.Empty(t, warnings)
	})

	t.Run("a role name with no recognized naming convention produces no warning, regardless of access", func(t *testing.T) {
		access := []domain.EffectiveAccess{
			accessEntry(domain.AccessSuperuserEquivalent, "app", "secrets"),
		}

		_, warnings, err := c.Classify(access, "app_service")
		require.NoError(t, err)
		assert.Empty(t, warnings, "a name with no ceiling implies nothing to violate")
	})

	t.Run("a writer-named role with Admin access produces a warning", func(t *testing.T) {
		access := []domain.EffectiveAccess{
			accessEntry(domain.AccessAdmin, "app", "widgets"),
		}

		_, warnings, err := c.Classify(access, "app_writer")
		require.NoError(t, err)
		require.NotEmpty(t, warnings)
		assert.Contains(t, warnings[0], "app_writer")
	})
}
