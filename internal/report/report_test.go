package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
	"github.com/vaultkit-inc/agent-db-scan/internal/report"
)

func sampleReport() *domain.Report {
	return &domain.Report{
		Login:     "app_service",
		ScannedAt: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC),
		Access: []domain.EffectiveAccess{
			{
				Object:     domain.DBObject{Schema: "app", Name: "widgets", Kind: domain.KindTable},
				Level:      domain.AccessRead,
				Privileges: []string{"SELECT"},
				Sources:    []domain.AccessSource{{Role: "app_reader", Kind: "inherited"}},
			},
			{
				Object:     domain.DBObject{Schema: "app", Name: "secrets", Kind: domain.KindTable},
				Level:      domain.AccessAdmin,
				Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"},
				Sources:    []domain.AccessSource{{Role: "app_service", Kind: "ownership"}},
			},
			{
				Object:     domain.DBObject{Schema: "app", Name: "orders", Kind: domain.KindTable},
				Level:      domain.AccessWrite,
				Privileges: []string{"INSERT", "UPDATE"},
				Sources:    []domain.AccessSource{{Role: "app_writer", Kind: "direct"}},
			},
		},
		Warnings: []string{
			`role "app_service" has WRITE access to app.widgets, but its name implies at most Read`,
		},
	}
}

func TestRender(t *testing.T) {
	t.Run("JSON format produces valid, parseable JSON", func(t *testing.T) {
		var buf bytes.Buffer
		err := report.Render(&buf, sampleReport(), report.FormatJSON, false)
		require.NoError(t, err)

		var decoded domain.Report
		err = json.Unmarshal(buf.Bytes(), &decoded)
		require.NoError(t, err, "output should be valid, parseable JSON")

		assert.Equal(t, "app_service", decoded.Login)
		assert.Len(t, decoded.Access, 3)
		assert.Len(t, decoded.Warnings, 1)
	})

	t.Run("table format includes a row per EffectiveAccess", func(t *testing.T) {
		var buf bytes.Buffer
		err := report.Render(&buf, sampleReport(), report.FormatTable, false)
		require.NoError(t, err)

		out := buf.String()
		assert.Contains(t, out, "widgets")
		assert.Contains(t, out, "secrets")
		assert.Contains(t, out, "orders")
	})

	t.Run("table format lists warnings separately", func(t *testing.T) {
		var buf bytes.Buffer
		err := report.Render(&buf, sampleReport(), report.FormatTable, false)
		require.NoError(t, err)

		out := buf.String()
		require.Contains(t, out, "WARNINGS")
		assert.Contains(t, out, "app_service")

		// The warning text should appear after the "WARNINGS" heading, not
		// mixed into the access table above it.
		warningsIdx := strings.Index(out, "WARNINGS")
		accessTableIdx := strings.Index(out, "CURRENT ACCESS")
		require.NotEqual(t, -1, accessTableIdx)
		assert.Greater(t, warningsIdx, accessTableIdx)
	})

	t.Run("table format sorts rows by severity, most severe first", func(t *testing.T) {
		var buf bytes.Buffer
		err := report.Render(&buf, sampleReport(), report.FormatTable, false)
		require.NoError(t, err)

		out := buf.String()
		secretsIdx := strings.Index(out, "secrets") // Admin
		ordersIdx := strings.Index(out, "orders")   // Write
		widgetsIdx := strings.Index(out, "widgets") // Read

		require.NotEqual(t, -1, secretsIdx)
		require.NotEqual(t, -1, ordersIdx)
		require.NotEqual(t, -1, widgetsIdx)

		assert.Less(t, secretsIdx, ordersIdx, "Admin (secrets) should come before Write (orders)")
		assert.Less(t, ordersIdx, widgetsIdx, "Write (orders) should come before Read (widgets)")
	})

	t.Run("an unknown format returns an error", func(t *testing.T) {
		var buf bytes.Buffer
		err := report.Render(&buf, sampleReport(), "yaml", false)
		require.Error(t, err)
	})
}
