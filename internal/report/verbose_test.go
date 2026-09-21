package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func richReport() *domain.Report {
	src := func(role, kind string) domain.AccessSource { return domain.AccessSource{Role: role, Kind: kind} }
	return &domain.Report{
		Login:     "app_service",
		ScannedAt: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC),
		Access: []domain.EffectiveAccess{
			{
				Object:     domain.DBObject{Schema: "app", Name: "widgets", Kind: domain.KindTable},
				Level:      domain.AccessWrite,
				Privileges: []string{"SELECT", "INSERT"},
				Sources: []domain.AccessSource{
					src("app_service", "direct"), src("app_writer", "inherited"),
					src("app_reader", "inherited"), src("PUBLIC", "public"),
				},
			},
			{
				Object:     domain.DBObject{Schema: "app", Name: "secrets", Kind: domain.KindTable},
				Level:      domain.AccessAdmin,
				Privileges: []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"},
				Sources:    []domain.AccessSource{src("app_service", "ownership")},
			},
		},
		FutureAccess: []domain.ForwardLookingAccess{
			{
				Schema: "app", CreatorRole: "app_admin", ObjectKind: domain.KindTable,
				Privileges: []string{"SELECT"},
				Sources:    []domain.AccessSource{src("app_reader", "direct")},
			},
			{
				Schema: "", CreatorRole: "app_admin", ObjectKind: domain.KindSequence,
				Privileges: []string{"SELECT", "USAGE"},
				Sources: []domain.AccessSource{
					src("a", "inherited"), src("b", "inherited"), src("c", "inherited"),
				},
			},
		},
		Warnings: []string{"example warning"},
	}
}

const goldenDefault = `agent-db-scan

TARGET
  Login       app_service
  Scanned     2026-01-01 12:00:00 UTC

SUMMARY
  Objects        2
  Tables         2
  Can read       yes
  Can write      yes
  Admin access   yes
  Ownership      1 objects
  Future access  2 rules

CURRENT ACCESS
  OBJECT       KIND   LEVEL  VIA
  app.secrets  table  admin  ownership
  app.widgets  table  write  app_service (direct), app_writer (inherited), +2 more

FUTURE ACCESS
  New objects created by app_admin database-wide:
    sequence  SELECT, USAGE  via a (inherited), b (inherited), +1 more

  New objects created by app_admin in app:
    table  SELECT  via app_reader (direct)

WARNINGS
  ! example warning

`

func render(t *testing.T, verbose bool) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, renderTable(&buf, richReport(), false, verbose))
	return buf.String()
}

func TestVerbose_DefaultOutputUnchanged(t *testing.T) {
	// goldenDefault was captured from the renderer before verbose support
	// existed; the non-verbose path must stay byte-identical.
	assert.Equal(t, goldenDefault, render(t, false))
}

func TestVerbose_CurrentAccess(t *testing.T) {
	out := render(t, true)

	assert.Regexp(t, `OBJECT\s+KIND\s+LEVEL\s+PRIVILEGES\s+SOURCES\n`, out)
	assert.NotContains(t, out, "VIA")
	// ALL-collapse still applies, and ownership is shown as a full source.
	assert.Regexp(t, `app\.secrets\s+table\s+admin\s+ALL\s+app_service \(ownership\)\n`, out)
	// Full, untruncated source list — no "+N more".
	assert.Contains(t, out, "SELECT, INSERT  app_service (direct), app_writer (inherited), app_reader (inherited), PUBLIC (public)")
	assert.NotContains(t, out, "+2 more")
}

func TestVerbose_FutureAccessIsFlatTable(t *testing.T) {
	out := render(t, true)

	assert.NotContains(t, out, "New objects created by")
	assert.Regexp(t, `SCHEMA\s+CREATOR\s+KIND\s+PRIVILEGES\s+SOURCES\n`, out)
	assert.Regexp(t, `\(database-wide\)\s+app_admin\s+sequence\s+SELECT, USAGE\s+a \(inherited\), b \(inherited\), c \(inherited\)\n`, out)
	assert.Regexp(t, `app\s+app_admin\s+table\s+SELECT\s+app_reader \(direct\)\n`, out)
}

func TestFormatSourcesFull(t *testing.T) {
	mk := func(n int) []domain.AccessSource {
		var out []domain.AccessSource
		for i := 0; i < n; i++ {
			out = append(out, domain.AccessSource{Role: string(rune('a' + i)), Kind: "direct"})
		}
		return out
	}

	for _, n := range []int{1, 2, 3, 7} {
		got := formatSourcesFull(mk(n))
		assert.NotContains(t, got, "more", "n=%d", n)
		assert.Equal(t, n, strings.Count(got, "(direct)"), "n=%d", n)
	}
	assert.Equal(t, "unknown", formatSourcesFull(nil))
}
