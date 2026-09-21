package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

func TestFormatPrivileges(t *testing.T) {
	all := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}

	assert.Equal(t, "ALL", formatPrivileges(all))
	assert.Equal(t, "ALL", formatPrivileges(append([]string{"TRIGGER"}, all[:6]...)), "order shouldn't matter")
	assert.Equal(t, "SELECT, INSERT", formatPrivileges([]string{"SELECT", "INSERT"}))
	assert.Equal(t, strings.Join(all[:6], ", "), formatPrivileges(all[:6]), "six of seven is not ALL")
	assert.Equal(t, "none", formatPrivileges(nil))
}

func TestFormatSources(t *testing.T) {
	src := func(role string) domain.AccessSource { return domain.AccessSource{Role: role, Kind: "direct"} }

	assert.Equal(t, "a (direct), b (direct)", formatSources([]domain.AccessSource{src("a"), src("b")}), "two is not truncated")
	assert.Equal(t, "a (direct), b (direct), +1 more",
		formatSources([]domain.AccessSource{src("a"), src("b"), src("c")}))
	assert.Equal(t, "a (direct), b (direct), +3 more",
		formatSources([]domain.AccessSource{src("a"), src("b"), src("c"), src("d"), src("e")}))
	assert.Equal(t, "? (public)", formatSources([]domain.AccessSource{{Kind: "public"}}))
}

func TestRenderTable_LevelColumn(t *testing.T) {
	rep := &domain.Report{Access: []domain.EffectiveAccess{
		{Object: domain.DBObject{Schema: "s", Name: "a", Kind: domain.KindTable}, Level: domain.AccessSuperuserEquivalent},
		{Object: domain.DBObject{Schema: "s", Name: "b", Kind: domain.KindTable}, Level: domain.AccessRead},
	}}

	t.Run("plain output right-aligns LEVEL and has no escapes", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, renderTable(&buf, rep, false, false))
		out := buf.String()
		assert.NotContains(t, out, "\x1b")
		assert.Contains(t, out, "                LEVEL") // padded to width of superuser_equivalent
		assert.Contains(t, out, "                 read") // right-aligned
	})

	t.Run("colored output keeps columns aligned and colors by severity", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, renderTable(&buf, rep, true, false))
		out := buf.String()
		assert.Contains(t, out, "\x1b[91msuperuser_equivalent\x1b[0m")
		assert.Contains(t, out, "\x1b[32m                read\x1b[0m")

		// After stripping escapes the layout must match the plain render.
		var plain bytes.Buffer
		require.NoError(t, renderTable(&plain, rep, false, false))
		stripped := out
		for _, e := range []string{"\x1b[91m", "\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[39m", "\x1b[0m"} {
			stripped = strings.ReplaceAll(stripped, e, "")
		}
		assert.Equal(t, plain.String(), stripped)
	})
}

func TestColorEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	assert.False(t, colorEnabled(&bytes.Buffer{}))
}
