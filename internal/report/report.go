// Package report is the Report Generator: it renders a domain.Report as
// either JSON or a human-readable security report.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"

	"github.com/vaultkit-inc/agent-db-scan/internal/domain"
)

// Format selects the output rendering.
type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
)

// Render writes rep to w in the requested format. verbose only affects the
// table format: it adds PRIVILEGES and the full SOURCES list to the access
// tables. JSON already carries full detail and ignores it.
func Render(w io.Writer, rep *domain.Report, format Format, verbose bool) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, rep)

	case FormatTable:
		return renderTable(w, rep, colorEnabled(w), verbose)

	default:
		return fmt.Errorf("report: unknown format %q", format)
	}
}

// renderJSON writes the complete report as indented JSON.
//
// JSON intentionally contains the full underlying data. The human-readable
// output is summarized, while JSON is intended for scripts, CI, jq,
// integrations, and debugging.
func renderJSON(w io.Writer, rep *domain.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(rep)
}

// renderTable renders the default human-facing report.
//
// The default output focuses on:
//  1. Who was scanned?
//  2. What can the login do?
//  3. Which objects can it access?
//  4. What access may apply to future objects?
//  5. Are there any existing heuristic warnings?
//
// It deliberately does not assign HIGH/MEDIUM/LOW severity. Risk
// classification belongs in a dedicated findings layer, not the renderer.
func renderTable(
	w io.Writer,
	rep *domain.Report,
	useColor bool,
	verbose bool,
) error {
	if err := renderHeader(w, rep); err != nil {
		return err
	}

	if err := renderSummary(w, rep, useColor); err != nil {
		return err
	}

	if err := renderCurrentAccess(w, rep, useColor, verbose); err != nil {
		return err
	}

	if err := renderFutureAccess(w, rep, verbose); err != nil {
		return err
	}

	if err := renderWarnings(w, rep, useColor); err != nil {
		return err
	}

	return nil
}

// renderHeader prints basic information about the scan.
func renderHeader(w io.Writer, rep *domain.Report) error {
	if _, err := fmt.Fprintln(w, "agent-db-scan"); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "TARGET"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		w,
		"  Login       %s\n",
		rep.Login,
	); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(
		w,
		"  Scanned     %s\n\n",
		rep.ScannedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
	); err != nil {
		return err
	}

	return nil
}

// summary contains factual, high-level information derived from the
// effective access records.
//
// These are capabilities, not security findings.
type summary struct {
	objects      int
	tables       int
	views        int
	sequences    int
	functions    int
	owned        int
	canRead      bool
	canWrite     bool
	hasAdmin     bool
	isSuperuser  bool
	futureAccess int
}

// buildSummary derives the information shown in SUMMARY.
//
// Read/write capability is derived from raw privileges instead of assuming
// AccessLevel is cumulative.
//
// In particular, EXECUTE and USAGE are intentionally not treated as proof
// that the login can modify table data.
func buildSummary(rep *domain.Report) summary {
	s := summary{
		objects:      len(rep.Access),
		futureAccess: len(rep.FutureAccess),
	}

	for _, access := range rep.Access {
		switch access.Object.Kind {
		case domain.KindTable:
			s.tables++

		case domain.KindView, domain.KindMaterializedView:
			s.views++

		case domain.KindSequence:
			s.sequences++

		case domain.KindFunction:
			s.functions++
		}

		for _, privilege := range access.Privileges {
			switch privilege {
			case "SELECT":
				s.canRead = true

			case "INSERT", "UPDATE", "DELETE", "TRUNCATE":
				s.canWrite = true

			case "ALL":
				s.canRead = true
				s.canWrite = true
			}
		}

		switch access.Level {
		case domain.AccessAdmin:
			s.hasAdmin = true

		case domain.AccessSuperuserEquivalent:
			s.hasAdmin = true
			s.isSuperuser = true
			s.canRead = true
			s.canWrite = true
		}

		for _, source := range access.Sources {
			if source.Kind == "ownership" {
				s.owned++
				break
			}
		}
	}

	return s
}

// renderSummary prints a concise overview of the login's capabilities.
//
// This section is intentionally factual. For example:
//
//	Ownership  6 objects
//
// does not imply:
//
//	HIGH: Login owns 6 objects
//
// Deciding whether a capability is dangerous belongs in a findings layer.
func renderSummary(
	w io.Writer,
	rep *domain.Report,
	useColor bool,
) error {
	s := buildSummary(rep)

	if _, err := fmt.Fprintln(w, "SUMMARY"); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(
		w,
		0,
		2,
		2,
		' ',
		0,
	)

	fmt.Fprintf(tw, "  Objects\t%d\n", s.objects)

	if s.tables > 0 {
		fmt.Fprintf(tw, "  Tables\t%d\n", s.tables)
	}

	if s.views > 0 {
		fmt.Fprintf(tw, "  Views\t%d\n", s.views)
	}

	if s.sequences > 0 {
		fmt.Fprintf(tw, "  Sequences\t%d\n", s.sequences)
	}

	if s.functions > 0 {
		fmt.Fprintf(tw, "  Functions\t%d\n", s.functions)
	}

	fmt.Fprintf(
		tw,
		"  Can read\t%s\n",
		yesNo(s.canRead, useColor),
	)

	fmt.Fprintf(
		tw,
		"  Can write\t%s\n",
		yesNo(s.canWrite, useColor),
	)

	fmt.Fprintf(
		tw,
		"  Admin access\t%s\n",
		yesNo(s.hasAdmin, useColor),
	)

	if s.isSuperuser {
		fmt.Fprintf(
			tw,
			"  Superuser\t%s\n",
			yesNo(true, useColor),
		)
	}

	if s.owned > 0 {
		fmt.Fprintf(
			tw,
			"  Ownership\t%d objects\n",
			s.owned,
		)
	} else {
		fmt.Fprintln(
			tw,
			"  Ownership\tnone",
		)
	}

	if s.futureAccess > 0 {
		fmt.Fprintf(
			tw,
			"  Future access\t%d rules\n",
			s.futureAccess,
		)
	} else {
		fmt.Fprintln(
			tw,
			"  Future access\tnone detected",
		)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintln(w)

	return err
}

// renderCurrentAccess prints the object-by-object access breakdown.
//
// The default terminal view intentionally hides the complete ACL details.
// Those remain available through JSON.
//
// The important questions here are:
//
//	What object can I access?
//	What kind of object is it?
//	What is my effective access level?
//	Where did that access come from?
//
// In verbose mode the VIA column is replaced by PRIVILEGES and the full,
// untruncated SOURCES list.
func renderCurrentAccess(
	w io.Writer,
	rep *domain.Report,
	useColor bool,
	verbose bool,
) error {
	if _, err := fmt.Fprintln(w, "CURRENT ACCESS"); err != nil {
		return err
	}

	if len(rep.Access) == 0 {
		if _, err := fmt.Fprintln(
			w,
			"  No accessible objects found.",
		); err != nil {
			return err
		}

		_, err := fmt.Fprintln(w)

		return err
	}

	// Work on a copy so rendering never mutates the domain report.
	sorted := make([]domain.EffectiveAccess, len(rep.Access))
	copy(sorted, rep.Access)

	// Most privileged objects first.
	//
	// Within the same level, sort by schema.object to keep the output
	// deterministic across runs.
	sort.SliceStable(sorted, func(i, j int) bool {
		leftRank := domain.AccessLevelRank[sorted[i].Level]
		rightRank := domain.AccessLevelRank[sorted[j].Level]

		if leftRank != rightRank {
			return leftRank > rightRank
		}

		return qualifiedObjectName(sorted[i]) <
			qualifiedObjectName(sorted[j])
	})

	// LEVEL is right-aligned manually because tabwriter's AlignRight option
	// would affect every column.
	levelWidth := len("LEVEL")

	for _, access := range sorted {
		if n := len(access.Level); n > levelWidth {
			levelWidth = n
		}
	}

	tw := tabwriter.NewWriter(
		w,
		0,
		2,
		2,
		' ',
		0,
	)

	lastHeader := "VIA"
	if verbose {
		lastHeader = "PRIVILEGES\tSOURCES"
	}

	fmt.Fprintf(
		tw,
		"  OBJECT\tKIND\t%s\t%s\n",
		colorLevel(
			fmt.Sprintf("%*s", levelWidth, "LEVEL"),
			"",
			useColor,
		),
		lastHeader,
	)

	for _, access := range sorted {
		lastCols := formatAccessVia(access.Sources)
		if verbose {
			lastCols = formatPrivileges(access.Privileges) +
				"\t" + formatSourcesFull(access.Sources)
		}

		fmt.Fprintf(
			tw,
			"  %s\t%s\t%s\t%s\n",
			qualifiedObjectName(access),
			access.Object.Kind,
			colorLevel(
				fmt.Sprintf(
					"%*s",
					levelWidth,
					access.Level,
				),
				access.Level,
				useColor,
			),
			lastCols,
		)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintln(w)

	return err
}

// qualifiedObjectName returns:
//
//	schema.object
//
// rather than rendering schema and object as separate columns.
func qualifiedObjectName(
	access domain.EffectiveAccess,
) string {
	if access.Object.Schema == "" {
		return access.Object.Name
	}

	return access.Object.Schema + "." + access.Object.Name
}

// renderFutureAccess presents PostgreSQL default privileges in terms of
// their consequence:
//
//	New objects created by ROLE in SCHEMA:
//
// rather than exposing "default ACL" terminology in the primary UI.
//
// In verbose mode the grouped narrative is replaced by a flat table with
// one row per rule and the full SOURCES list.
func renderFutureAccess(
	w io.Writer,
	rep *domain.Report,
	verbose bool,
) error {
	if len(rep.FutureAccess) == 0 {
		return nil
	}

	if _, err := fmt.Fprintln(w, "FUTURE ACCESS"); err != nil {
		return err
	}

	if verbose {
		return renderFutureAccessFlat(w, rep)
	}

	type groupKey struct {
		schema  string
		creator string
	}

	groups := make(
		map[groupKey][]domain.ForwardLookingAccess,
	)

	var order []groupKey

	for _, access := range rep.FutureAccess {
		key := groupKey{
			schema:  access.Schema,
			creator: access.CreatorRole,
		}

		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}

		groups[key] = append(
			groups[key],
			access,
		)
	}

	// Deterministic output.
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].schema != order[j].schema {
			return order[i].schema < order[j].schema
		}

		return order[i].creator < order[j].creator
	})

	for groupIndex, key := range order {
		if key.schema == "" {
			fmt.Fprintf(
				w,
				"  New objects created by %s database-wide:\n",
				key.creator,
			)
		} else {
			fmt.Fprintf(
				w,
				"  New objects created by %s in %s:\n",
				key.creator,
				key.schema,
			)
		}

		entries := groups[key]

		sort.SliceStable(entries, func(i, j int) bool {
			return string(entries[i].ObjectKind) <
				string(entries[j].ObjectKind)
		})

		tw := tabwriter.NewWriter(
			w,
			0,
			2,
			2,
			' ',
			0,
		)

		for _, access := range entries {
			fmt.Fprintf(
				tw,
				"    %s\t%s\tvia %s\n",
				access.ObjectKind,
				formatPrivileges(access.Privileges),
				formatSources(access.Sources),
			)
		}

		if err := tw.Flush(); err != nil {
			return err
		}

		if groupIndex < len(order)-1 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintln(w)

	return err
}

// renderFutureAccessFlat is the verbose FUTURE ACCESS view: one row per
// default-privilege rule, in the report's original order.
func renderFutureAccessFlat(w io.Writer, rep *domain.Report) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)

	fmt.Fprintln(tw, "  SCHEMA\tCREATOR\tKIND\tPRIVILEGES\tSOURCES")

	for _, access := range rep.FutureAccess {
		schema := access.Schema
		if schema == "" {
			schema = "(database-wide)"
		}

		fmt.Fprintf(
			tw,
			"  %s\t%s\t%s\t%s\t%s\n",
			schema,
			access.CreatorRole,
			access.ObjectKind,
			formatPrivileges(access.Privileges),
			formatSourcesFull(access.Sources),
		)
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	_, err := fmt.Fprintln(w)

	return err
}

// renderWarnings prints warnings already generated elsewhere in the scanner.
//
// The renderer does not decide severity. It simply presents warnings that
// already exist on domain.Report.
func renderWarnings(
	w io.Writer,
	rep *domain.Report,
	useColor bool,
) error {
	if len(rep.Warnings) == 0 {
		return nil
	}

	if _, err := fmt.Fprintln(w, "WARNINGS"); err != nil {
		return err
	}

	for _, warning := range rep.Warnings {
		prefix := "!"

		if useColor {
			prefix = "\x1b[33m!\x1b[0m"
		}

		if _, err := fmt.Fprintf(
			w,
			"  %s %s\n",
			prefix,
			warning,
		); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(w)

	return err
}

// formatAccessVia produces the short explanation used in CURRENT ACCESS.
//
// Instead of:
//
//	neondb_owner (ownership)
//
// a single ownership source is rendered simply as:
//
//	ownership
//
// Other access paths retain the role name because that information is
// useful:
//
//	app_reader (inherited)
func formatAccessVia(
	sources []domain.AccessSource,
) string {
	if len(sources) == 0 {
		return "unknown"
	}

	if len(sources) == 1 &&
		sources[0].Kind == "ownership" {
		return "ownership"
	}

	return formatSources(sources)
}

// maxSourcesShown limits how many sources are displayed in the terminal.
//
// JSON always contains every source.
const maxSourcesShown = 2

// allTablePrivileges is the complete PostgreSQL table privilege set.
//
// If all of these privileges are present, the terminal displays:
//
//	ALL
//
// instead of:
//
//	SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
var allTablePrivileges = []string{
	"SELECT",
	"INSERT",
	"UPDATE",
	"DELETE",
	"TRUNCATE",
	"REFERENCES",
	"TRIGGER",
}

// formatPrivileges produces the compact privilege representation used in
// FUTURE ACCESS.
func formatPrivileges(privileges []string) string {
	if len(privileges) == 0 {
		return "none"
	}

	// Superuser-equivalent records may already contain ALL.
	for _, privilege := range privileges {
		if privilege == "ALL" {
			return "ALL"
		}
	}

	have := make(
		map[string]bool,
		len(privileges),
	)

	for _, privilege := range privileges {
		have[privilege] = true
	}

	hasAllTablePrivileges := true

	for _, privilege := range allTablePrivileges {
		if !have[privilege] {
			hasAllTablePrivileges = false
			break
		}
	}

	if hasAllTablePrivileges {
		return "ALL"
	}

	return strings.Join(privileges, ", ")
}

// formatSources renders access sources as:
//
//	role (kind), role (kind)
//
// Long source lists are shortened:
//
//	app_reader (inherited), PUBLIC (public), +2 more
func formatSources(
	sources []domain.AccessSource,
) string {
	return joinSources(sources, maxSourcesShown)
}

// formatSourcesFull is formatSources without the maxSourcesShown cap or the
// "+N more" suffix: every source is listed.
func formatSourcesFull(
	sources []domain.AccessSource,
) string {
	return joinSources(sources, len(sources))
}

// joinSources renders at most limit sources as "role (kind), ...", followed
// by "+N more" if any were cut.
func joinSources(
	sources []domain.AccessSource,
	limit int,
) string {
	if len(sources) == 0 {
		return "unknown"
	}

	shown := sources

	if len(shown) > limit {
		shown = shown[:limit]
	}

	parts := make(
		[]string,
		0,
		len(shown)+1,
	)

	for _, source := range shown {
		role := source.Role

		if role == "" {
			role = "?"
		}

		parts = append(
			parts,
			fmt.Sprintf(
				"%s (%s)",
				role,
				source.Kind,
			),
		)
	}

	if extra := len(sources) - len(shown); extra > 0 {
		parts = append(
			parts,
			fmt.Sprintf(
				"+%d more",
				extra,
			),
		)
	}

	return strings.Join(parts, ", ")
}

// yesNo renders a boolean used in SUMMARY.
//
// "yes" is yellow because it represents the presence of a capability,
// not necessarily a vulnerability.
//
// "no" is green because that capability was not detected.
func yesNo(
	value bool,
	useColor bool,
) string {
	if value {
		if useColor {
			return "\x1b[33myes\x1b[0m"
		}

		return "yes"
	}

	if useColor {
		return "\x1b[32mno\x1b[0m"
	}

	return "no"
}

// colorEnabled reports whether ANSI colour should be used.
//
// Colour is enabled only when:
//   - output is being written to a terminal
//   - NO_COLOR is not set
//
// This means:
//
//	agent-db-scan
//
// can use colour interactively, while:
//
//	agent-db-scan > report.txt
//
// automatically produces clean plain text.
func colorEnabled(w io.Writer) bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}

	f, ok := w.(*os.File)

	return ok && term.IsTerminal(int(f.Fd()))
}

// colorLevel applies a visual colour to effective access levels.
//
// This is visualization of capability level, not a security severity:
//
//	READ        green
//	WRITE       yellow
//	ADMIN       red
//	SUPERUSER   bright red
//
// Every ANSI wrapper uses the same byte length so tabwriter's byte-based
// width calculation remains aligned.
func colorLevel(
	text string,
	level domain.AccessLevel,
	useColor bool,
) string {
	if !useColor {
		return text
	}

	code := "\x1b[39m"

	switch level {
	case domain.AccessSuperuserEquivalent:
		code = "\x1b[91m" // bright red

	case domain.AccessAdmin:
		code = "\x1b[31m" // red

	case domain.AccessWrite:
		code = "\x1b[33m" // yellow

	case domain.AccessRead:
		code = "\x1b[32m" // green
	}

	return code + text + "\x1b[0m"
}
