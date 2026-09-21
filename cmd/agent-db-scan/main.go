// Command agent-db-scan is the CLI entrypoint for agent-db-scan: it scans a
// Postgres connection's effective privileges and prints a report.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	agentdbscan "github.com/vaultkit-inc/agent-db-scan"
	"github.com/vaultkit-inc/agent-db-scan/internal/report"
)

var (
	dsn           string
	format        string
	schema        string
	includeSystem bool
	verbose       bool
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "agent-db-scan:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent-db-scan",
		Short: "Scan a Postgres connection's effective privileges",
		Long: "agent-db-scan reports what a Postgres connection can actually read, write, or\n" +
			"administer, by resolving role membership, ACLs, default privileges, and\n" +
			"ownership — not just its role name. It never touches table contents.",
		RunE: runScan,
	}
	cmd.Flags().StringVar(&dsn, "dsn", "", "Postgres connection string (defaults to $DATABASE_URL)")
	cmd.Flags().StringVar(&format, "format", "table", "output format: json|table")
	cmd.Flags().StringVar(&schema, "schema", "", "restrict the scan to a single schema")
	cmd.Flags().BoolVar(&includeSystem, "include-system", false, "include pg_catalog/information_schema in the scan")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "show privileges and full source lists in the table output")
	return cmd
}

func runScan(cmd *cobra.Command, args []string) error {
	resolvedDSN := dsn
	if resolvedDSN == "" {
		resolvedDSN = os.Getenv("DATABASE_URL")
	}
	if resolvedDSN == "" {
		return fmt.Errorf("no connection string given: pass --dsn or set DATABASE_URL")
	}

	var outFormat report.Format
	switch format {
	case string(report.FormatJSON):
		outFormat = report.FormatJSON
	case string(report.FormatTable):
		outFormat = report.FormatTable
	default:
		return fmt.Errorf("invalid --format %q: must be %q or %q", format, report.FormatJSON, report.FormatTable)
	}

	scanOpts := []agentdbscan.Option{agentdbscan.WithSchema(schema)}
	if includeSystem {
		scanOpts = append(scanOpts, agentdbscan.WithSystemSchemas())
	}

	rep, err := agentdbscan.Scan(cmd.Context(), resolvedDSN, scanOpts...)
	if err != nil {
		return err
	}

	return report.Render(cmd.OutOrStdout(), rep, outFormat, verbose)
}
