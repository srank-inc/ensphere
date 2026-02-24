package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/scan"
	"github.com/srank/ensphere/internal/sinks"
)

var (
	scanCategories []string
	scanExtensions []string
	scanExcludes   []string
)

var scanCmd = &cobra.Command{
	Use:   "scan [directory]",
	Short: "Scan source code for dangerous sink patterns",
	Long: `Scan a directory for code patterns that may indicate security vulnerabilities.

Uses the built-in sink pattern database to find dangerous function calls,
SQL construction, command execution, and other security-relevant code patterns.

Examples:
  ensphere scan ./src                          # scan all categories
  ensphere scan ./src --category sqli,xss      # filter by category
  ensphere scan ./src --exclude "test/**"      # exclude patterns`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanCategories, "category", nil, "Filter by sink category (repeatable)")
	scanCmd.Flags().StringSliceVar(&scanExtensions, "extensions", nil, "Override file extensions to scan (repeatable)")
	scanCmd.Flags().StringSliceVar(&scanExcludes, "exclude", nil, "Additional glob patterns to exclude (repeatable)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	dir := args[0]

	// Validate categories
	if len(scanCategories) > 0 {
		validNames := sinks.CategoryNames()
		validSet := make(map[string]bool)
		for _, n := range validNames {
			validSet[n] = true
		}
		for _, c := range scanCategories {
			if !validSet[c] {
				return fmt.Errorf("invalid category %q — valid: %s", c, fmt.Sprintf("%v", validNames))
			}
		}
	}

	cfg := scan.ScanConfig{
		Directory:  dir,
		Categories: scanCategories,
		Extensions: scanExtensions,
		Excludes:   scanExcludes,
	}

	result, err := scan.RunScan(cfg)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	if result.TotalMatches > 0 {
		os.Exit(1)
	}
	return nil
}
