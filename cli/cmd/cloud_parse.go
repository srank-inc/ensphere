package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/cloud"
	"github.com/srank/ensphere/internal/evidence"
)

var (
	cloudParseEvidence string
)

var cloudParseProwlerCmd = &cobra.Command{
	Use:   "parse-prowler [file]",
	Short: "Parse Prowler JSON-OCSF output",
	Long: `Parse Prowler JSON-OCSF output and map findings to Ensphere vuln types.

Examples:
  ensphere cloud parse-prowler ./prowler-output.json
  ensphere cloud parse-prowler ./prowler-output.json --evidence ./evidence.jsonl`,
	Args: cobra.ExactArgs(1),
	RunE: runParseProwler,
}

var cloudParseTrivyCmd = &cobra.Command{
	Use:   "parse-trivy [file]",
	Short: "Parse Trivy JSON output",
	Long: `Parse Trivy JSON output and map findings to Ensphere vuln types.

Examples:
  ensphere cloud parse-trivy ./trivy-results.json
  ensphere cloud parse-trivy ./trivy-results.json --evidence ./evidence.jsonl`,
	Args: cobra.ExactArgs(1),
	RunE: runParseTrivy,
}

func init() {
	cloudParseProwlerCmd.Flags().StringVar(&cloudParseEvidence, "evidence", "", "Evidence file path (optional)")
	cloudParseTrivyCmd.Flags().StringVar(&cloudParseEvidence, "evidence", "", "Evidence file path (optional)")

	cloudCmd.AddCommand(cloudParseProwlerCmd)
	cloudCmd.AddCommand(cloudParseTrivyCmd)
}

func runParseProwler(cmd *cobra.Command, args []string) error {
	result, err := cloud.ParseProwler(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %s\n", err)
		os.Exit(3)
	}

	logParseEvidence(result)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}

func runParseTrivy(cmd *cobra.Command, args []string) error {
	result, err := cloud.ParseTrivy(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %s\n", err)
		os.Exit(3)
	}

	logParseEvidence(result)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}

func logParseEvidence(result *cloud.ParseResult) {
	if cloudParseEvidence == "" || len(result.Findings) == 0 {
		return
	}
	ew, err := evidence.NewWriter(cloudParseEvidence)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", err)
		return
	}
	defer ew.Close()

	for _, f := range result.Findings {
		entry := evidence.NewEntry(f.VulnType, "cloud_audit", f.ResourceARN, f.CheckID, 0,
			"", result.Source+"_finding", fmt.Sprintf("[%s] %s: %s", f.Severity, f.CheckTitle, f.Description))
		_ = ew.Write(entry)
	}
}
