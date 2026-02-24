package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/evidence"
)

var (
	evidLogFile       string
	evidLogProbeType  string
	evidLogTechnique  string
	evidLogURL        string
	evidLogParam      string
	evidLogResult     string
	evidLogNotes      string
	evidLogStatusCode int
	evidLogDuration   string
	evidLogSession    int
	evidLogFindingRef string
	evidLogScreenshot string
)

var evidenceLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Write a new evidence entry",
	Long: `Log a structured evidence entry to a JSONL file with auto-assigned sequential ID.

Examples:
  ensphere evidence log --probe-type sqli --technique blind_time --url "http://target/api" --result confirmed
  ensphere evidence log --probe-type xss --technique reflected --url "http://target/search" --result confirmed --session 5 --finding-ref VULN-003`,
	RunE: runEvidenceLog,
}

func init() {
	evidenceLogCmd.Flags().StringVar(&evidLogFile, "file", "./evidence.jsonl", "Evidence file path")
	evidenceLogCmd.Flags().StringVar(&evidLogProbeType, "probe-type", "", "Probe type (required)")
	evidenceLogCmd.Flags().StringVar(&evidLogTechnique, "technique", "", "Technique used (required)")
	evidenceLogCmd.Flags().StringVar(&evidLogURL, "url", "", "Target URL (required)")
	evidenceLogCmd.Flags().StringVar(&evidLogParam, "param", "", "Parameter name")
	evidenceLogCmd.Flags().StringVar(&evidLogResult, "result", "", "Result: confirmed, potential, safe, baseline, probe (required)")
	evidenceLogCmd.Flags().StringVar(&evidLogNotes, "notes", "", "Additional notes")
	evidenceLogCmd.Flags().IntVar(&evidLogStatusCode, "status-code", 0, "HTTP status code")
	evidenceLogCmd.Flags().StringVar(&evidLogDuration, "duration", "", "Probe duration")
	evidenceLogCmd.Flags().IntVar(&evidLogSession, "session", 0, "Session number")
	evidenceLogCmd.Flags().StringVar(&evidLogFindingRef, "finding-ref", "", "Finding reference (e.g., VULN-001)")
	evidenceLogCmd.Flags().StringVar(&evidLogScreenshot, "screenshot", "", "Screenshot file path")

	_ = evidenceLogCmd.MarkFlagRequired("probe-type")
	_ = evidenceLogCmd.MarkFlagRequired("technique")
	_ = evidenceLogCmd.MarkFlagRequired("url")
	_ = evidenceLogCmd.MarkFlagRequired("result")

	evidenceCmd.AddCommand(evidenceLogCmd)
}

func runEvidenceLog(cmd *cobra.Command, args []string) error {
	nextID, err := evidence.NextID(evidLogFile)
	if err != nil {
		return fmt.Errorf("get next ID: %w", err)
	}

	entry := evidence.NewEntry(
		evidLogProbeType, evidLogTechnique, evidLogURL, evidLogParam,
		evidLogStatusCode, evidLogDuration, evidLogResult, evidLogNotes,
	).WithID(nextID)

	if evidLogSession > 0 {
		entry = entry.WithSession(evidLogSession)
	}
	if evidLogFindingRef != "" {
		entry = entry.WithFinding(evidLogFindingRef)
	}
	if evidLogScreenshot != "" {
		entry = entry.WithScreenshot(evidLogScreenshot)
	}

	ew, err := evidence.NewWriter(evidLogFile)
	if err != nil {
		return fmt.Errorf("open evidence file: %w", err)
	}
	defer ew.Close()

	if err := ew.Write(entry); err != nil {
		return fmt.Errorf("write evidence: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(entry)
}
