package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	csviSubmitURL string
	csviExportURL string
	csviParam     string
	csviMethod    string
	csviHeaders   []string
	csviInScope   []string
	csviMaxRisk   int
	csviThrottle  int
	csviTimeout   int
	csviEvidence  string
)

var verifyCSVInjectionCmd = &cobra.Command{
	Use:   "csvinjection",
	Short: "Verify CSV injection vulnerability",
	Long: `Verify CSV injection by submitting formula payloads and checking if they survive in exports.

Examples:
  ensphere verify csvinjection --submit-url "http://target/api/items" --export-url "http://target/api/export.csv" --param name --in-scope "*.target.com"`,
	RunE: runVerifyCSVInjection,
}

func init() {
	verifyCSVInjectionCmd.Flags().StringVar(&csviSubmitURL, "submit-url", "", "URL to submit data (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviExportURL, "export-url", "", "URL to download CSV export (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviParam, "param", "", "Field to inject into (required)")
	verifyCSVInjectionCmd.Flags().StringVar(&csviMethod, "method", "POST", "HTTP method for submit")
	verifyCSVInjectionCmd.Flags().StringSliceVar(&csviHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyCSVInjectionCmd.Flags().StringSliceVar(&csviInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyCSVInjectionCmd.Flags().IntVar(&csviMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyCSVInjectionCmd.Flags().IntVar(&csviThrottle, "throttle", 500, "Milliseconds between probes")
	verifyCSVInjectionCmd.Flags().IntVar(&csviTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyCSVInjectionCmd.Flags().StringVar(&csviEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyCSVInjectionCmd.MarkFlagRequired("submit-url")
	_ = verifyCSVInjectionCmd.MarkFlagRequired("export-url")
	_ = verifyCSVInjectionCmd.MarkFlagRequired("param")
	_ = verifyCSVInjectionCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyCSVInjectionCmd)
}

func runVerifyCSVInjection(cmd *cobra.Command, args []string) error {
	headers, err := parseHeaders(csviHeaders)
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
		return nil
	}

	cfg := verify.CSVInjectionConfig{
		SubmitURL: csviSubmitURL,
		ExportURL: csviExportURL,
		Param:     csviParam,
		Method:    csviMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    csviInScope,
			MaxRisk:    csviMaxRisk,
			ThrottleMs: csviThrottle,
			TimeoutSec: csviTimeout,
			Headers:    headers,
			Evidence:   csviEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCSVInjection(cfg)
	})
}
