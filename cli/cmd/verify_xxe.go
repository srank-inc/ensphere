package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	xxeURL       string
	xxeTechnique string
	xxeMethod    string
	xxeHeaders   []string
	xxeInScope   []string
	xxeMaxRisk   int
	xxeThrottle  int
	xxeTimeout   int
	xxeEvidence  string
)

var verifyXXECmd = &cobra.Command{
	Use:   "xxe",
	Short: "Verify XML external entity injection",
	Long: `Verify XXE by sending crafted XML with external entity references.

Techniques: file_read, ssrf, oob

Examples:
  ensphere verify xxe --url "http://target/api/xml" --technique file_read --in-scope "*.target.com"
  ensphere verify xxe --url "http://target/upload" --technique ssrf --in-scope "*.target.com"`,
	RunE: runVerifyXXE,
}

func init() {
	verifyXXECmd.Flags().StringVar(&xxeURL, "url", "", "Target URL (required)")
	verifyXXECmd.Flags().StringVar(&xxeTechnique, "technique", "file_read", "Technique: file_read, ssrf, oob")
	verifyXXECmd.Flags().StringVar(&xxeMethod, "method", "POST", "HTTP method")
	verifyXXECmd.Flags().StringSliceVar(&xxeHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyXXECmd.Flags().StringSliceVar(&xxeInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyXXECmd.Flags().IntVar(&xxeMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyXXECmd.Flags().IntVar(&xxeThrottle, "throttle", 500, "Milliseconds between probes")
	verifyXXECmd.Flags().IntVar(&xxeTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyXXECmd.Flags().StringVar(&xxeEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyXXECmd.MarkFlagRequired("url")
	_ = verifyXXECmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyXXECmd)
}

func runVerifyXXE(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(xxeHeaders)

	cfg := verify.XXEConfig{
		URL:       xxeURL,
		Method:    xxeMethod,
		Technique: xxeTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    xxeInScope,
			MaxRisk:    xxeMaxRisk,
			ThrottleMs: xxeThrottle,
			TimeoutSec: xxeTimeout,
			Headers:    headers,
			Evidence:   xxeEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyXXE(cfg)
	})
}
