package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	clickjackURL      string
	clickjackMethod   string
	clickjackHeaders  []string
	clickjackInScope  []string
	clickjackMaxRisk  int
	clickjackThrottle int
	clickjackTimeout  int
	clickjackEvidence string
)

var verifyClickjackingCmd = &cobra.Command{
	Use:   "clickjacking",
	Short: "Verify clickjacking protection",
	Long: `Verify clickjacking protection by inspecting X-Frame-Options and CSP frame-ancestors headers.

Examples:
  ensphere verify clickjacking --url "http://target/app" --in-scope "*.target.com"
  ensphere verify clickjacking --url "http://target/login" --method GET --in-scope "*.target.com"`,
	RunE: runVerifyClickjacking,
}

func init() {
	verifyClickjackingCmd.Flags().StringVar(&clickjackURL, "url", "", "Target URL (required)")
	verifyClickjackingCmd.Flags().StringVar(&clickjackMethod, "method", "GET", "HTTP method")
	verifyClickjackingCmd.Flags().StringSliceVar(&clickjackHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyClickjackingCmd.Flags().StringSliceVar(&clickjackInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyClickjackingCmd.Flags().IntVar(&clickjackMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyClickjackingCmd.Flags().IntVar(&clickjackThrottle, "throttle", 500, "Milliseconds between probes")
	verifyClickjackingCmd.Flags().IntVar(&clickjackTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyClickjackingCmd.Flags().StringVar(&clickjackEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyClickjackingCmd.MarkFlagRequired("url")
	_ = verifyClickjackingCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyClickjackingCmd)
}

func runVerifyClickjacking(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(clickjackHeaders)

	cfg := verify.ClickjackingConfig{
		URL:    clickjackURL,
		Method: clickjackMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    clickjackInScope,
			MaxRisk:    clickjackMaxRisk,
			ThrottleMs: clickjackThrottle,
			TimeoutSec: clickjackTimeout,
			Headers:    headers,
			Evidence:   clickjackEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyClickjacking(cfg)
	})
}
