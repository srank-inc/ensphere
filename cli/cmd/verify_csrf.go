package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	csrfURL      string
	csrfMethod   string
	csrfToken    string
	csrfHeaders  []string
	csrfInScope  []string
	csrfMaxRisk  int
	csrfThrottle int
	csrfTimeout  int
	csrfEvidence string
)

var verifyCSRFCmd = &cobra.Command{
	Use:   "csrf",
	Short: "Verify cross-site request forgery",
	Long: `Verify CSRF by testing Origin header validation and SameSite cookie attributes.

Examples:
  ensphere verify csrf --url "http://target/api/action" --method POST --in-scope "*.target.com"
  ensphere verify csrf --url "http://target/transfer" --token "auth-jwt" --in-scope "*.target.com"`,
	RunE: runVerifyCSRF,
}

func init() {
	verifyCSRFCmd.Flags().StringVar(&csrfURL, "url", "", "Target URL (required)")
	verifyCSRFCmd.Flags().StringVar(&csrfMethod, "method", "POST", "HTTP method")
	verifyCSRFCmd.Flags().StringVar(&csrfToken, "token", "", "Valid auth token")
	verifyCSRFCmd.Flags().StringSliceVar(&csrfHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyCSRFCmd.Flags().StringSliceVar(&csrfInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyCSRFCmd.Flags().IntVar(&csrfMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyCSRFCmd.Flags().IntVar(&csrfThrottle, "throttle", 500, "Milliseconds between probes")
	verifyCSRFCmd.Flags().IntVar(&csrfTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyCSRFCmd.Flags().StringVar(&csrfEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyCSRFCmd.MarkFlagRequired("url")
	_ = verifyCSRFCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyCSRFCmd)
}

func runVerifyCSRF(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(csrfHeaders)

	cfg := verify.CSRFConfig{
		URL:    csrfURL,
		Method: csrfMethod,
		Token:  csrfToken,
		ProbeConfig: verify.ProbeConfig{
			InScope:    csrfInScope,
			MaxRisk:    csrfMaxRisk,
			ThrottleMs: csrfThrottle,
			TimeoutSec: csrfTimeout,
			Headers:    headers,
			Evidence:   csrfEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyCSRF(cfg)
	})
}
