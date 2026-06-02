package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	redirectURL      string
	redirectParam    string
	redirectMethod   string
	redirectHeaders  []string
	redirectInScope  []string
	redirectMaxRisk  int
	redirectThrottle int
	redirectTimeout  int
	redirectEvidence string
)

var verifyRedirectCmd = &cobra.Command{
	Use:   "redirect",
	Short: "Verify open redirect vulnerability",
	Long: `Verify open redirect by injecting an external URL and checking the Location header.

Examples:
  ensphere verify redirect --url "http://target/login?next=/dashboard" --param next --in-scope "*.target.com"
  ensphere verify redirect --url "http://target/goto?url=/" --param url --in-scope "*.target.com"`,
	RunE: runVerifyRedirect,
}

func init() {
	verifyRedirectCmd.Flags().StringVar(&redirectURL, "url", "", "Target URL (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectParam, "param", "", "Redirect parameter name (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectMethod, "method", "GET", "HTTP method")
	verifyRedirectCmd.Flags().StringSliceVar(&redirectHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyRedirectCmd.Flags().StringSliceVar(&redirectInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyRedirectCmd.Flags().IntVar(&redirectMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyRedirectCmd.Flags().IntVar(&redirectThrottle, "throttle", 500, "Milliseconds between probes")
	verifyRedirectCmd.Flags().IntVar(&redirectTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyRedirectCmd.Flags().StringVar(&redirectEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyRedirectCmd.MarkFlagRequired("url")
	_ = verifyRedirectCmd.MarkFlagRequired("param")
	_ = verifyRedirectCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyRedirectCmd)
}

func runVerifyRedirect(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(redirectHeaders)

	cfg := verify.RedirectConfig{
		URL:    redirectURL,
		Param:  redirectParam,
		Method: redirectMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    redirectInScope,
			MaxRisk:    redirectMaxRisk,
			ThrottleMs: redirectThrottle,
			TimeoutSec: redirectTimeout,
			Headers:    headers,
			Evidence:   redirectEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyRedirect(cfg)
	})
}
