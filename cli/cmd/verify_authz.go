package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	authzURL       string
	authzMethod    string
	authzLowToken  string
	authzHighToken string
	authzHeaders   []string
	authzInScope   []string
	authzMaxRisk   int
	authzThrottle  int
	authzTimeout   int
	authzEvidence  string
)

var verifyAuthZCmd = &cobra.Command{
	Use:   "authz",
	Short: "Verify authorization bypass vulnerability",
	Long: `Verify authorization bypass by comparing responses for different privilege levels.

Sends the same request with a high-privilege and low-privilege token and compares results.

Examples:
  ensphere verify authz --url "http://target/api/admin" --low-token "user-jwt" --high-token "admin-jwt" --in-scope "*.target.com"`,
	RunE: runVerifyAuthZ,
}

func init() {
	verifyAuthZCmd.Flags().StringVar(&authzURL, "url", "", "Target URL (required)")
	verifyAuthZCmd.Flags().StringVar(&authzMethod, "method", "GET", "HTTP method")
	verifyAuthZCmd.Flags().StringVar(&authzLowToken, "low-token", "", "Low-privilege auth token (required)")
	verifyAuthZCmd.Flags().StringVar(&authzHighToken, "high-token", "", "High-privilege auth token (required)")
	verifyAuthZCmd.Flags().StringSliceVar(&authzHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyAuthZCmd.Flags().StringSliceVar(&authzInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyAuthZCmd.Flags().IntVar(&authzMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyAuthZCmd.Flags().IntVar(&authzThrottle, "throttle", 500, "Milliseconds between probes")
	verifyAuthZCmd.Flags().IntVar(&authzTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyAuthZCmd.Flags().StringVar(&authzEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyAuthZCmd.MarkFlagRequired("url")
	_ = verifyAuthZCmd.MarkFlagRequired("low-token")
	_ = verifyAuthZCmd.MarkFlagRequired("high-token")
	_ = verifyAuthZCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyAuthZCmd)
}

func runVerifyAuthZ(cmd *cobra.Command, args []string) error {
	headers, err := parseHeaders(authzHeaders)
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
		return nil
	}

	cfg := verify.AuthZConfig{
		URL:           authzURL,
		Method:        authzMethod,
		LowPrivToken:  authzLowToken,
		HighPrivToken: authzHighToken,
		ProbeConfig: verify.ProbeConfig{
			InScope:    authzInScope,
			MaxRisk:    authzMaxRisk,
			ThrottleMs: authzThrottle,
			TimeoutSec: authzTimeout,
			Headers:    headers,
			Evidence:   authzEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyAuthZ(cfg)
	})
}
