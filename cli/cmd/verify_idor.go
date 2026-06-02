package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	idorURL            string
	idorID             string
	idorToken          string
	idorExpectedStatus int
	idorMethod         string
	idorHeaders        []string
	idorInScope        []string
	idorMaxRisk        int
	idorThrottle       int
	idorTimeout        int
	idorEvidence       string
)

var verifyIDORCmd = &cobra.Command{
	Use:   "idor",
	Short: "Verify insecure direct object reference",
	Long: `Verify IDOR by accessing a resource with an attacker's token.

The URL should contain {id} as a placeholder for the resource ID.

Examples:
  ensphere verify idor --url "http://target/api/items/{id}" --id "victim-uuid" --token "attacker-jwt" --in-scope "*.target.com"
  ensphere verify idor --url "http://target/api/users/{id}/profile" --id "123" --token "low-priv-token" --in-scope "*.target.com"`,
	RunE: runVerifyIDOR,
}

func init() {
	verifyIDORCmd.Flags().StringVar(&idorURL, "url", "", "Target URL with {id} placeholder (required)")
	verifyIDORCmd.Flags().StringVar(&idorID, "id", "", "Resource ID to access (required)")
	verifyIDORCmd.Flags().StringVar(&idorToken, "token", "", "Attacker's auth token (required)")
	verifyIDORCmd.Flags().IntVar(&idorExpectedStatus, "expected-status", 403, "Expected denial status code")
	verifyIDORCmd.Flags().StringVar(&idorMethod, "method", "GET", "HTTP method")
	verifyIDORCmd.Flags().StringSliceVar(&idorHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyIDORCmd.Flags().StringSliceVar(&idorInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8)")
	verifyIDORCmd.Flags().IntVar(&idorMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyIDORCmd.Flags().IntVar(&idorThrottle, "throttle", 500, "Milliseconds between probes")
	verifyIDORCmd.Flags().IntVar(&idorTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyIDORCmd.Flags().StringVar(&idorEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyIDORCmd.MarkFlagRequired("url")
	_ = verifyIDORCmd.MarkFlagRequired("id")
	_ = verifyIDORCmd.MarkFlagRequired("token")
	_ = verifyIDORCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyIDORCmd)
}

func runVerifyIDOR(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(idorHeaders)

	cfg := verify.IDORConfig{
		URL:            idorURL,
		ID:             idorID,
		Token:          idorToken,
		ExpectedStatus: idorExpectedStatus,
		Method:         idorMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    idorInScope,
			MaxRisk:    idorMaxRisk,
			ThrottleMs: idorThrottle,
			TimeoutSec: idorTimeout,
			Headers:    headers,
			Evidence:   idorEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyIDOR(cfg)
	})
}
