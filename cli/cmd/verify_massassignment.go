package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	maURL         string
	maMethod      string
	maBody        string
	maWatchFields []string
	maToken       string
	maHeaders     []string
	maInScope     []string
	maMaxRisk     int
	maThrottle    int
	maTimeout     int
	maEvidence    string
)

var verifyMassAssignmentCmd = &cobra.Command{
	Use:   "massassignment",
	Short: "Verify mass assignment vulnerability",
	Long: `Verify mass assignment vulnerability using a 3-step approach:

1. Baseline GET — capture the resource's current state
2. Mutation PUT/PATCH/POST — send the legitimate body with injected watch fields
3. Follow-up GET — re-read the resource and compare with baseline

The probe injects each watch field (e.g., role, is_admin, price) into the
legitimate request body with a test value, then checks whether those fields
appear or change in the follow-up response.

Examples:
  ensphere verify massassignment \
    --url "http://target/api/users/42" \
    --body '{"name":"test"}' \
    --watch-fields role,is_admin \
    --token "eyJhbGci..." \
    --in-scope "*.target.com"

  ensphere verify massassignment \
    --url "http://target/api/products/1" \
    --method PATCH \
    --body '{"name":"Widget"}' \
    --watch-fields price,discount \
    --token "tok_abc123" \
    --in-scope "*.target.com"`,
	RunE: runVerifyMassAssignment,
}

func init() {
	verifyMassAssignmentCmd.Flags().StringVar(&maURL, "url", "", "Target URL (required)")
	verifyMassAssignmentCmd.Flags().StringVar(&maMethod, "method", "PUT", "HTTP method: PUT, PATCH, POST")
	verifyMassAssignmentCmd.Flags().StringVar(&maBody, "body", "", "Base JSON body (required)")
	verifyMassAssignmentCmd.Flags().StringSliceVar(&maWatchFields, "watch-fields", nil, "Fields to inject (required, comma-separated)")
	verifyMassAssignmentCmd.Flags().StringVar(&maToken, "token", "", "Auth token for requests (required)")
	verifyMassAssignmentCmd.Flags().StringSliceVar(&maHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyMassAssignmentCmd.Flags().StringSliceVar(&maInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyMassAssignmentCmd.Flags().IntVar(&maMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyMassAssignmentCmd.Flags().IntVar(&maThrottle, "throttle", 500, "Milliseconds between probes")
	verifyMassAssignmentCmd.Flags().IntVar(&maTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyMassAssignmentCmd.Flags().StringVar(&maEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyMassAssignmentCmd.MarkFlagRequired("url")
	_ = verifyMassAssignmentCmd.MarkFlagRequired("body")
	_ = verifyMassAssignmentCmd.MarkFlagRequired("watch-fields")
	_ = verifyMassAssignmentCmd.MarkFlagRequired("token")
	_ = verifyMassAssignmentCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyMassAssignmentCmd)
}

func runVerifyMassAssignment(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(maHeaders)

	cfg := verify.MassAssignmentConfig{
		URL:         maURL,
		Method:      maMethod,
		Body:        maBody,
		WatchFields: maWatchFields,
		Token:       maToken,
		ProbeConfig: verify.ProbeConfig{
			InScope:    maInScope,
			MaxRisk:    maMaxRisk,
			ThrottleMs: maThrottle,
			TimeoutSec: maTimeout,
			Headers:    headers,
			Evidence:   maEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyMassAssignment(cfg)
	})
}
