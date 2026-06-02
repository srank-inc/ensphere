package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	authURL       string
	authMethod    string
	authToken     string
	authTechnique string
	authHeaders   []string
	authInScope   []string
	authMaxRisk   int
	authThrottle  int
	authTimeout   int
	authEvidence  string
)

var verifyAuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Verify authentication bypass",
	Long: `Verify authentication bypass using various techniques.

Techniques:
  no_token        Send request without Authorization header
  expired_token   Send request with an invalid/expired token
  alg_none        Modify JWT to use alg:none with empty signature
  method_override Use X-HTTP-Method-Override to bypass method-based auth

Examples:
  ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique no_token --in-scope "*.target.com"
  ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique alg_none --in-scope "*.target.com"`,
	RunE: runVerifyAuth,
}

func init() {
	verifyAuthCmd.Flags().StringVar(&authURL, "url", "", "Target URL (required)")
	verifyAuthCmd.Flags().StringVar(&authMethod, "method", "GET", "HTTP method")
	verifyAuthCmd.Flags().StringVar(&authToken, "token", "", "Valid auth token for baseline (required)")
	verifyAuthCmd.Flags().StringVar(&authTechnique, "technique", "", "Technique: no_token, expired_token, alg_none, method_override (required)")
	verifyAuthCmd.Flags().StringSliceVar(&authHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyAuthCmd.Flags().StringSliceVar(&authInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8)")
	verifyAuthCmd.Flags().IntVar(&authMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyAuthCmd.Flags().IntVar(&authThrottle, "throttle", 500, "Milliseconds between probes")
	verifyAuthCmd.Flags().IntVar(&authTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyAuthCmd.Flags().StringVar(&authEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyAuthCmd.MarkFlagRequired("url")
	_ = verifyAuthCmd.MarkFlagRequired("token")
	_ = verifyAuthCmd.MarkFlagRequired("technique")
	_ = verifyAuthCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyAuthCmd)
}

func runVerifyAuth(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(authHeaders)

	cfg := verify.AuthConfig{
		URL:       authURL,
		Method:    authMethod,
		Token:     authToken,
		Technique: authTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    authInScope,
			MaxRisk:    authMaxRisk,
			ThrottleMs: authThrottle,
			TimeoutSec: authTimeout,
			Headers:    headers,
			Evidence:   authEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyAuth(cfg)
	})
}
