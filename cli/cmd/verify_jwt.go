package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	jwtURL       string
	jwtToken     string
	jwtTechnique string
	jwtMethod    string
	jwtHeaders   []string
	jwtInScope   []string
	jwtMaxRisk   int
	jwtThrottle  int
	jwtTimeout   int
	jwtEvidence  string
)

var verifyJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Verify JWT manipulation vulnerability",
	Long: `Verify JWT manipulation by modifying token algorithm or claims.

Techniques:
  alg_none       Change algorithm to "none" and strip signature
  kid_injection  Inject path traversal in kid header claim

Examples:
  ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique alg_none --in-scope "*.target.com"
  ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique kid_injection --in-scope "*.target.com"`,
	RunE: runVerifyJWT,
}

func init() {
	verifyJWTCmd.Flags().StringVar(&jwtURL, "url", "", "Target URL (required)")
	verifyJWTCmd.Flags().StringVar(&jwtToken, "token", "", "Valid JWT token (required)")
	verifyJWTCmd.Flags().StringVar(&jwtTechnique, "technique", "", "Technique: alg_none, kid_injection (required)")
	verifyJWTCmd.Flags().StringVar(&jwtMethod, "method", "GET", "HTTP method")
	verifyJWTCmd.Flags().StringSliceVar(&jwtHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyJWTCmd.Flags().StringSliceVar(&jwtInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyJWTCmd.Flags().IntVar(&jwtMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyJWTCmd.Flags().IntVar(&jwtThrottle, "throttle", 500, "Milliseconds between probes")
	verifyJWTCmd.Flags().IntVar(&jwtTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyJWTCmd.Flags().StringVar(&jwtEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyJWTCmd.MarkFlagRequired("url")
	_ = verifyJWTCmd.MarkFlagRequired("token")
	_ = verifyJWTCmd.MarkFlagRequired("technique")
	_ = verifyJWTCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyJWTCmd)
}

func runVerifyJWT(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(jwtHeaders)

	cfg := verify.JWTConfig{
		URL:       jwtURL,
		Token:     jwtToken,
		Technique: jwtTechnique,
		Method:    jwtMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    jwtInScope,
			MaxRisk:    jwtMaxRisk,
			ThrottleMs: jwtThrottle,
			TimeoutSec: jwtTimeout,
			Headers:    headers,
			Evidence:   jwtEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyJWT(cfg)
	})
}
