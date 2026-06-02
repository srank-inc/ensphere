package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	headerinjURL      string
	headerinjParam    string
	headerinjMethod   string
	headerinjHeaders  []string
	headerinjInScope  []string
	headerinjMaxRisk  int
	headerinjThrottle int
	headerinjTimeout  int
	headerinjEvidence string
)

var verifyHeaderInjectionCmd = &cobra.Command{
	Use:   "headerinjection",
	Short: "Verify CRLF header injection",
	Long: `Verify CRLF header injection by injecting CR+LF into a parameter and checking if an injected header appears in the response.

Examples:
  ensphere verify headerinjection --url "http://target/api" --param q --in-scope "*.target.com"
  ensphere verify headerinjection --url "http://target/redirect" --param next --method GET --in-scope "*.target.com"`,
	RunE: runVerifyHeaderInjection,
}

func init() {
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjURL, "url", "", "Target URL (required)")
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjParam, "param", "", "Parameter name to inject (required)")
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjMethod, "method", "GET", "HTTP method: GET or POST")
	verifyHeaderInjectionCmd.Flags().StringSliceVar(&headerinjHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyHeaderInjectionCmd.Flags().StringSliceVar(&headerinjInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyHeaderInjectionCmd.Flags().IntVar(&headerinjMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyHeaderInjectionCmd.Flags().IntVar(&headerinjThrottle, "throttle", 500, "Milliseconds between probes")
	verifyHeaderInjectionCmd.Flags().IntVar(&headerinjTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyHeaderInjectionCmd.Flags().StringVar(&headerinjEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyHeaderInjectionCmd.MarkFlagRequired("url")
	_ = verifyHeaderInjectionCmd.MarkFlagRequired("param")
	_ = verifyHeaderInjectionCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyHeaderInjectionCmd)
}

func runVerifyHeaderInjection(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(headerinjHeaders)

	cfg := verify.HeaderInjectionConfig{
		URL:    headerinjURL,
		Param:  headerinjParam,
		Method: headerinjMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    headerinjInScope,
			MaxRisk:    headerinjMaxRisk,
			ThrottleMs: headerinjThrottle,
			TimeoutSec: headerinjTimeout,
			Headers:    headers,
			Evidence:   headerinjEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyHeaderInjection(cfg)
	})
}
