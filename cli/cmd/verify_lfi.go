package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	lfiURL      string
	lfiParam    string
	lfiOS       string
	lfiMethod   string
	lfiHeaders  []string
	lfiInScope  []string
	lfiMaxRisk  int
	lfiThrottle int
	lfiTimeout  int
	lfiEvidence string
)

var verifyLFICmd = &cobra.Command{
	Use:   "lfi",
	Short: "Verify local file inclusion vulnerability",
	Long: `Verify LFI by injecting path traversal payloads and checking for file content signatures.

Examples:
  ensphere verify lfi --url "http://target/api?file=test" --param file --in-scope "*.target.com"
  ensphere verify lfi --url "http://target/load?path=x" --param path --os windows --in-scope "*.target.com"`,
	RunE: runVerifyLFI,
}

func init() {
	verifyLFICmd.Flags().StringVar(&lfiURL, "url", "", "Target URL (required)")
	verifyLFICmd.Flags().StringVar(&lfiParam, "param", "", "Parameter name to inject (required)")
	verifyLFICmd.Flags().StringVar(&lfiOS, "os", "linux", "Target OS: linux, windows")
	verifyLFICmd.Flags().StringVar(&lfiMethod, "method", "GET", "HTTP method")
	verifyLFICmd.Flags().StringSliceVar(&lfiHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyLFICmd.Flags().StringSliceVar(&lfiInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyLFICmd.Flags().IntVar(&lfiMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyLFICmd.Flags().IntVar(&lfiThrottle, "throttle", 500, "Milliseconds between probes")
	verifyLFICmd.Flags().IntVar(&lfiTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyLFICmd.Flags().StringVar(&lfiEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyLFICmd.MarkFlagRequired("url")
	_ = verifyLFICmd.MarkFlagRequired("param")
	_ = verifyLFICmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyLFICmd)
}

func runVerifyLFI(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(lfiHeaders)

	cfg := verify.LFIConfig{
		URL:    lfiURL,
		Param:  lfiParam,
		OS:     lfiOS,
		Method: lfiMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    lfiInScope,
			MaxRisk:    lfiMaxRisk,
			ThrottleMs: lfiThrottle,
			TimeoutSec: lfiTimeout,
			Headers:    headers,
			Evidence:   lfiEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyLFI(cfg)
	})
}
