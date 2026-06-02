package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	deserURL       string
	deserRuntime   string
	deserMethod    string
	deserTechnique string
	deserHeaders   []string
	deserInScope   []string
	deserMaxRisk   int
	deserThrottle  int
	deserTimeout   int
	deserEvidence  string
)

var verifyDeserializationCmd = &cobra.Command{
	Use:   "deserialization",
	Short: "Verify insecure deserialization",
	Long: `Verify insecure deserialization with time-based blind probes.

Runtimes: java, python, php, node

Examples:
  ensphere verify deserialization --url "http://target/api" --runtime python --max-risk 4 --in-scope "*.target.com"
  ensphere verify deserialization --url "http://target/deserialize" --runtime java --max-risk 4 --in-scope "*.target.com"`,
	RunE: runVerifyDeserialization,
}

func init() {
	verifyDeserializationCmd.Flags().StringVar(&deserURL, "url", "", "Target URL (required)")
	verifyDeserializationCmd.Flags().StringVar(&deserRuntime, "runtime", "", "Target runtime: java, python, php, node (required)")
	verifyDeserializationCmd.Flags().StringVar(&deserMethod, "method", "POST", "HTTP method")
	verifyDeserializationCmd.Flags().StringVar(&deserTechnique, "technique", "time_based", "Technique: time_based")
	verifyDeserializationCmd.Flags().StringSliceVar(&deserHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyDeserializationCmd.Flags().StringSliceVar(&deserInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyDeserializationCmd.Flags().IntVar(&deserMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyDeserializationCmd.Flags().IntVar(&deserThrottle, "throttle", 500, "Milliseconds between probes")
	verifyDeserializationCmd.Flags().IntVar(&deserTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyDeserializationCmd.Flags().StringVar(&deserEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyDeserializationCmd.MarkFlagRequired("url")
	_ = verifyDeserializationCmd.MarkFlagRequired("runtime")
	_ = verifyDeserializationCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyDeserializationCmd)
}

func runVerifyDeserialization(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(deserHeaders)

	cfg := verify.DeserializationConfig{
		URL:       deserURL,
		Runtime:   deserRuntime,
		Method:    deserMethod,
		Technique: deserTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    deserInScope,
			MaxRisk:    deserMaxRisk,
			ThrottleMs: deserThrottle,
			TimeoutSec: deserTimeout,
			Headers:    headers,
			Evidence:   deserEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyDeserialization(cfg)
	})
}
