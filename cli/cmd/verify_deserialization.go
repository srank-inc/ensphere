package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

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
  ensphere verify deserialization --url "http://target/api" --runtime python --in-scope "*.target.com"
  ensphere verify deserialization --url "http://target/deserialize" --runtime java --in-scope "*.target.com"`,
	RunE: runVerifyDeserialization,
}

func init() {
	verifyDeserializationCmd.Flags().StringVar(&deserURL, "url", "", "Target URL (required)")
	verifyDeserializationCmd.Flags().StringVar(&deserRuntime, "runtime", "", "Target runtime: java, python, php, node (required)")
	verifyDeserializationCmd.Flags().StringVar(&deserMethod, "method", "POST", "HTTP method")
	verifyDeserializationCmd.Flags().StringVar(&deserTechnique, "technique", "time_based", "Technique: time_based, dns_oob")
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
	headers := make(map[string]string)
	for _, h := range deserHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

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

	result, err := verify.VerifyDeserialization(cfg)
	if err != nil {
		var scopeErr *verify.ScopeError
		if errors.As(err, &scopeErr) {
			fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
		os.Exit(3)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
