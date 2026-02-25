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
	ppURL       string
	ppMethod    string
	ppTechnique string
	ppHeaders   []string
	ppInScope   []string
	ppMaxRisk   int
	ppThrottle  int
	ppTimeout   int
	ppEvidence  string
)

var verifyProtoPollutionCmd = &cobra.Command{
	Use:   "protopollution",
	Short: "Verify prototype pollution vulnerability",
	Long: `Verify prototype pollution by injecting __proto__ or constructor.prototype payloads.

Techniques: proto_assignment, constructor_pollution, json_merge

Examples:
  ensphere verify protopollution --url "http://target/api/config" --in-scope "*.target.com"
  ensphere verify protopollution --url "http://target/api/merge" --technique json_merge --in-scope "*.target.com"`,
	RunE: runVerifyProtoPollution,
}

func init() {
	verifyProtoPollutionCmd.Flags().StringVar(&ppURL, "url", "", "Target URL (required)")
	verifyProtoPollutionCmd.Flags().StringVar(&ppMethod, "method", "POST", "HTTP method")
	verifyProtoPollutionCmd.Flags().StringVar(&ppTechnique, "technique", "proto_assignment", "Technique: proto_assignment, constructor_pollution, json_merge")
	verifyProtoPollutionCmd.Flags().StringSliceVar(&ppHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyProtoPollutionCmd.Flags().StringSliceVar(&ppInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyProtoPollutionCmd.Flags().IntVar(&ppMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyProtoPollutionCmd.Flags().IntVar(&ppThrottle, "throttle", 500, "Milliseconds between probes")
	verifyProtoPollutionCmd.Flags().IntVar(&ppTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyProtoPollutionCmd.Flags().StringVar(&ppEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyProtoPollutionCmd.MarkFlagRequired("url")
	_ = verifyProtoPollutionCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyProtoPollutionCmd)
}

func runVerifyProtoPollution(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range ppHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.ProtoPollutionConfig{
		URL:       ppURL,
		Method:    ppMethod,
		Technique: ppTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ppInScope,
			MaxRisk:    ppMaxRisk,
			ThrottleMs: ppThrottle,
			TimeoutSec: ppTimeout,
			Headers:    headers,
			Evidence:   ppEvidence,
		},
	}

	result, err := verify.VerifyProtoPollution(cfg)
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
