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
	smugglingURL       string
	smugglingTechnique string
	smugglingHeaders   []string
	smugglingInScope   []string
	smugglingMaxRisk   int
	smugglingThrottle  int
	smugglingTimeout   int
	smugglingEvidence  string
)

var verifySmugglingCmd = &cobra.Command{
	Use:   "smuggling",
	Short: "Verify request smuggling vulnerability",
	Long: `Verify HTTP request smuggling via CL-TE/TE-CL/TE-TE differential timing.

Techniques:
  cl_te  Content-Length vs Transfer-Encoding confusion
  te_cl  Transfer-Encoding vs Content-Length confusion
  te_te  Obfuscated Transfer-Encoding header

Examples:
  ensphere verify smuggling --url "http://target/" --technique cl_te --in-scope "*.target.com"
  ensphere verify smuggling --url "http://target/" --technique te_cl --in-scope "*.target.com"`,
	RunE: runVerifySmuggling,
}

func init() {
	verifySmugglingCmd.Flags().StringVar(&smugglingURL, "url", "", "Target URL (required)")
	verifySmugglingCmd.Flags().StringVar(&smugglingTechnique, "technique", "", "Technique: cl_te, te_cl, te_te (required)")
	verifySmugglingCmd.Flags().StringSliceVar(&smugglingHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifySmugglingCmd.Flags().StringSliceVar(&smugglingInScope, "in-scope", nil, "In-scope patterns (required)")
	verifySmugglingCmd.Flags().IntVar(&smugglingMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifySmugglingCmd.Flags().IntVar(&smugglingThrottle, "throttle", 500, "Milliseconds between probes")
	verifySmugglingCmd.Flags().IntVar(&smugglingTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifySmugglingCmd.Flags().StringVar(&smugglingEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifySmugglingCmd.MarkFlagRequired("url")
	_ = verifySmugglingCmd.MarkFlagRequired("technique")
	_ = verifySmugglingCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifySmugglingCmd)
}

func runVerifySmuggling(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range smugglingHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.SmugglingConfig{
		URL:       smugglingURL,
		Technique: smugglingTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    smugglingInScope,
			MaxRisk:    smugglingMaxRisk,
			ThrottleMs: smugglingThrottle,
			TimeoutSec: smugglingTimeout,
			Headers:    headers,
			Evidence:   smugglingEvidence,
		},
	}

	result, err := verify.VerifySmuggling(cfg)
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
