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
	cpURL       string
	cpTechnique string
	cpHeaders   []string
	cpInScope   []string
	cpMaxRisk   int
	cpThrottle  int
	cpTimeout   int
	cpEvidence  string
)

var verifyCachePoisoningCmd = &cobra.Command{
	Use:   "cachepoisoning",
	Short: "Verify cache poisoning vulnerability",
	Long: `Verify web cache poisoning by injecting unkeyed headers and checking for cache contamination.

Techniques:
  unkeyed_header  Inject X-Forwarded-Host header (default)
  unkeyed_cookie  Inject unexpected cookie value
  fat_get         Inject X-Original-URL header

Examples:
  ensphere verify cachepoisoning --url "http://target/page" --in-scope "*.target.com"
  ensphere verify cachepoisoning --url "http://target/page" --technique fat_get --in-scope "*.target.com"`,
	RunE: runVerifyCachePoisoning,
}

func init() {
	verifyCachePoisoningCmd.Flags().StringVar(&cpURL, "url", "", "Target URL (required)")
	verifyCachePoisoningCmd.Flags().StringVar(&cpTechnique, "technique", "unkeyed_header", "Technique: unkeyed_header, unkeyed_cookie, fat_get")
	verifyCachePoisoningCmd.Flags().StringSliceVar(&cpHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyCachePoisoningCmd.Flags().StringSliceVar(&cpInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyCachePoisoningCmd.Flags().IntVar(&cpMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyCachePoisoningCmd.Flags().IntVar(&cpThrottle, "throttle", 500, "Milliseconds between probes")
	verifyCachePoisoningCmd.Flags().IntVar(&cpTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyCachePoisoningCmd.Flags().StringVar(&cpEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyCachePoisoningCmd.MarkFlagRequired("url")
	_ = verifyCachePoisoningCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyCachePoisoningCmd)
}

func runVerifyCachePoisoning(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range cpHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.CachePoisoningConfig{
		URL:       cpURL,
		Technique: cpTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cpInScope,
			MaxRisk:    cpMaxRisk,
			ThrottleMs: cpThrottle,
			TimeoutSec: cpTimeout,
			Headers:    headers,
			Evidence:   cpEvidence,
		},
	}

	result, err := verify.VerifyCachePoisoning(cfg)
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
