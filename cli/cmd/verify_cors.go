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
	corsURL      string
	corsMethod   string
	corsHeaders  []string
	corsInScope  []string
	corsMaxRisk  int
	corsThrottle int
	corsTimeout  int
	corsEvidence string
)

var verifyCORSCmd = &cobra.Command{
	Use:   "cors",
	Short: "Verify CORS misconfiguration",
	Long: `Verify CORS misconfiguration by testing Origin header reflection.

Sends requests with evil, null, and subdomain Origin headers and inspects ACAO response.

Examples:
  ensphere verify cors --url "http://target/api/data" --in-scope "*.target.com"
  ensphere verify cors --url "http://target/api/user" --method OPTIONS --in-scope "*.target.com"`,
	RunE: runVerifyCORS,
}

func init() {
	verifyCORSCmd.Flags().StringVar(&corsURL, "url", "", "Target URL (required)")
	verifyCORSCmd.Flags().StringVar(&corsMethod, "method", "GET", "HTTP method")
	verifyCORSCmd.Flags().StringSliceVar(&corsHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyCORSCmd.Flags().StringSliceVar(&corsInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyCORSCmd.Flags().IntVar(&corsMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyCORSCmd.Flags().IntVar(&corsThrottle, "throttle", 500, "Milliseconds between probes")
	verifyCORSCmd.Flags().IntVar(&corsTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyCORSCmd.Flags().StringVar(&corsEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyCORSCmd.MarkFlagRequired("url")
	_ = verifyCORSCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyCORSCmd)
}

func runVerifyCORS(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range corsHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.CORSConfig{
		URL:    corsURL,
		Method: corsMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    corsInScope,
			MaxRisk:    corsMaxRisk,
			ThrottleMs: corsThrottle,
			TimeoutSec: corsTimeout,
			Headers:    headers,
			Evidence:   corsEvidence,
		},
	}

	result, err := verify.VerifyCORS(cfg)
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
