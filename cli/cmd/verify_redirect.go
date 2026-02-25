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
	redirectURL      string
	redirectParam    string
	redirectMethod   string
	redirectHeaders  []string
	redirectInScope  []string
	redirectMaxRisk  int
	redirectThrottle int
	redirectTimeout  int
	redirectEvidence string
)

var verifyRedirectCmd = &cobra.Command{
	Use:   "redirect",
	Short: "Verify open redirect vulnerability",
	Long: `Verify open redirect by injecting an external URL and checking the Location header.

Examples:
  ensphere verify redirect --url "http://target/login?next=/dashboard" --param next --in-scope "*.target.com"
  ensphere verify redirect --url "http://target/goto?url=/" --param url --in-scope "*.target.com"`,
	RunE: runVerifyRedirect,
}

func init() {
	verifyRedirectCmd.Flags().StringVar(&redirectURL, "url", "", "Target URL (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectParam, "param", "", "Redirect parameter name (required)")
	verifyRedirectCmd.Flags().StringVar(&redirectMethod, "method", "GET", "HTTP method")
	verifyRedirectCmd.Flags().StringSliceVar(&redirectHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyRedirectCmd.Flags().StringSliceVar(&redirectInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyRedirectCmd.Flags().IntVar(&redirectMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyRedirectCmd.Flags().IntVar(&redirectThrottle, "throttle", 500, "Milliseconds between probes")
	verifyRedirectCmd.Flags().IntVar(&redirectTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyRedirectCmd.Flags().StringVar(&redirectEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyRedirectCmd.MarkFlagRequired("url")
	_ = verifyRedirectCmd.MarkFlagRequired("param")
	_ = verifyRedirectCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyRedirectCmd)
}

func runVerifyRedirect(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range redirectHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.RedirectConfig{
		URL:    redirectURL,
		Param:  redirectParam,
		Method: redirectMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    redirectInScope,
			MaxRisk:    redirectMaxRisk,
			ThrottleMs: redirectThrottle,
			TimeoutSec: redirectTimeout,
			Headers:    headers,
			Evidence:   redirectEvidence,
		},
	}

	result, err := verify.VerifyRedirect(cfg)
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
