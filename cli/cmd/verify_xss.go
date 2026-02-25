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
	xssURL      string
	xssParam    string
	xssPayload  string
	xssMethod   string
	xssHeaders  []string
	xssInScope  []string
	xssMaxRisk  int
	xssThrottle int
	xssTimeout  int
	xssEvidence string
)

var verifyXSSCmd = &cobra.Command{
	Use:   "xss",
	Short: "Verify reflected cross-site scripting",
	Long: `Verify reflected XSS by injecting a payload and checking if it appears unencoded in the response.

Examples:
  ensphere verify xss --url "http://target/search" --param q --payload "<script>alert(1)</script>" --in-scope "*.target.com"
  ensphere verify xss --url "http://target/api" --param name --payload "<img src=x onerror=alert(1)>" --method POST --in-scope "*.target.com"`,
	RunE: runVerifyXSS,
}

func init() {
	verifyXSSCmd.Flags().StringVar(&xssURL, "url", "", "Target URL (required)")
	verifyXSSCmd.Flags().StringVar(&xssParam, "param", "", "Parameter name to inject (required)")
	verifyXSSCmd.Flags().StringVar(&xssPayload, "payload", "", "XSS payload string (required)")
	verifyXSSCmd.Flags().StringVar(&xssMethod, "method", "GET", "HTTP method: GET or POST")
	verifyXSSCmd.Flags().StringSliceVar(&xssHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyXSSCmd.Flags().StringSliceVar(&xssInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8)")
	verifyXSSCmd.Flags().IntVar(&xssMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyXSSCmd.Flags().IntVar(&xssThrottle, "throttle", 500, "Milliseconds between probes")
	verifyXSSCmd.Flags().IntVar(&xssTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyXSSCmd.Flags().StringVar(&xssEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyXSSCmd.MarkFlagRequired("url")
	_ = verifyXSSCmd.MarkFlagRequired("param")
	_ = verifyXSSCmd.MarkFlagRequired("payload")
	_ = verifyXSSCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyXSSCmd)
}

func runVerifyXSS(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range xssHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.XSSConfig{
		URL:     xssURL,
		Param:   xssParam,
		Payload: xssPayload,
		Method:  xssMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    xssInScope,
			MaxRisk:    xssMaxRisk,
			ThrottleMs: xssThrottle,
			TimeoutSec: xssTimeout,
			Headers:    headers,
			Evidence:   xssEvidence,
		},
	}

	result, err := verify.VerifyXSS(cfg)
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
