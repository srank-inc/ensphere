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
	xxeURL       string
	xxeTechnique string
	xxeMethod    string
	xxeHeaders   []string
	xxeInScope   []string
	xxeMaxRisk   int
	xxeThrottle  int
	xxeTimeout   int
	xxeEvidence  string
)

var verifyXXECmd = &cobra.Command{
	Use:   "xxe",
	Short: "Verify XML external entity injection",
	Long: `Verify XXE by sending crafted XML with external entity references.

Techniques: file_read, ssrf, oob

Examples:
  ensphere verify xxe --url "http://target/api/xml" --technique file_read --in-scope "*.target.com"
  ensphere verify xxe --url "http://target/upload" --technique ssrf --in-scope "*.target.com"`,
	RunE: runVerifyXXE,
}

func init() {
	verifyXXECmd.Flags().StringVar(&xxeURL, "url", "", "Target URL (required)")
	verifyXXECmd.Flags().StringVar(&xxeTechnique, "technique", "file_read", "Technique: file_read, ssrf, oob")
	verifyXXECmd.Flags().StringVar(&xxeMethod, "method", "POST", "HTTP method")
	verifyXXECmd.Flags().StringSliceVar(&xxeHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyXXECmd.Flags().StringSliceVar(&xxeInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyXXECmd.Flags().IntVar(&xxeMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyXXECmd.Flags().IntVar(&xxeThrottle, "throttle", 500, "Milliseconds between probes")
	verifyXXECmd.Flags().IntVar(&xxeTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyXXECmd.Flags().StringVar(&xxeEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyXXECmd.MarkFlagRequired("url")
	_ = verifyXXECmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyXXECmd)
}

func runVerifyXXE(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range xxeHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.XXEConfig{
		URL:       xxeURL,
		Method:    xxeMethod,
		Technique: xxeTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    xxeInScope,
			MaxRisk:    xxeMaxRisk,
			ThrottleMs: xxeThrottle,
			TimeoutSec: xxeTimeout,
			Headers:    headers,
			Evidence:   xxeEvidence,
		},
	}

	result, err := verify.VerifyXXE(cfg)
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
