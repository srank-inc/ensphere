package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	ssrfURL         string
	ssrfParam       string
	ssrfCallbackURL string
	ssrfMethod      string
	ssrfHeaders     []string
	ssrfInScope     []string
	ssrfMaxRisk     int
	ssrfThrottle    int
	ssrfTimeout     int
	ssrfEvidence    string
)

var verifySSRFCmd = &cobra.Command{
	Use:   "ssrf",
	Short: "Verify server-side request forgery",
	Long: `Verify SSRF by injecting internal URLs and checking for metadata signatures or response differences.

Examples:
  ensphere verify ssrf --url "http://target/fetch" --param url --in-scope "*.target.com"
  ensphere verify ssrf --url "http://target/proxy" --param url --callback-url "https://attacker.com/cb" --in-scope "*.target.com"`,
	RunE: runVerifySSRF,
}

func init() {
	verifySSRFCmd.Flags().StringVar(&ssrfURL, "url", "", "Target URL (required)")
	verifySSRFCmd.Flags().StringVar(&ssrfParam, "param", "", "Parameter name to inject (required)")
	verifySSRFCmd.Flags().StringVar(&ssrfCallbackURL, "callback-url", "", "External callback URL for blind SSRF")
	verifySSRFCmd.Flags().StringVar(&ssrfMethod, "method", "GET", "HTTP method")
	verifySSRFCmd.Flags().StringSliceVar(&ssrfHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifySSRFCmd.Flags().StringSliceVar(&ssrfInScope, "in-scope", nil, "In-scope hostname patterns (required, repeatable)")
	verifySSRFCmd.Flags().IntVar(&ssrfMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifySSRFCmd.Flags().IntVar(&ssrfThrottle, "throttle", 500, "Milliseconds between probes")
	verifySSRFCmd.Flags().IntVar(&ssrfTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifySSRFCmd.Flags().StringVar(&ssrfEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifySSRFCmd.MarkFlagRequired("url")
	_ = verifySSRFCmd.MarkFlagRequired("param")
	_ = verifySSRFCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifySSRFCmd)
}

func runVerifySSRF(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range ssrfHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.SSRFConfig{
		URL:         ssrfURL,
		Param:       ssrfParam,
		CallbackURL: ssrfCallbackURL,
		Method:      ssrfMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ssrfInScope,
			MaxRisk:    ssrfMaxRisk,
			ThrottleMs: ssrfThrottle,
			TimeoutSec: ssrfTimeout,
			Headers:    headers,
			Evidence:   ssrfEvidence,
		},
	}

	result, err := verify.VerifySSRF(cfg)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	if result.Status == "confirmed" || result.Status == "potential" {
		os.Exit(1)
	}
	return nil
}
