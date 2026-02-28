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
	ratelimitURL        string
	ratelimitMethod     string
	ratelimitBody       string
	ratelimitToken      string
	ratelimitBurstCount int
	ratelimitWindowSec  int
	ratelimitHeaders    []string
	ratelimitInScope    []string
	ratelimitMaxRisk    int
	ratelimitThrottle   int
	ratelimitTimeout    int
	ratelimitEvidence   string
)

var verifyRateLimitCmd = &cobra.Command{
	Use:   "ratelimit",
	Short: "Verify rate limiting behavior",
	Long: `Measure rate limiting by sending sequential request bursts.

Sends N requests as fast as possible within a time window and records response distribution.

Examples:
  ensphere verify ratelimit --url "http://target/api/login" --method POST --burst-count 100 --window-sec 10 --in-scope "*.target.com"
  ensphere verify ratelimit --url "http://target/api/data" --method GET --burst-count 50 --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyRateLimit,
}

func init() {
	verifyRateLimitCmd.Flags().StringVar(&ratelimitURL, "url", "", "Target URL (required)")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitMethod, "method", "POST", "HTTP method")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitBody, "body", "", "Request body")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitToken, "token", "", "Auth token")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitBurstCount, "burst-count", 50, "Number of sequential requests")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitWindowSec, "window-sec", 10, "Time window in seconds")
	verifyRateLimitCmd.Flags().StringSliceVar(&ratelimitHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyRateLimitCmd.Flags().StringSliceVar(&ratelimitInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitThrottle, "throttle", 500, "Milliseconds between probes")
	verifyRateLimitCmd.Flags().IntVar(&ratelimitTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyRateLimitCmd.Flags().StringVar(&ratelimitEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyRateLimitCmd.MarkFlagRequired("url")
	_ = verifyRateLimitCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyRateLimitCmd)
}

func runVerifyRateLimit(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range ratelimitHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.RateLimitConfig{
		URL:        ratelimitURL,
		Method:     ratelimitMethod,
		Body:       ratelimitBody,
		Token:      ratelimitToken,
		BurstCount: ratelimitBurstCount,
		WindowSec:  ratelimitWindowSec,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ratelimitInScope,
			MaxRisk:    ratelimitMaxRisk,
			ThrottleMs: ratelimitThrottle,
			TimeoutSec: ratelimitTimeout,
			Headers:    headers,
			Evidence:   ratelimitEvidence,
		},
	}

	result, err := verify.VerifyRateLimit(cfg)
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
