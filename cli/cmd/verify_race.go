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
	raceURL         string
	raceMethod      string
	raceBody        string
	raceToken       string
	raceConcurrency int
	raceHeaders     []string
	raceInScope     []string
	raceMaxRisk     int
	raceThrottle    int
	raceTimeout     int
	raceEvidence    string
)

var verifyRaceCmd = &cobra.Command{
	Use:   "race",
	Short: "Verify race condition vulnerability",
	Long: `Verify race conditions by sending concurrent request bursts.

Sends N identical requests in parallel and measures response distribution.

Examples:
  ensphere verify race --url "http://target/api/redeem" --method POST --body '{"code":"PROMO"}' --in-scope "*.target.com"
  ensphere verify race --url "http://target/api/transfer" --concurrency 20 --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyRace,
}

func init() {
	verifyRaceCmd.Flags().StringVar(&raceURL, "url", "", "Target URL (required)")
	verifyRaceCmd.Flags().StringVar(&raceMethod, "method", "POST", "HTTP method")
	verifyRaceCmd.Flags().StringVar(&raceBody, "body", "", "Request body")
	verifyRaceCmd.Flags().StringVar(&raceToken, "token", "", "Auth token")
	verifyRaceCmd.Flags().IntVar(&raceConcurrency, "concurrency", 10, "Number of concurrent requests")
	verifyRaceCmd.Flags().StringSliceVar(&raceHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyRaceCmd.Flags().StringSliceVar(&raceInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyRaceCmd.Flags().IntVar(&raceMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyRaceCmd.Flags().IntVar(&raceThrottle, "throttle", 500, "Milliseconds between probes")
	verifyRaceCmd.Flags().IntVar(&raceTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyRaceCmd.Flags().StringVar(&raceEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyRaceCmd.MarkFlagRequired("url")
	_ = verifyRaceCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyRaceCmd)
}

func runVerifyRace(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range raceHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.RaceConfig{
		URL:         raceURL,
		Method:      raceMethod,
		Body:        raceBody,
		Token:       raceToken,
		Concurrency: raceConcurrency,
		ProbeConfig: verify.ProbeConfig{
			InScope:    raceInScope,
			MaxRisk:    raceMaxRisk,
			ThrottleMs: raceThrottle,
			TimeoutSec: raceTimeout,
			Headers:    headers,
			Evidence:   raceEvidence,
		},
	}

	result, err := verify.VerifyRace(cfg)
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
