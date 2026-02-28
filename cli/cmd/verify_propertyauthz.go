package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	pauthzURL       string
	pauthzMethod    string
	pauthzHighToken string
	pauthzLowToken  string
	pauthzWatch     string
	pauthzHeaders   []string
	pauthzInScope   []string
	pauthzMaxRisk   int
	pauthzThrottle  int
	pauthzTimeout   int
	pauthzEvidence  string
)

var verifyPropertyAuthZCmd = &cobra.Command{
	Use:   "propertyauthz",
	Short: "Verify property-level authorization",
	Long: `Verify property-level authorization by comparing JSON response fields for different privilege levels.

Sends the same request with a high-privilege and low-privilege token and compares top-level JSON keys.

Examples:
  ensphere verify propertyauthz --url "http://target/api/user/profile" --high-token "admin-jwt" --low-token "user-jwt" --in-scope "*.target.com"
  ensphere verify propertyauthz --url "http://target/api/user/1" --high-token "admin" --low-token "user" --watch-fields "ssn,salary,role" --in-scope "*.target.com"`,
	RunE: runVerifyPropertyAuthZ,
}

func init() {
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzURL, "url", "", "Target URL (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzMethod, "method", "GET", "HTTP method")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzHighToken, "high-token", "", "High-privilege auth token (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzLowToken, "low-token", "", "Low-privilege auth token (required)")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzWatch, "watch-fields", "", "Comma-separated fields to watch (optional)")
	verifyPropertyAuthZCmd.Flags().StringSliceVar(&pauthzHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyPropertyAuthZCmd.Flags().StringSliceVar(&pauthzInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyPropertyAuthZCmd.Flags().IntVar(&pauthzMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyPropertyAuthZCmd.Flags().IntVar(&pauthzThrottle, "throttle", 500, "Milliseconds between probes")
	verifyPropertyAuthZCmd.Flags().IntVar(&pauthzTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyPropertyAuthZCmd.Flags().StringVar(&pauthzEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyPropertyAuthZCmd.MarkFlagRequired("url")
	_ = verifyPropertyAuthZCmd.MarkFlagRequired("high-token")
	_ = verifyPropertyAuthZCmd.MarkFlagRequired("low-token")
	_ = verifyPropertyAuthZCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyPropertyAuthZCmd)
}

func runVerifyPropertyAuthZ(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range pauthzHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	var watchFields []string
	if pauthzWatch != "" {
		for _, f := range strings.Split(pauthzWatch, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				watchFields = append(watchFields, f)
			}
		}
	}

	cfg := verify.PropertyAuthZConfig{
		URL:           pauthzURL,
		Method:        pauthzMethod,
		HighPrivToken: pauthzHighToken,
		LowPrivToken:  pauthzLowToken,
		WatchFields:   watchFields,
		ProbeConfig: verify.ProbeConfig{
			InScope:    pauthzInScope,
			MaxRisk:    pauthzMaxRisk,
			ThrottleMs: pauthzThrottle,
			TimeoutSec: pauthzTimeout,
			Headers:    headers,
			Evidence:   pauthzEvidence,
		},
	}

	result, err := verify.VerifyPropertyAuthZ(cfg)
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
