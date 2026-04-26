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
	sqliURL       string
	sqliParam     string
	sqliDB        string
	sqliTechnique string
	sqliMethod    string
	sqliHeaders   []string
	sqliBoundary  string
	sqliInScope   []string
	sqliMaxRisk   int
	sqliThrottle  int
	sqliTimeout   int
	sqliEvidence  string
)

var verifySQLiCmd = &cobra.Command{
	Use:   "sqli",
	Short: "Verify SQL injection vulnerability",
	Long: `Verify SQL injection with targeted probes.

Techniques:
  blind_time     Inject a DB-specific delay payload and measure response delay (default)
  blind_boolean  Compare responses for true/false conditions
  error_based    Check for DB-specific error signatures in response

Examples:
  ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --in-scope *.localhost
  ensphere verify sqli --url http://localhost:3000/rest/products/search?q=test --param q --db sqlite --technique blind_boolean --in-scope localhost
  ensphere verify sqli --url http://app.test/items?id=1 --param id --db mysql --technique error_based --in-scope *.test`,
	RunE: runVerifySQLi,
}

func init() {
	verifySQLiCmd.Flags().StringVar(&sqliURL, "url", "", "Target URL with injectable parameter (required)")
	verifySQLiCmd.Flags().StringVar(&sqliParam, "param", "", "Query parameter name to inject (required)")
	verifySQLiCmd.Flags().StringVar(&sqliDB, "db", "postgres", "Database engine: postgres, mysql, mssql, sqlite")
	verifySQLiCmd.Flags().StringVar(&sqliTechnique, "technique", "blind_time", "Technique: blind_time, blind_boolean, error_based")
	verifySQLiCmd.Flags().StringVar(&sqliMethod, "method", "GET", "HTTP method: GET or POST")
	verifySQLiCmd.Flags().StringSliceVar(&sqliHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifySQLiCmd.Flags().StringVar(&sqliBoundary, "string-boundary", "single_quote", "String boundary: single_quote, double_quote, numeric")
	verifySQLiCmd.Flags().StringSliceVar(&sqliInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8)")
	verifySQLiCmd.Flags().IntVar(&sqliMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifySQLiCmd.Flags().IntVar(&sqliThrottle, "throttle", 500, "Milliseconds between probes")
	verifySQLiCmd.Flags().IntVar(&sqliTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifySQLiCmd.Flags().StringVar(&sqliEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifySQLiCmd.MarkFlagRequired("url")
	_ = verifySQLiCmd.MarkFlagRequired("param")
	_ = verifySQLiCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifySQLiCmd)
}

func runVerifySQLi(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range sqliHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.SQLiConfig{
		URL:       sqliURL,
		Param:     sqliParam,
		DBEngine:  sqliDB,
		Technique: sqliTechnique,
		Method:    sqliMethod,
		Boundary:  sqliBoundary,
		ProbeConfig: verify.ProbeConfig{
			InScope:    sqliInScope,
			MaxRisk:    sqliMaxRisk,
			ThrottleMs: sqliThrottle,
			TimeoutSec: sqliTimeout,
			Headers:    headers,
			Evidence:   sqliEvidence,
		},
	}

	result, err := verify.VerifySQLi(cfg)
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

func splitOnce(s, sep string) []string {
	idx := -1
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			idx = i
			break
		}
	}
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}
