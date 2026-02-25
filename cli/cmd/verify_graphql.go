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
	gqlURL       string
	gqlTechnique string
	gqlToken     string
	gqlMethod    string
	gqlHeaders   []string
	gqlInScope   []string
	gqlMaxRisk   int
	gqlThrottle  int
	gqlTimeout   int
	gqlEvidence  string
)

var verifyGraphQLCmd = &cobra.Command{
	Use:   "graphql",
	Short: "Verify GraphQL abuse vulnerability",
	Long: `Verify GraphQL abuse via introspection, batch queries, or nested query DoS.

Techniques:
  introspection  Check if introspection is enabled
  batch_query    Check if batch queries are accepted
  nested_query_dos     Measure timing of deeply nested queries

Examples:
  ensphere verify graphql --url "http://target/graphql" --technique introspection --in-scope "*.target.com"
  ensphere verify graphql --url "http://target/graphql" --technique batch_query --token "jwt" --in-scope "*.target.com"`,
	RunE: runVerifyGraphQL,
}

func init() {
	verifyGraphQLCmd.Flags().StringVar(&gqlURL, "url", "", "Target GraphQL URL (required)")
	verifyGraphQLCmd.Flags().StringVar(&gqlTechnique, "technique", "", "Technique: introspection, batch_query, nested_query_dos (required)")
	verifyGraphQLCmd.Flags().StringVar(&gqlToken, "token", "", "Auth token (optional)")
	verifyGraphQLCmd.Flags().StringVar(&gqlMethod, "method", "POST", "HTTP method")
	verifyGraphQLCmd.Flags().StringSliceVar(&gqlHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyGraphQLCmd.Flags().StringSliceVar(&gqlInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyGraphQLCmd.Flags().IntVar(&gqlMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyGraphQLCmd.Flags().IntVar(&gqlThrottle, "throttle", 500, "Milliseconds between probes")
	verifyGraphQLCmd.Flags().IntVar(&gqlTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyGraphQLCmd.Flags().StringVar(&gqlEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyGraphQLCmd.MarkFlagRequired("url")
	_ = verifyGraphQLCmd.MarkFlagRequired("technique")
	_ = verifyGraphQLCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyGraphQLCmd)
}

func runVerifyGraphQL(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range gqlHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.GraphQLConfig{
		URL:       gqlURL,
		Technique: gqlTechnique,
		Token:     gqlToken,
		Method:    gqlMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    gqlInScope,
			MaxRisk:    gqlMaxRisk,
			ThrottleMs: gqlThrottle,
			TimeoutSec: gqlTimeout,
			Headers:    headers,
			Evidence:   gqlEvidence,
		},
	}

	result, err := verify.VerifyGraphQL(cfg)
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
