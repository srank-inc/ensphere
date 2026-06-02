package cmd

import (
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
	headers := mustParseHeaders(gqlHeaders)

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

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyGraphQL(cfg)
	})
}
