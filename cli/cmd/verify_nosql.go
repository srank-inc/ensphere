package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	nosqlURL       string
	nosqlParam     string
	nosqlTechnique string
	nosqlMethod    string
	nosqlHeaders   []string
	nosqlInScope   []string
	nosqlMaxRisk   int
	nosqlThrottle  int
	nosqlTimeout   int
	nosqlEvidence  string
)

var verifyNoSQLCmd = &cobra.Command{
	Use:   "nosql",
	Short: "Verify NoSQL injection vulnerability",
	Long: `Verify NoSQL injection with operator injection or time-based probes.

Techniques:
  operator_injection  Inject MongoDB operators ($gt, $ne) and compare responses (default)
  where_time          Inject $where with sleep and measure delay

Examples:
  ensphere verify nosql --url "http://target/api/login" --param username --in-scope "*.target.com"
  ensphere verify nosql --url "http://target/api/search" --param q --technique where_time --in-scope "*.target.com"`,
	RunE: runVerifyNoSQL,
}

func init() {
	verifyNoSQLCmd.Flags().StringVar(&nosqlURL, "url", "", "Target URL (required)")
	verifyNoSQLCmd.Flags().StringVar(&nosqlParam, "param", "", "Parameter/field name (required)")
	verifyNoSQLCmd.Flags().StringVar(&nosqlTechnique, "technique", "operator_injection", "Technique: operator_injection, where_time")
	verifyNoSQLCmd.Flags().StringVar(&nosqlMethod, "method", "POST", "HTTP method")
	verifyNoSQLCmd.Flags().StringSliceVar(&nosqlHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyNoSQLCmd.Flags().StringSliceVar(&nosqlInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyNoSQLCmd.Flags().IntVar(&nosqlMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyNoSQLCmd.Flags().IntVar(&nosqlThrottle, "throttle", 500, "Milliseconds between probes")
	verifyNoSQLCmd.Flags().IntVar(&nosqlTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyNoSQLCmd.Flags().StringVar(&nosqlEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyNoSQLCmd.MarkFlagRequired("url")
	_ = verifyNoSQLCmd.MarkFlagRequired("param")
	_ = verifyNoSQLCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyNoSQLCmd)
}

func runVerifyNoSQL(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(nosqlHeaders)

	cfg := verify.NoSQLConfig{
		URL:       nosqlURL,
		Param:     nosqlParam,
		Technique: nosqlTechnique,
		Method:    nosqlMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    nosqlInScope,
			MaxRisk:    nosqlMaxRisk,
			ThrottleMs: nosqlThrottle,
			TimeoutSec: nosqlTimeout,
			Headers:    headers,
			Evidence:   nosqlEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyNoSQL(cfg)
	})
}
