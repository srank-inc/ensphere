package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	sstiURL      string
	sstiParam    string
	sstiEngine   string
	sstiMethod   string
	sstiHeaders  []string
	sstiInScope  []string
	sstiMaxRisk  int
	sstiThrottle int
	sstiTimeout  int
	sstiEvidence string
)

var verifySSTICmd = &cobra.Command{
	Use:   "ssti",
	Short: "Verify server-side template injection",
	Long: `Verify SSTI by injecting template expressions and checking for evaluated output.

Engines: auto (try all), jinja2, twig, freemarker, erb

Examples:
  ensphere verify ssti --url "http://target/search?q=test" --param q --in-scope "*.target.com"
  ensphere verify ssti --url "http://target/render?tpl=x" --param tpl --engine jinja2 --in-scope "*.target.com"`,
	RunE: runVerifySSTI,
}

func init() {
	verifySSTICmd.Flags().StringVar(&sstiURL, "url", "", "Target URL (required)")
	verifySSTICmd.Flags().StringVar(&sstiParam, "param", "", "Parameter name to inject (required)")
	verifySSTICmd.Flags().StringVar(&sstiEngine, "engine", "auto", "Template engine: auto, jinja2, twig, freemarker, erb")
	verifySSTICmd.Flags().StringVar(&sstiMethod, "method", "GET", "HTTP method")
	verifySSTICmd.Flags().StringSliceVar(&sstiHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifySSTICmd.Flags().StringSliceVar(&sstiInScope, "in-scope", nil, "In-scope patterns (required)")
	verifySSTICmd.Flags().IntVar(&sstiMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifySSTICmd.Flags().IntVar(&sstiThrottle, "throttle", 500, "Milliseconds between probes")
	verifySSTICmd.Flags().IntVar(&sstiTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifySSTICmd.Flags().StringVar(&sstiEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifySSTICmd.MarkFlagRequired("url")
	_ = verifySSTICmd.MarkFlagRequired("param")
	_ = verifySSTICmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifySSTICmd)
}

func runVerifySSTI(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(sstiHeaders)

	cfg := verify.SSTIConfig{
		URL:    sstiURL,
		Param:  sstiParam,
		Engine: sstiEngine,
		Method: sstiMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    sstiInScope,
			MaxRisk:    sstiMaxRisk,
			ThrottleMs: sstiThrottle,
			TimeoutSec: sstiTimeout,
			Headers:    headers,
			Evidence:   sstiEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifySSTI(cfg)
	})
}
