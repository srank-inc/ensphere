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
	headers := make(map[string]string)
	for _, h := range sstiHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

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

	result, err := verify.VerifySSTI(cfg)
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
