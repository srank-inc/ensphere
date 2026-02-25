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
	cmdiURL      string
	cmdiParam    string
	cmdiOS       string
	cmdiMethod   string
	cmdiHeaders  []string
	cmdiInScope  []string
	cmdiMaxRisk  int
	cmdiThrottle int
	cmdiTimeout  int
	cmdiEvidence string
)

var verifyCMDiCmd = &cobra.Command{
	Use:   "cmdi",
	Short: "Verify command injection vulnerability",
	Long: `Verify command injection with time-based blind probes.

Injects OS-specific sleep commands and measures response delay.

Examples:
  ensphere verify cmdi --url "http://target/api?cmd=test" --param cmd --in-scope "*.target.com"
  ensphere verify cmdi --url "http://target/api?input=1" --param input --os windows --in-scope "*.target.com"`,
	RunE: runVerifyCMDi,
}

func init() {
	verifyCMDiCmd.Flags().StringVar(&cmdiURL, "url", "", "Target URL (required)")
	verifyCMDiCmd.Flags().StringVar(&cmdiParam, "param", "", "Parameter name to inject (required)")
	verifyCMDiCmd.Flags().StringVar(&cmdiOS, "os", "linux", "Target OS: linux, windows")
	verifyCMDiCmd.Flags().StringVar(&cmdiMethod, "method", "GET", "HTTP method")
	verifyCMDiCmd.Flags().StringSliceVar(&cmdiHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyCMDiCmd.Flags().StringSliceVar(&cmdiInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyCMDiCmd.Flags().IntVar(&cmdiMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyCMDiCmd.Flags().IntVar(&cmdiThrottle, "throttle", 500, "Milliseconds between probes")
	verifyCMDiCmd.Flags().IntVar(&cmdiTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyCMDiCmd.Flags().StringVar(&cmdiEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyCMDiCmd.MarkFlagRequired("url")
	_ = verifyCMDiCmd.MarkFlagRequired("param")
	_ = verifyCMDiCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyCMDiCmd)
}

func runVerifyCMDi(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range cmdiHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.CMDiConfig{
		URL:    cmdiURL,
		Param:  cmdiParam,
		OS:     cmdiOS,
		Method: cmdiMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    cmdiInScope,
			MaxRisk:    cmdiMaxRisk,
			ThrottleMs: cmdiThrottle,
			TimeoutSec: cmdiTimeout,
			Headers:    headers,
			Evidence:   cmdiEvidence,
		},
	}

	result, err := verify.VerifyCMDi(cfg)
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
