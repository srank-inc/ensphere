package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	grpcURL       string
	grpcTechnique string
	grpcHeaders   []string
	grpcInScope   []string
	grpcMaxRisk   int
	grpcThrottle  int
	grpcTimeout   int
	grpcEvidence  string
)

var verifyGRPCCmd = &cobra.Command{
	Use:   "grpc",
	Short: "Verify gRPC security",
	Long: `Verify gRPC security via reflection probing and plaintext transport detection.

Techniques:
  grpc_reflection  Check if gRPC server reflection is enabled (exposes service inventory)
  grpc_plaintext   Check if server accepts plaintext (h2c) vs requiring TLS

Examples:
  ensphere verify grpc --url "https://target:50051" --technique grpc_reflection --in-scope "*.target.com"
  ensphere verify grpc --url "http://target:50051" --technique grpc_plaintext --in-scope "*.target.com"`,
	RunE: runVerifyGRPC,
}

func init() {
	verifyGRPCCmd.Flags().StringVar(&grpcURL, "url", "", "Target gRPC URL (required)")
	verifyGRPCCmd.Flags().StringVar(&grpcTechnique, "technique", "", "Technique: grpc_reflection, grpc_plaintext (required)")
	verifyGRPCCmd.Flags().StringSliceVar(&grpcHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyGRPCCmd.Flags().StringSliceVar(&grpcInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyGRPCCmd.Flags().IntVar(&grpcMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyGRPCCmd.Flags().IntVar(&grpcThrottle, "throttle", 500, "Milliseconds between probes")
	verifyGRPCCmd.Flags().IntVar(&grpcTimeout, "timeout", 10, "Request timeout in seconds")
	verifyGRPCCmd.Flags().StringVar(&grpcEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyGRPCCmd.MarkFlagRequired("url")
	_ = verifyGRPCCmd.MarkFlagRequired("technique")
	_ = verifyGRPCCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyGRPCCmd)
}

func runVerifyGRPC(cmd *cobra.Command, args []string) error {
	headers := mustParseHeaders(grpcHeaders)

	cfg := verify.GRPCConfig{
		URL:       grpcURL,
		Technique: grpcTechnique,
		ProbeConfig: verify.ProbeConfig{
			InScope:    grpcInScope,
			MaxRisk:    grpcMaxRisk,
			ThrottleMs: grpcThrottle,
			TimeoutSec: grpcTimeout,
			Headers:    headers,
			Evidence:   grpcEvidence,
		},
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyGRPC(cfg)
	})
}
