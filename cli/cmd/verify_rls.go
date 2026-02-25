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
	rlsProjectURL string
	rlsAnonKey    string
	rlsJWTSecret  string
	rlsTable      string
	rlsTenantA    string
	rlsTenantB    string
	rlsSelect     string
	rlsEvidence   string
	rlsInScope    []string
	rlsThrottle   int
	rlsTimeout    int
)

var verifyRLSCmd = &cobra.Command{
	Use:   "rls",
	Short: "Verify Supabase RLS tenant isolation",
	Long: `Verify Supabase Row Level Security by testing cross-tenant data access.

Constructs JWTs with different company_id claims and queries the PostgREST API
to check if tenant A can read tenant B's data.

Example:
  ensphere verify rls \
    --project-url http://127.0.0.1:54321 \
    --anon-key eyJ... \
    --jwt-secret super-secret-jwt-token-with-at-least-32-characters \
    --table invoices \
    --tenant-a uuid-company-a \
    --tenant-b uuid-company-b \
    --in-scope 127.0.0.1`,
	RunE: runVerifyRLS,
}

func init() {
	verifyRLSCmd.Flags().StringVar(&rlsProjectURL, "project-url", "", "Supabase project URL (required)")
	verifyRLSCmd.Flags().StringVar(&rlsAnonKey, "anon-key", "", "Supabase anon key (required)")
	verifyRLSCmd.Flags().StringVar(&rlsJWTSecret, "jwt-secret", "", "JWT signing secret (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTable, "table", "", "Table to test (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTenantA, "tenant-a", "", "Tenant A company ID (required)")
	verifyRLSCmd.Flags().StringVar(&rlsTenantB, "tenant-b", "", "Tenant B company ID (required)")
	verifyRLSCmd.Flags().StringVar(&rlsSelect, "select", "*", "Columns to select")
	verifyRLSCmd.Flags().StringVar(&rlsEvidence, "evidence", "./evidence.jsonl", "Evidence file path")
	verifyRLSCmd.Flags().StringSliceVar(&rlsInScope, "in-scope", nil, "In-scope patterns: globs (*.example.com) or CIDR (10.0.0.0/8)")
	verifyRLSCmd.Flags().IntVar(&rlsThrottle, "throttle", 500, "Milliseconds between probes")
	verifyRLSCmd.Flags().IntVar(&rlsTimeout, "timeout", 10, "HTTP request timeout in seconds")

	_ = verifyRLSCmd.MarkFlagRequired("project-url")
	_ = verifyRLSCmd.MarkFlagRequired("anon-key")
	_ = verifyRLSCmd.MarkFlagRequired("jwt-secret")
	_ = verifyRLSCmd.MarkFlagRequired("table")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-a")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-b")
	_ = verifyRLSCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyRLSCmd)
}

func runVerifyRLS(cmd *cobra.Command, args []string) error {
	cfg := verify.RLSConfig{
		ProjectURL: rlsProjectURL,
		AnonKey:    rlsAnonKey,
		JWTSecret:  rlsJWTSecret,
		Table:      rlsTable,
		TenantA:    rlsTenantA,
		TenantB:    rlsTenantB,
		Select:     rlsSelect,
		ProbeConfig: verify.ProbeConfig{
			InScope:    rlsInScope,
			ThrottleMs: rlsThrottle,
			TimeoutSec: rlsTimeout,
			Evidence:   rlsEvidence,
		},
	}

	result, err := verify.VerifyRLS(cfg)
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
