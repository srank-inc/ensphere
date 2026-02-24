package cmd

import (
	"encoding/json"
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
    --tenant-b uuid-company-b`,
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

	_ = verifyRLSCmd.MarkFlagRequired("project-url")
	_ = verifyRLSCmd.MarkFlagRequired("anon-key")
	_ = verifyRLSCmd.MarkFlagRequired("jwt-secret")
	_ = verifyRLSCmd.MarkFlagRequired("table")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-a")
	_ = verifyRLSCmd.MarkFlagRequired("tenant-b")

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
		Evidence:   rlsEvidence,
	}

	result, err := verify.VerifyRLS(cfg)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}

	if result.Status == "confirmed" || result.Status == "potential" {
		os.Exit(1)
	}
	return nil
}
