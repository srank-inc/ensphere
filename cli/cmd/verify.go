package cmd

import (
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vulnerabilities with targeted probes",
	Long: `Run targeted verification probes against specific vulnerability types.

Available subcommands:
  sqli    Verify SQL injection (blind_time, blind_boolean, error_based)
  rls     Verify Supabase RLS tenant isolation
  idor    Verify insecure direct object reference
  xss     Verify reflected cross-site scripting
  ssrf    Verify server-side request forgery
  auth    Verify authentication bypass (no_token, expired_token, alg_none, method_override)`,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
