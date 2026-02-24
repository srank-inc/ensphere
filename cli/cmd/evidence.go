package cmd

import (
	"github.com/spf13/cobra"
)

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Manage evidence records",
	Long: `Log and query structured evidence entries for security assessment audit trails.

Available subcommands:
  log     Write a new evidence entry
  query   Read and filter evidence entries`,
}

func init() {
	rootCmd.AddCommand(evidenceCmd)
}
