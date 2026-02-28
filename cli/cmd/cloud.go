package cmd

import "github.com/spf13/cobra"

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Cloud security verification",
	Long: `Run cloud security verification probes against cloud provider resources.

Available subcommands:
  storage         Verify cloud storage security (S3, GCS, Azure Blob)
  iam             Verify cloud IAM configuration
  network         Verify cloud network security (security groups, firewalls)
  parse-prowler   Parse Prowler JSON-OCSF output
  parse-trivy     Parse Trivy JSON output`,
}

func init() {
	rootCmd.AddCommand(cloudCmd)
}
