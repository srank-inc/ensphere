package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/runner"
)

var (
	runWorkspace           string
	runTarget              string
	runSource              string
	runTargetType          string
	runCloud               string
	runInScope             string
	runOutOfScope          string
	runLoginURL            string
	runUsername            string
	runPassword            string
	runExploitEnabled      bool
	runPlanForce           bool
	runSelectedFindingRefs []string
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Orchestrate Ensphere assessment workspace files",
	Long: `Create and inspect the ensphere-pentest workspace used by AI agents.

The runner is conservative: it writes deterministic workspace files,
next-action.md, and agent-prompt.md for Codex, Claude Code, or another agent.
It does not execute AI reasoning or run exploit attempts by itself.`,
}

var runInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create ensphere-pentest workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		if runTarget == "" {
			fmt.Fprintln(os.Stderr, "--target is required")
			os.Exit(2)
		}
		out, err := runner.InitWorkspace(runner.InitConfig{
			Workspace:           runWorkspace,
			TargetURL:           runTarget,
			SourceCode:          runSource,
			TargetType:          runTargetType,
			Cloud:               runCloud,
			InScope:             runInScope,
			OutOfScope:          runOutOfScope,
			LoginURL:            runLoginURL,
			Username:            runUsername,
			Password:            runPassword,
			ExploitationEnabled: runExploitEnabled,
		})
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show workspace progress and next session",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.WorkspaceStatus(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runNextCmd = &cobra.Command{
	Use:   "next",
	Short: "Write gated next-action.md and agent-prompt.md",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.WriteNextAction(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Generate, mirror, or validate assessment-plan.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunPlan(runWorkspace, runPlanForce)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Validate Session 09 report readiness",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunReport(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runFinalCmd = &cobra.Command{
	Use:   "final",
	Short: "Derive Session 11 registry from exploit outcomes",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.RunFinalReport(runWorkspace)
		if err != nil {
			return err
		}
		return encodeRunJSON(out)
	},
}

var runExploitCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Prepare selected findings for optional Session 10",
	RunE: func(cmd *cobra.Command, args []string) error {
		out, err := runner.PrepareExploit(runWorkspace, runSelectedFindingRefs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(2)
		}
		return encodeRunJSON(out)
	},
}

func init() {
	runCmd.PersistentFlags().StringVar(&runWorkspace, "workspace", runner.DefaultWorkspace(), "Ensphere workspace directory")

	runInitCmd.Flags().StringVar(&runTarget, "target", "", "Target URL")
	runInitCmd.Flags().StringVar(&runSource, "source", "yes", "Source code availability: yes or no")
	runInitCmd.Flags().StringVar(&runTargetType, "target-type", "auto", "Target type: auto, web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, or library_or_cli")
	runInitCmd.Flags().StringVar(&runCloud, "cloud", "none", "Cloud scope: none, aws, gcp, azure, kubernetes, or comma-separated")
	runInitCmd.Flags().StringVar(&runInScope, "in-scope", "", "In-scope boundary summary")
	runInitCmd.Flags().StringVar(&runOutOfScope, "out-of-scope", "", "Out-of-scope boundary summary")
	runInitCmd.Flags().StringVar(&runLoginURL, "login-url", "", "Login URL")
	runInitCmd.Flags().StringVar(&runUsername, "username", "", "Test username")
	runInitCmd.Flags().StringVar(&runPassword, "password", "", "Test password")
	runInitCmd.Flags().BoolVar(&runExploitEnabled, "exploitation-enabled", false, "Enable optional Session 10 planning")

	runPlanCmd.Flags().BoolVar(&runPlanForce, "force", false, "Overwrite an existing assessment-plan.yaml from config")
	runExploitCmd.Flags().StringArrayVar(&runSelectedFindingRefs, "finding", nil, "Finding ID to select for Session 10; repeatable")

	runCmd.AddCommand(runInitCmd, runStatusCmd, runNextCmd, runPlanCmd, runReportCmd, runExploitCmd, runFinalCmd)
	rootCmd.AddCommand(runCmd)
}

func encodeRunJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
