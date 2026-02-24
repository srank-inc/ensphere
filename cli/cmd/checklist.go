package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/checklist"
)

var checklistList bool

var checklistCmd = &cobra.Command{
	Use:   "checklist [name]",
	Short: "Framework-specific security checklists",
	Long: `List and display security checklists for common frameworks.

Examples:
  ensphere checklist                      # list available checklists
  ensphere checklist supabase-rls         # print checklist content
  ensphere checklist --list               # JSON output of available checklists`,
	Args: cobra.MaximumNArgs(1),
	RunE: runChecklist,
}

func init() {
	checklistCmd.Flags().BoolVar(&checklistList, "list", false, "List available checklists as JSON")

	rootCmd.AddCommand(checklistCmd)
}

func runChecklist(cmd *cobra.Command, args []string) error {
	if checklistList {
		summaries, err := checklist.ListChecklists()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summaries)
	}

	if len(args) == 0 {
		// No name and no --list: show available checklists as text
		names, err := checklist.ChecklistNames()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Available checklists:\n")
		for _, name := range names {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		fmt.Fprintf(os.Stderr, "\nUse 'ensphere checklist <name>' to view, or '--list' for JSON details.\n")
		return nil
	}

	name := args[0]
	content, err := checklist.GetChecklist(name)
	if err != nil {
		names, _ := checklist.ChecklistNames()
		return fmt.Errorf("unknown checklist %q — available: %s", name, strings.Join(names, ", "))
	}

	fmt.Print(content)
	return nil
}
