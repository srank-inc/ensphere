package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/templates"
)

var templateOut string
var templateList bool

var templateCmd = &cobra.Command{
	Use:   "template [name]",
	Short: "Exploit templates for common vulnerability patterns",
	Long: `List and materialize exploit templates for common vulnerability patterns.

Examples:
  ensphere template --list                              # JSON list of templates
  ensphere template idor-uuid                           # print files to stdout
  ensphere template sqli-time-postgres --out ./poc/sqli # write to directory`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTemplate,
}

func init() {
	templateCmd.Flags().BoolVar(&templateList, "list", false, "List available templates as JSON")
	templateCmd.Flags().StringVar(&templateOut, "out", "", "Output directory (default: print to stdout)")

	rootCmd.AddCommand(templateCmd)
}

func runTemplate(cmd *cobra.Command, args []string) error {
	if templateList {
		summaries, err := templates.ListTemplates()
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(summaries)
	}

	if len(args) == 0 {
		// No name and no --list: show available templates as text
		names, err := templates.TemplateNames()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Available templates:\n")
		for _, name := range names {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		fmt.Fprintf(os.Stderr, "\nUse 'ensphere template <name>' to view, or '--list' for JSON details.\n")
		return nil
	}

	name := args[0]

	// Validate template name
	names, err := templates.TemplateNames()
	if err != nil {
		return err
	}
	found := false
	for _, n := range names {
		if n == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown template %q — available: %s", name, strings.Join(names, ", "))
	}

	if templateOut != "" {
		if err := templates.Materialize(name, templateOut, nil); err != nil {
			return err
		}
		cfg, _ := templates.GetTemplate(name)
		fmt.Fprintf(os.Stderr, "Template %q written to %s/\n", name, templateOut)
		if cfg != nil {
			fmt.Fprintf(os.Stderr, "Run: cd %s && %s\n", templateOut, cfg.RunCommand)
		}
		return nil
	}

	return templates.Materialize(name, "", os.Stdout)
}
