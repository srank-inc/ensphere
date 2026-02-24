package checklist

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// ListChecklists returns summaries of all embedded checklists.
func ListChecklists() ([]ChecklistSummary, error) {
	entries, err := fs.ReadDir(embeddedData, "data")
	if err != nil {
		return nil, fmt.Errorf("read checklist data dir: %w", err)
	}

	var summaries []ChecklistSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".md")

		content, err := fs.ReadFile(embeddedData, "data/"+entry.Name())
		if err != nil {
			continue
		}

		title := extractTitle(string(content))
		itemCount := countCheckboxes(string(content))

		summaries = append(summaries, ChecklistSummary{
			Name:      name,
			Title:     title,
			ItemCount: itemCount,
		})
	}

	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	return summaries, nil
}

// GetChecklist returns the raw markdown content of a checklist by name.
func GetChecklist(name string) (string, error) {
	data, err := fs.ReadFile(embeddedData, "data/"+name+".md")
	if err != nil {
		return "", fmt.Errorf("checklist %q not found", name)
	}
	return string(data), nil
}

// ChecklistNames returns sorted list of available checklist names.
func ChecklistNames() ([]string, error) {
	entries, err := fs.ReadDir(embeddedData, "data")
	if err != nil {
		return nil, fmt.Errorf("read checklist data dir: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			names = append(names, strings.TrimSuffix(entry.Name(), ".md"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// extractTitle finds the first "# " heading in markdown content.
func extractTitle(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	return ""
}

// countCheckboxes counts "- [ ]" lines in markdown content.
func countCheckboxes(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- [ ]") || strings.HasPrefix(trimmed, "- [x]") {
			count++
		}
	}
	return count
}
