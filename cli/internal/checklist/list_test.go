package checklist

import (
	"sort"
	"strings"
	"testing"
)

func TestListChecklistsAndNames(t *testing.T) {
	summaries, err := ListChecklists()
	if err != nil {
		t.Fatalf("ListChecklists: %v", err)
	}
	if len(summaries) == 0 {
		t.Fatal("expected checklists")
	}
	names, err := ChecklistNames()
	if err != nil {
		t.Fatalf("ChecklistNames: %v", err)
	}
	if len(names) != len(summaries) {
		t.Fatalf("names=%d summaries=%d", len(names), len(summaries))
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("checklist names not sorted: %v", names)
	}
	for _, summary := range summaries {
		if summary.Name == "" || summary.Title == "" || summary.ItemCount == 0 {
			t.Fatalf("unexpected checklist summary: %+v", summary)
		}
	}
}

func TestGetChecklistAndInvalidName(t *testing.T) {
	content, err := GetChecklist("django")
	if err != nil {
		t.Fatalf("GetChecklist: %v", err)
	}
	if !strings.Contains(content, "# ") {
		t.Fatalf("expected markdown heading, got %q", content[:min(len(content), 80)])
	}
	if _, err := GetChecklist("missing"); err == nil {
		t.Fatal("expected missing checklist error")
	}
}

func TestMarkdownHelpers(t *testing.T) {
	content := "# Title\n\n- [ ] One\n- [x] Two\n"
	if got := extractTitle(content); got != "Title" {
		t.Fatalf("expected Title, got %s", got)
	}
	if got := countCheckboxes(content); got != 2 {
		t.Fatalf("expected 2 checkboxes, got %d", got)
	}
}
