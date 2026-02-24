package checklist

// ChecklistSummary is the JSON output for --list.
type ChecklistSummary struct {
	Name      string `json:"name"`
	Title     string `json:"title"`
	ItemCount int    `json:"item_count"`
}
