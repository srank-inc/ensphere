package scan

// ScanMatch represents a single pattern match in a source file.
type ScanMatch struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	PatternName string `json:"pattern_name"`
	Category    string `json:"category"`
	Risk        int    `json:"risk"`
	MatchedText string `json:"matched_text"`
	Context     string `json:"context"`
}

// ScanResult holds the complete output of a scan.
type ScanResult struct {
	Directory    string        `json:"directory"`
	FilesScanned int           `json:"files_scanned"`
	TotalMatches int           `json:"total_matches"`
	Duration     string        `json:"duration"`
	Matches      []ScanMatch   `json:"matches"`
	Summary      []CategoryHit `json:"summary"`
}

// CategoryHit summarizes matches for a single category.
type CategoryHit struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
	MaxRisk  int    `json:"max_risk"`
}

// ScanConfig holds configuration for a scan run.
type ScanConfig struct {
	Directory  string
	Categories []string // filter to these categories; empty = all
	Extensions []string // override file extensions; empty = use pattern defaults
	Excludes   []string // glob patterns to skip
}
