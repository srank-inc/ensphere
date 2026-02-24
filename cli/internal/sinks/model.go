package sinks

// SinkPattern represents a single code sink pattern.
type SinkPattern struct {
	Name        string   `json:"name" yaml:"name"`
	Pattern     string   `json:"pattern" yaml:"pattern"`
	Extensions  []string `json:"extensions" yaml:"extensions"`
	Description string   `json:"description" yaml:"description"`
	Risk        int      `json:"risk" yaml:"risk"`
}

// SinkCategory groups patterns by vulnerability type.
type SinkCategory struct {
	Category string        `json:"category"`
	Count    int           `json:"count"`
	Patterns []SinkPattern `json:"patterns"`
}

// SinkSummary is used for the list view.
type SinkSummary struct {
	Name         string `json:"name"`
	PatternCount int    `json:"pattern_count"`
}

// SinkListOutput is the JSON output for the summary view.
type SinkListOutput struct {
	Categories []SinkSummary `json:"categories"`
}
