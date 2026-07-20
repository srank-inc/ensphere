package sinks

// SinkPattern represents a single code sink pattern.
type SinkPattern struct {
	Name       string   `json:"name" yaml:"name"`
	Pattern    string   `json:"pattern" yaml:"pattern"`
	Extensions []string `json:"extensions" yaml:"extensions"`
	Filenames  []string `json:"filenames,omitempty" yaml:"filenames,omitempty"`
}

// SinkCategory groups literal review patterns by catalog category.
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

// AbsenceRule represents an IaC security absence pattern.
type AbsenceRule struct {
	Name            string   `json:"name" yaml:"name"`
	Pattern         string   `json:"pattern" yaml:"pattern"`
	SecurityPattern string   `json:"security_pattern" yaml:"security_pattern"`
	Window          int      `json:"window" yaml:"window"`
	Extensions      []string `json:"extensions" yaml:"extensions"`
}
