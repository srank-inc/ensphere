package compliance

// FrameworkEntry represents a single compliance framework mapping.
type FrameworkEntry struct {
	Framework   string   `json:"framework" yaml:"framework"`
	ControlIDs  []string `json:"control_ids" yaml:"control_ids"`
	Description string   `json:"description" yaml:"description"`
}

// ComplianceMapping is the JSON output for a specific vuln_type.
type ComplianceMapping struct {
	VulnType       string           `json:"vuln_type"`
	FrameworkCount int              `json:"framework_count"`
	Mappings       []FrameworkEntry `json:"mappings"`
}

// ComplianceSummary is used for the --list view.
type ComplianceSummary struct {
	VulnType       string `json:"vuln_type"`
	FrameworkCount int    `json:"framework_count"`
}

// ComplianceListOutput is the JSON output for --list.
type ComplianceListOutput struct {
	VulnTypes []ComplianceSummary `json:"vuln_types"`
}
