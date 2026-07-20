package templates

// TemplateConfig is the parsed template.json for a measurement template.
type TemplateConfig struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	VulnType          string          `json:"vuln_type"`
	Technique         string          `json:"technique"`
	AuthMethod        string          `json:"auth_method,omitempty"`
	IDPattern         string          `json:"id_pattern,omitempty"`
	Risk              int             `json:"risk"`
	RunCommand        string          `json:"run_command"`
	ObservationFields []string        `json:"observation_fields"`
	Params            []TemplateParam `json:"params"`
	Files             []string        `json:"files"`
}

// TemplateParam describes a configurable parameter in a template.
type TemplateParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Example     string `json:"example"`
	Required    bool   `json:"required"`
}

// TemplateSummary is the JSON output for --list.
type TemplateSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	VulnType    string `json:"vuln_type"`
	Technique   string `json:"technique"`
	Risk        int    `json:"risk"`
	ParamCount  int    `json:"param_count"`
	RunCommand  string `json:"run_command"`
}
