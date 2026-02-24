package payloads

// Payload represents a single curated security testing payload.
type Payload struct {
	ID               string   `json:"id"`
	VulnType         string   `json:"vuln_type"`
	DBEngine         *string  `json:"db_engine,omitempty"`
	Runtime          *string  `json:"runtime,omitempty"`
	Technique        string   `json:"technique"`
	InjectionSurface string   `json:"injection_surface"`
	ContentType      *string  `json:"content_type,omitempty"`
	Encoding         string   `json:"encoding"`
	StringBoundary   *string  `json:"string_boundary,omitempty"`
	EvidenceType     string   `json:"evidence_type"`
	Risk             int      `json:"risk"`
	Payload          string   `json:"payload"`
	Placeholders     []string `json:"placeholders"`
	Notes            string   `json:"notes"`
	Source           string   `json:"source"`
	Tags             []string `json:"tags"`
}

// PayloadFilter holds query parameters for filtering payloads.
type PayloadFilter struct {
	VulnType    string
	DBEngine    string
	Runtime     string
	Technique   string
	Surface     string
	ContentType string
	Encoding    string
	Boundary    string
	Tag         string
	MaxRisk     int
	Limit       int
}

// QueryOutput is the JSON envelope returned by the payloads command.
type QueryOutput struct {
	Query   map[string]any  `json:"query"`
	Count   int             `json:"count"`
	Results []PayloadResult `json:"results"`
}

// PayloadResult is a single result row — payload fields relevant to the consumer.
type PayloadResult struct {
	ID               string   `json:"id"`
	Payload          string   `json:"payload"`
	Technique        string   `json:"technique"`
	InjectionSurface string   `json:"injection_surface"`
	Encoding         string   `json:"encoding"`
	StringBoundary   *string  `json:"string_boundary,omitempty"`
	EvidenceType     string   `json:"evidence_type"`
	Risk             int      `json:"risk"`
	Placeholders     []string `json:"placeholders"`
	Notes            string   `json:"notes"`
	Source           string   `json:"source"`
	Tags             []string `json:"tags"`
}
