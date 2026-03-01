package openapi

// Spec holds parsed OpenAPI specification data.
type Spec struct {
	Title       string     `json:"title"`
	Version     string     `json:"version"`
	Description string     `json:"description,omitempty"`
	Servers     []Server   `json:"servers,omitempty"`
	Endpoints   []Endpoint `json:"endpoints"`
	TotalPaths  int        `json:"total_paths"`
	TotalOps    int        `json:"total_operations"`
}

// Server holds server URL information.
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Endpoint holds a single API endpoint.
type Endpoint struct {
	Method       string       `json:"method"`
	Path         string       `json:"path"`
	OperationID  string       `json:"operation_id,omitempty"`
	Summary      string       `json:"summary,omitempty"`
	Tags         []string     `json:"tags,omitempty"`
	Parameters   []Parameter  `json:"parameters,omitempty"`
	RequestBody  *RequestBody `json:"request_body,omitempty"`
	AuthRequired bool         `json:"auth_required"`
	Deprecated   bool         `json:"deprecated,omitempty"`
}

// Parameter holds an API parameter.
type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query, path, header, cookie
	Required bool   `json:"required"`
	Type     string `json:"type,omitempty"`
}

// RequestBody holds request body info.
type RequestBody struct {
	Required     bool     `json:"required"`
	ContentTypes []string `json:"content_types"`
}
