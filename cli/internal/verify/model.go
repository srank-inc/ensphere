package verify

import "time"

// ProbeConfig holds common configuration for all probe types.
type ProbeConfig struct {
	InScope    []string          // Required glob patterns for scope validation
	MaxRisk    int               // Maximum risk level (1-5)
	ThrottleMs int               // Milliseconds between probes
	TimeoutSec int               // HTTP request timeout
	Headers    map[string]string // Custom headers
	Evidence   string            // Evidence file path
}

// VerifyResult is the JSON output for all verify commands.
type VerifyResult struct {
	Status     string      `json:"status"`     // confirmed | potential | safe | error
	VulnType   string      `json:"vuln_type"`
	Technique  string      `json:"technique"`
	Confidence string      `json:"confidence"` // high | medium | low
	Evidence   string      `json:"evidence"`
	Details    interface{} `json:"details"`
	ProbeCount int         `json:"probe_count"`
	Duration   string      `json:"duration"`
}

// SQLiDetails holds SQLi-specific result details.
type SQLiDetails struct {
	BaselineMs     int64  `json:"baseline_ms"`
	PayloadMs      int64  `json:"payload_ms"`
	DeltaMs        int64  `json:"delta_ms"`
	Rounds         int    `json:"rounds"`
	Consistent     bool   `json:"consistent"`
	PayloadUsed    string `json:"payload_used"`
	StringBoundary string `json:"string_boundary"`
}

// SQLiBooleanDetails holds boolean-based SQLi result details.
type SQLiBooleanDetails struct {
	TrueHash       string `json:"true_hash"`
	FalseHash      string `json:"false_hash"`
	BaselineHash   string `json:"baseline_hash"`
	Rounds         int    `json:"rounds"`
	Consistent     bool   `json:"consistent"`
	PayloadUsed    string `json:"payload_used"`
	StringBoundary string `json:"string_boundary"`
}

// SQLiErrorDetails holds error-based SQLi result details.
type SQLiErrorDetails struct {
	ErrorPattern   string `json:"error_pattern"`
	PayloadUsed    string `json:"payload_used"`
	StringBoundary string `json:"string_boundary"`
	ResponseSnippet string `json:"response_snippet,omitempty"`
}

// RLSDetails holds RLS probe result details.
type RLSDetails struct {
	Table           string `json:"table"`
	TenantAOwnRows int    `json:"tenant_a_own_rows"`
	TenantACrossRows int  `json:"tenant_a_cross_rows"`
	TenantBOwnRows  int   `json:"tenant_b_own_rows"`
	RLSEnabled      bool  `json:"rls_enabled"`
	PoliciesFound   bool  `json:"policies_found"`
}

// IDORDetails holds IDOR-specific result details.
type IDORDetails struct {
	StatusCode     int    `json:"status_code"`
	ResponseLength int    `json:"response_length"`
	ContainsData   bool   `json:"contains_data"`
	ExpectedStatus int    `json:"expected_status"`
	ResourceID     string `json:"resource_id"`
}

// XSSDetails holds XSS-specific result details.
type XSSDetails struct {
	Reflected      bool   `json:"reflected"`
	Encoded        bool   `json:"encoded"`
	Context        string `json:"context"`
	PayloadUsed    string `json:"payload_used"`
	ResponseLength int    `json:"response_length"`
}

// SSRFDetails holds SSRF-specific result details.
type SSRFDetails struct {
	CallbackHit     bool   `json:"callback_hit"`
	ResponseDiff    bool   `json:"response_diff"`
	InternalContent bool   `json:"internal_content"`
	CallbackURL     string `json:"callback_url,omitempty"`
	BaselineHash    string `json:"baseline_hash"`
	ProbeHash       string `json:"probe_hash"`
	PayloadUsed     string `json:"payload_used"`
}

// AuthDetails holds auth bypass result details.
type AuthDetails struct {
	Technique      string `json:"technique"`
	Bypassed       bool   `json:"bypassed"`
	ResponseStatus int    `json:"response_status"`
	ResponseLength int    `json:"response_length"`
}

// Timer tracks probe duration.
type Timer struct {
	start time.Time
}

// NewTimer starts a new timer.
func NewTimer() *Timer {
	return &Timer{start: time.Now()}
}

// Elapsed returns formatted elapsed duration.
func (t *Timer) Elapsed() string {
	d := time.Since(t.start)
	return d.Round(100 * time.Millisecond).String()
}
