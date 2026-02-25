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

// ProbeResult is the JSON output for all verify commands.
// Schema version 2: measurement-only output. No status/confidence/evidence.
type ProbeResult struct {
	SchemaVersion int         `json:"schema_version"`
	VulnType      string      `json:"vuln_type"`
	Technique     string      `json:"technique"`
	StartedAt     string      `json:"started_at"`
	ProbeCount    int         `json:"probe_count"`
	Duration      string      `json:"duration"`
	Measurements  interface{} `json:"measurements"`
}

// RoundResult captures raw measurements from a single HTTP round-trip.
type RoundResult struct {
	StatusCode int    `json:"status_code"`
	ElapsedMs  int64  `json:"elapsed_ms"`
	BodyHash   string `json:"body_hash"`
	BodyLength int    `json:"body_length"`
}

// SQLiTimeMeasurements holds blind-time SQLi probe measurements.
type SQLiTimeMeasurements struct {
	SleepSeconds   int           `json:"sleep_seconds"`
	BaselineRounds []RoundResult `json:"baseline_rounds"`
	PayloadRounds  []RoundResult `json:"payload_rounds"`
	BaselineAvgMs  int64         `json:"baseline_avg_ms"`
	PayloadAvgMs   int64         `json:"payload_avg_ms"`
	DeltaMs        int64         `json:"delta_ms"`
	PayloadUsed    string        `json:"payload_used"`
	StringBoundary string        `json:"string_boundary"`
}

// SQLiBooleanMeasurements holds boolean-based SQLi probe measurements.
type SQLiBooleanMeasurements struct {
	BaselineRound  RoundResult   `json:"baseline_round"`
	TrueRounds     []RoundResult `json:"true_rounds"`
	FalseRounds    []RoundResult `json:"false_rounds"`
	HashesMatch    bool          `json:"hashes_match"`
	TruePayload    string        `json:"true_payload"`
	FalsePayload   string        `json:"false_payload"`
	StringBoundary string        `json:"string_boundary"`
}

// SQLiErrorMeasurements holds error-based SQLi probe measurements.
type SQLiErrorMeasurements struct {
	ProbeRound      RoundResult `json:"probe_round"`
	MatchedPatterns []string    `json:"matched_patterns"`
	PayloadUsed     string      `json:"payload_used"`
	StringBoundary  string      `json:"string_boundary"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// XSSMeasurements holds XSS probe measurements.
type XSSMeasurements struct {
	ProbeRound  RoundResult `json:"probe_round"`
	Reflected   bool        `json:"reflected"`
	Encoded     bool        `json:"encoded"`
	Context     string      `json:"context,omitempty"`
	PayloadUsed string      `json:"payload_used"`
}

// IDORMeasurements holds IDOR probe measurements.
type IDORMeasurements struct {
	ProbeRound      RoundResult `json:"probe_round"`
	ExpectedStatus  int         `json:"expected_status"`
	ResourceID      string      `json:"resource_id"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// SSRFMeasurements holds SSRF probe measurements.
type SSRFMeasurements struct {
	Baseline          RoundResult `json:"baseline"`
	Probe             RoundResult `json:"probe"`
	HashesMatch       bool        `json:"hashes_match"`
	MatchedSignatures []string    `json:"matched_signatures"`
	CallbackURL       string      `json:"callback_url,omitempty"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// AuthMeasurements holds auth bypass probe measurements.
type AuthMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	Probe           RoundResult `json:"probe"`
	BodyLengthDelta int         `json:"body_length_delta"`
}

// RLSMeasurements holds Supabase RLS probe measurements.
type RLSMeasurements struct {
	Table           string      `json:"table"`
	TenantAOwn      RoundResult `json:"tenant_a_own"`
	TenantAOwnRows  int         `json:"tenant_a_own_rows"`
	TenantBOwn      RoundResult `json:"tenant_b_own"`
	TenantBOwnRows  int         `json:"tenant_b_own_rows"`
	CrossTenant     RoundResult `json:"cross_tenant"`
	CrossTenantRows int         `json:"cross_tenant_rows"`
}

// Timer tracks probe duration.
type Timer struct {
	start time.Time
}

// NewTimer starts a new timer.
func NewTimer() *Timer {
	return &Timer{start: time.Now()}
}

// StartedAt returns the start time formatted as RFC3339.
func (t *Timer) StartedAt() string {
	return t.start.UTC().Format(time.RFC3339)
}

// Elapsed returns formatted elapsed duration.
func (t *Timer) Elapsed() string {
	d := time.Since(t.start)
	return d.Round(100 * time.Millisecond).String()
}
