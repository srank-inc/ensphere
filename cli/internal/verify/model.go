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

// CMDiTimeMeasurements holds command injection time-based probe measurements.
type CMDiTimeMeasurements struct {
	SleepSeconds   int           `json:"sleep_seconds"`
	TargetOS       string        `json:"target_os"`
	BaselineRounds []RoundResult `json:"baseline_rounds"`
	PayloadRounds  []RoundResult `json:"payload_rounds"`
	BaselineAvgMs  int64         `json:"baseline_avg_ms"`
	PayloadAvgMs   int64         `json:"payload_avg_ms"`
	DeltaMs        int64         `json:"delta_ms"`
	PayloadUsed    string        `json:"payload_used"`
}

// LFIMeasurements holds local file inclusion probe measurements.
type LFIMeasurements struct {
	Baseline          RoundResult `json:"baseline"`
	Probe             RoundResult `json:"probe"`
	HashesMatch       bool        `json:"hashes_match"`
	MatchedSignatures []string    `json:"matched_signatures"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// SSTIMeasurements holds server-side template injection probe measurements.
type SSTIMeasurements struct {
	Probes []SSTIProbeResult `json:"probes"`
}

// SSTIProbeResult holds a single SSTI probe result.
type SSTIProbeResult struct {
	RoundResult
	PayloadUsed string `json:"payload_used"`
	Expected    string `json:"expected"`
	Found       bool   `json:"found"`
	Context     string `json:"context,omitempty"`
}

// XXEMeasurements holds XML external entity probe measurements.
type XXEMeasurements struct {
	Probe             RoundResult `json:"probe"`
	MatchedSignatures []string    `json:"matched_signatures"`
	PayloadUsed       string      `json:"payload_used"`
	ResponseSnippet   string      `json:"response_snippet,omitempty"`
}

// DeserializationMeasurements holds insecure deserialization probe measurements.
type DeserializationMeasurements struct {
	Runtime        string        `json:"runtime"`
	BaselineRounds []RoundResult `json:"baseline_rounds"`
	PayloadRounds  []RoundResult `json:"payload_rounds"`
	BaselineAvgMs  int64         `json:"baseline_avg_ms"`
	PayloadAvgMs   int64         `json:"payload_avg_ms"`
	DeltaMs        int64         `json:"delta_ms"`
	PayloadUsed    string        `json:"payload_used"`
}

// CSRFMeasurements holds CSRF probe measurements.
type CSRFMeasurements struct {
	NoOrigin       RoundResult `json:"no_origin"`
	MismatchOrigin RoundResult `json:"mismatch_origin"`
	Baseline       RoundResult `json:"baseline"`
	SameSiteFound  bool        `json:"samesite_found"`
	SameSiteValue  string      `json:"samesite_value,omitempty"`
	CSRFTokenInBody bool       `json:"csrf_token_in_body"`
}

// NoSQLMeasurements holds NoSQL injection probe measurements.
type NoSQLMeasurements struct {
	Technique      string        `json:"technique"`
	TrueProbe      *RoundResult  `json:"true_probe,omitempty"`
	FalseProbe     *RoundResult  `json:"false_probe,omitempty"`
	HashesMatch    *bool         `json:"hashes_match,omitempty"`
	TruePayload    string        `json:"true_payload,omitempty"`
	FalsePayload   string        `json:"false_payload,omitempty"`
	SleepSeconds   *int          `json:"sleep_seconds,omitempty"`
	BaselineRounds []RoundResult `json:"baseline_rounds,omitempty"`
	PayloadRounds  []RoundResult `json:"payload_rounds,omitempty"`
	BaselineAvgMs  *int64        `json:"baseline_avg_ms,omitempty"`
	PayloadAvgMs   *int64        `json:"payload_avg_ms,omitempty"`
	DeltaMs        *int64        `json:"delta_ms,omitempty"`
	PayloadUsed    string        `json:"payload_used"`
}

// JWTMeasurements holds JWT manipulation probe measurements.
type JWTMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	Probe           RoundResult `json:"probe"`
	BodyLengthDelta int         `json:"body_length_delta"`
	ModifiedToken   string      `json:"modified_token"`
	PayloadUsed     string      `json:"payload_used"`
}

// CORSMeasurements holds CORS misconfiguration probe measurements.
type CORSMeasurements struct {
	Baseline        CORSProbeResult `json:"baseline"`
	EvilOrigin      CORSProbeResult `json:"evil_origin"`
	NullOrigin      CORSProbeResult `json:"null_origin"`
	SubdomainOrigin CORSProbeResult `json:"subdomain_origin"`
}

// CORSProbeResult holds a single CORS probe result with header details.
type CORSProbeResult struct {
	RoundResult
	OriginSent         string `json:"origin_sent"`
	ACAOHeader         string `json:"acao_header"`
	ACACHeader         string `json:"acac_header"`
	OriginReflected    bool   `json:"origin_reflected"`
	CredentialsAllowed bool   `json:"credentials_allowed"`
}

// ProtoPollutionMeasurements holds prototype pollution probe measurements.
type ProtoPollutionMeasurements struct {
	Technique       string      `json:"technique"`
	Baseline        RoundResult `json:"baseline"`
	InjectionProbe  RoundResult `json:"injection_probe"`
	VerifyProbe     RoundResult `json:"verify_probe"`
	HashesMatch     bool        `json:"hashes_match"`
	PayloadUsed     string      `json:"payload_used"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// GraphQLMeasurements holds GraphQL abuse probe measurements.
type GraphQLMeasurements struct {
	Technique            string       `json:"technique"`
	Probe                RoundResult  `json:"probe"`
	IntrospectionEnabled *bool        `json:"introspection_enabled,omitempty"`
	TypeCount            *int         `json:"type_count,omitempty"`
	BatchAccepted        *bool        `json:"batch_accepted,omitempty"`
	Baseline             *RoundResult `json:"baseline,omitempty"`
	DeltaMs              *int64       `json:"delta_ms,omitempty"`
	PayloadUsed          string       `json:"payload_used"`
	ResponseSnippet      string       `json:"response_snippet,omitempty"`
}

// RaceMeasurements holds race condition probe measurements.
type RaceMeasurements struct {
	Concurrency  int           `json:"concurrency"`
	Rounds       []RoundResult `json:"rounds"`
	SuccessCount int           `json:"success_count"`
	UniqueHashes int           `json:"unique_hashes"`
	MinMs        int64         `json:"min_ms"`
	MaxMs        int64         `json:"max_ms"`
	AvgMs        int64         `json:"avg_ms"`
	PayloadUsed  string        `json:"payload_used"`
}

// SmugglingMeasurements holds request smuggling probe measurements.
type SmugglingMeasurements struct {
	Technique   string        `json:"technique"`
	Baseline    RoundResult   `json:"baseline"`
	ProbeRounds []RoundResult `json:"probe_rounds"`
	BaselineMs  int64         `json:"baseline_ms"`
	ProbeAvgMs  int64         `json:"probe_avg_ms"`
	DeltaMs     int64         `json:"delta_ms"`
	PayloadUsed string        `json:"payload_used"`
}

// CachePoisoningMeasurements holds cache poisoning probe measurements.
type CachePoisoningMeasurements struct {
	Technique              string      `json:"technique"`
	Baseline               RoundResult `json:"baseline"`
	Injection              RoundResult `json:"injection"`
	Verify                 RoundResult `json:"verify"`
	BaselineHash           string      `json:"baseline_hash"`
	VerifyHash             string      `json:"verify_hash"`
	VerifyMatchesInjection bool        `json:"verify_matches_injection"`
	VerifyMatchesBaseline  bool        `json:"verify_matches_baseline"`
	HeaderUsed             string      `json:"header_used"`
	PayloadUsed            string      `json:"payload_used"`
	ResponseSnippet        string      `json:"response_snippet,omitempty"`
}

// RedirectMeasurements holds open redirect probe measurements.
type RedirectMeasurements struct {
	Probe            RoundResult `json:"probe"`
	LocationHeader   string      `json:"location_header"`
	RedirectChain    []string    `json:"redirect_chain"`
	PayloadUsed      string      `json:"payload_used"`
	ExternalRedirect bool        `json:"external_redirect"`
}

// CSVInjectionMeasurements holds CSV injection probe measurements.
type CSVInjectionMeasurements struct {
	SubmitProbe     RoundResult `json:"submit_probe"`
	ExportProbe     RoundResult `json:"export_probe"`
	FormulaFound    bool        `json:"formula_found"`
	FormulaEscaped  bool        `json:"formula_escaped"`
	PayloadUsed     string      `json:"payload_used"`
	ResponseSnippet string      `json:"response_snippet,omitempty"`
}

// AuthZMeasurements holds authorization bypass probe measurements.
type AuthZMeasurements struct {
	HighPriv        RoundResult `json:"high_priv"`
	LowPriv         RoundResult `json:"low_priv"`
	StatusMatch     bool        `json:"status_match"`
	BodyLengthDelta int         `json:"body_length_delta"`
	HashesMatch     bool        `json:"hashes_match"`
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
