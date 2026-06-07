package runner

type Session struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Methodology string `json:"methodology"`
	Directory   string `json:"directory"`
	Optional    bool   `json:"optional"`
}

type InitConfig struct {
	Workspace           string
	TargetURL           string
	SourceCode          string
	TargetType          string
	Cloud               string
	InScope             string
	OutOfScope          string
	LoginURL            string
	Username            string
	Password            string
	ExploitationEnabled bool
}

type Status struct {
	SchemaVersion        int               `json:"schema_version"`
	Workspace            string            `json:"workspace"`
	ConfigPath           string            `json:"config_path"`
	ProgressPath         string            `json:"progress_path"`
	AssessmentPlanPath   string            `json:"assessment_plan_path"`
	AssessmentPlanExists bool              `json:"assessment_plan_exists"`
	AssessmentPlan       *PlanSummary      `json:"assessment_plan,omitempty"`
	NextSession          *Session          `json:"next_session,omitempty"`
	NextPlanDecision     *PlanDecisionView `json:"next_plan_decision,omitempty"`
	Sessions             map[string]string `json:"sessions"`
}

type NextAction struct {
	SchemaVersion  int               `json:"schema_version"`
	Workspace      string            `json:"workspace"`
	Session        *Session          `json:"session,omitempty"`
	PlanDecision   *PlanDecisionView `json:"plan_decision,omitempty"`
	PlanValidation []string          `json:"plan_validation,omitempty"`
	ActionPath     string            `json:"action_path"`
	PromptPath     string            `json:"prompt_path"`
	Message        string            `json:"message"`
}

type ExploitSelection struct {
	SchemaVersion           int      `json:"schema_version"`
	Workspace               string   `json:"workspace"`
	Findings                []string `json:"findings"`
	FindingRegistryPath     string   `json:"finding_registry_path"`
	SelectionPath           string   `json:"selection_path"`
	ActionPath              string   `json:"action_path"`
	PromptPath              string   `json:"prompt_path"`
	MaxRisk                 int      `json:"max_risk"`
	AllowedActions          []string `json:"allowed_actions"`
	ForbiddenActions        []string `json:"forbidden_actions"`
	CleanupRequired         bool     `json:"cleanup_required"`
	CleanupEvidenceRequired bool     `json:"cleanup_evidence_required"`
	Message                 string   `json:"message"`
}

type ReportGateOutput struct {
	SchemaVersion        int               `json:"schema_version" yaml:"schema_version"`
	Workspace            string            `json:"workspace" yaml:"workspace"`
	Ready                bool              `json:"ready" yaml:"ready"`
	GatePath             string            `json:"gate_path" yaml:"gate_path"`
	GateMarkdownPath     string            `json:"gate_markdown_path" yaml:"gate_markdown_path"`
	FindingRegistryPath  string            `json:"finding_registry_path" yaml:"finding_registry_path"`
	FindingRegistryState string            `json:"finding_registry_state" yaml:"finding_registry_state"`
	Issues               []ReportGateIssue `json:"issues,omitempty" yaml:"issues,omitempty"`
	NextActionPath       string            `json:"next_action_path,omitempty" yaml:"next_action_path,omitempty"`
	PromptPath           string            `json:"prompt_path,omitempty" yaml:"prompt_path,omitempty"`
	Message              string            `json:"message" yaml:"message"`
}

type ReportGateIssue struct {
	Severity string `json:"severity" yaml:"severity"`
	Code     string `json:"code" yaml:"code"`
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	Message  string `json:"message" yaml:"message"`
}

type FinalReportOutput struct {
	SchemaVersion      int               `json:"schema_version" yaml:"schema_version"`
	Workspace          string            `json:"workspace" yaml:"workspace"`
	Ready              bool              `json:"ready" yaml:"ready"`
	SourceRegistryPath string            `json:"source_registry_path" yaml:"source_registry_path"`
	OutcomePath        string            `json:"outcome_path" yaml:"outcome_path"`
	FinalRegistryPath  string            `json:"final_registry_path" yaml:"final_registry_path"`
	EvidenceAppendix   string            `json:"evidence_appendix" yaml:"evidence_appendix"`
	Issues             []ReportGateIssue `json:"issues,omitempty" yaml:"issues,omitempty"`
	UpdatedFindings    []string          `json:"updated_findings,omitempty" yaml:"updated_findings,omitempty"`
	PreservedFindings  []string          `json:"preserved_findings,omitempty" yaml:"preserved_findings,omitempty"`
	NextActionPath     string            `json:"next_action_path,omitempty" yaml:"next_action_path,omitempty"`
	PromptPath         string            `json:"prompt_path,omitempty" yaml:"prompt_path,omitempty"`
	Message            string            `json:"message" yaml:"message"`
}

type FindingRegistry struct {
	SchemaVersion int              `json:"schema_version" yaml:"schema_version"`
	GeneratedFrom string           `json:"generated_from" yaml:"generated_from"`
	Findings      []FindingSummary `json:"findings" yaml:"findings"`
}

type FindingSummary struct {
	ID                      string   `json:"id" yaml:"id"`
	Title                   string   `json:"title" yaml:"title"`
	Category                string   `json:"category" yaml:"category"`
	Status                  string   `json:"status" yaml:"status"`
	Confidence              string   `json:"confidence" yaml:"confidence"`
	Severity                string   `json:"severity" yaml:"severity"`
	CVSSV4                  string   `json:"cvss_v4" yaml:"cvss_v4"`
	CVSSV31                 string   `json:"cvss_v31" yaml:"cvss_v31"`
	EvidenceIDs             []string `json:"evidence_ids" yaml:"evidence_ids"`
	Transcripts             []string `json:"transcripts" yaml:"transcripts"`
	ArtifactPaths           []string `json:"artifact_paths" yaml:"artifact_paths,omitempty"`
	CleanupEvidence         []string `json:"cleanup_evidence" yaml:"cleanup_evidence,omitempty"`
	ImportRefs              []string `json:"import_refs" yaml:"import_refs"`
	ManualNotes             []string `json:"manual_notes" yaml:"manual_notes"`
	EvidenceCategories      []string `json:"evidence_categories" yaml:"evidence_categories"`
	CoverageLabel           string   `json:"coverage_label" yaml:"coverage_label"`
	ExploitCandidate        bool     `json:"exploit_candidate" yaml:"exploit_candidate"`
	ExploitCandidateReason  string   `json:"exploit_candidate_reason" yaml:"exploit_candidate_reason"`
	SelectedForExploitation bool     `json:"selected_for_exploitation" yaml:"selected_for_exploitation"`
	OriginalStatus          string   `json:"original_status" yaml:"original_status,omitempty"`
	ExploitVerified         bool     `json:"exploit_verified" yaml:"exploit_verified,omitempty"`
	ExploitOutcomeReason    string   `json:"exploit_outcome_reason" yaml:"exploit_outcome_reason,omitempty"`
	CleanupStatus           string   `json:"cleanup_status" yaml:"cleanup_status,omitempty"`
	Notes                   string   `json:"notes" yaml:"notes"`
}

type ExploitOutcomes struct {
	SchemaVersion int              `json:"schema_version" yaml:"schema_version"`
	GeneratedFrom string           `json:"generated_from" yaml:"generated_from"`
	Outcomes      []ExploitOutcome `json:"outcomes" yaml:"outcomes"`
}

type ExploitOutcome struct {
	ID                 string   `json:"id" yaml:"id"`
	Status             string   `json:"status" yaml:"status"`
	OutcomeReason      string   `json:"outcome_reason" yaml:"outcome_reason,omitempty"`
	EvidenceIDs        []string `json:"evidence_ids" yaml:"evidence_ids,omitempty"`
	Transcripts        []string `json:"transcripts" yaml:"transcripts,omitempty"`
	ArtifactPaths      []string `json:"artifact_paths" yaml:"artifact_paths,omitempty"`
	CleanupEvidence    []string `json:"cleanup_evidence" yaml:"cleanup_evidence,omitempty"`
	CleanupStatus      string   `json:"cleanup_status" yaml:"cleanup_status,omitempty"`
	EvidenceCategories []string `json:"evidence_categories" yaml:"evidence_categories,omitempty"`
	Notes              string   `json:"notes" yaml:"notes,omitempty"`
}

type AssessmentPlan struct {
	SchemaVersion  int                    `json:"schema_version" yaml:"schema_version"`
	Draft          bool                   `json:"draft" yaml:"draft"`
	Target         PlanTarget             `json:"target" yaml:"target"`
	Sessions       map[string]PlanSession `json:"sessions" yaml:"sessions"`
	Exploitation   PlanExploitation       `json:"exploitation" yaml:"exploitation"`
	HumanOverrides []string               `json:"human_overrides" yaml:"human_overrides"`
	CreatedBy      string                 `json:"created_by" yaml:"created_by"`
	CreatedAt      string                 `json:"created_at" yaml:"created_at"`
}

type PlanTarget struct {
	Type                     string                  `json:"type" yaml:"type"`
	URL                      string                  `json:"url" yaml:"url"`
	SourceMode               string                  `json:"source_mode" yaml:"source_mode"`
	CoverageLabel            string                  `json:"coverage_label" yaml:"coverage_label"`
	ClassificationSource     string                  `json:"classification_source" yaml:"classification_source"`
	ClassificationConfidence string                  `json:"classification_confidence" yaml:"classification_confidence"`
	ReconProfilePath         string                  `json:"recon_profile_path,omitempty" yaml:"recon_profile_path,omitempty"`
	Cloud                    []string                `json:"cloud" yaml:"cloud"`
	Scope                    []string                `json:"scope" yaml:"scope"`
	Rationale                []string                `json:"rationale" yaml:"rationale"`
	BackendInventory         []BackendInventoryEntry `json:"backend_inventory,omitempty" yaml:"backend_inventory,omitempty"`
	ClientExposureReview     []string                `json:"client_exposure_review,omitempty" yaml:"client_exposure_review,omitempty"`
	Signals                  *TargetSignals          `json:"signals,omitempty" yaml:"signals,omitempty"`
}

type PlanSession struct {
	Decision      string   `json:"decision" yaml:"decision"`
	Applicability string   `json:"applicability" yaml:"applicability"`
	CoverageLabel string   `json:"coverage_label" yaml:"coverage_label"`
	Reason        string   `json:"reason" yaml:"reason"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	RequiredInput []string `json:"required_input,omitempty" yaml:"required_input,omitempty"`
}

type PlanExploitation struct {
	Enabled                 bool     `json:"enabled" yaml:"enabled"`
	SelectedFindings        []string `json:"selected_findings" yaml:"selected_findings"`
	MaxRisk                 int      `json:"max_risk" yaml:"max_risk"`
	AllowedActions          []string `json:"allowed_actions" yaml:"allowed_actions"`
	ForbiddenActions        []string `json:"forbidden_actions" yaml:"forbidden_actions"`
	CleanupRequired         bool     `json:"cleanup_required" yaml:"cleanup_required"`
	CleanupEvidenceRequired bool     `json:"cleanup_evidence_required" yaml:"cleanup_evidence_required"`
}

type PlanOutput struct {
	SchemaVersion  int             `json:"schema_version"`
	Workspace      string          `json:"workspace"`
	PlanPath       string          `json:"plan_path"`
	MirrorPath     string          `json:"mirror_path"`
	Written        bool            `json:"written"`
	Valid          bool            `json:"valid"`
	Validation     []string        `json:"validation,omitempty"`
	Message        string          `json:"message"`
	Plan           *AssessmentPlan `json:"plan,omitempty"`
	NextActionPath string          `json:"next_action_path,omitempty"`
	PromptPath     string          `json:"prompt_path,omitempty"`
}

type PlanSummary struct {
	Exists              bool              `json:"exists"`
	Valid               bool              `json:"valid"`
	Validation          []string          `json:"validation,omitempty"`
	TargetType          string            `json:"target_type,omitempty"`
	SourceMode          string            `json:"source_mode,omitempty"`
	CoverageLabel       string            `json:"coverage_label,omitempty"`
	ExploitationEnabled bool              `json:"exploitation_enabled"`
	SessionDecisions    map[string]string `json:"session_decisions,omitempty"`
}

type PlanDecisionView struct {
	SessionKey    string   `json:"session_key"`
	Decision      string   `json:"decision"`
	Applicability string   `json:"applicability"`
	CoverageLabel string   `json:"coverage_label"`
	Reason        string   `json:"reason"`
	RequiredInput []string `json:"required_input,omitempty"`
}

type ReconTargetProfile struct {
	SchemaVersion        int                     `json:"schema_version" yaml:"schema_version"`
	Target               ReconProfileTarget      `json:"target" yaml:"target"`
	BackendInventory     []BackendInventoryEntry `json:"backend_inventory,omitempty" yaml:"backend_inventory,omitempty"`
	Signals              TargetSignals           `json:"signals,omitempty" yaml:"signals,omitempty"`
	ClientExposureReview []string                `json:"client_exposure_review,omitempty" yaml:"client_exposure_review,omitempty"`
}

type ReconProfileTarget struct {
	Type                     string   `json:"type" yaml:"type"`
	SourceMode               string   `json:"source_mode" yaml:"source_mode"`
	CoverageLabel            string   `json:"coverage_label,omitempty" yaml:"coverage_label,omitempty"`
	ClassificationConfidence string   `json:"classification_confidence" yaml:"classification_confidence"`
	Rationale                []string `json:"rationale" yaml:"rationale"`
	EvidenceRefs             []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type BackendInventoryEntry struct {
	Name         string   `json:"name" yaml:"name"`
	BaseURL      string   `json:"base_url" yaml:"base_url"`
	Kind         string   `json:"kind" yaml:"kind"`
	Source       string   `json:"source" yaml:"source"`
	EvidenceRefs []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
}

type TargetSignals struct {
	BrowserUI               *bool `json:"browser_ui,omitempty" yaml:"browser_ui,omitempty"`
	APISurface              *bool `json:"api_surface,omitempty" yaml:"api_surface,omitempty"`
	ServerSideSurface       *bool `json:"server_side_surface,omitempty" yaml:"server_side_surface,omitempty"`
	Authentication          *bool `json:"authentication,omitempty" yaml:"authentication,omitempty"`
	AuthorizationBoundaries *bool `json:"authorization_boundaries,omitempty" yaml:"authorization_boundaries,omitempty"`
	OutboundFetchSurface    *bool `json:"outbound_fetch_surface,omitempty" yaml:"outbound_fetch_surface,omitempty"`
	CloudSurface            *bool `json:"cloud_surface,omitempty" yaml:"cloud_surface,omitempty"`
	ClientOnly              *bool `json:"client_only,omitempty" yaml:"client_only,omitempty"`
	MonorepoAmbiguous       *bool `json:"monorepo_ambiguous,omitempty" yaml:"monorepo_ambiguous,omitempty"`
}

var Sessions = []Session{
	{ID: "01", Name: "Recon", Methodology: "skills/methodology/01-recon.md", Directory: "01-recon"},
	{ID: "01.5", Name: "Session Applicability Plan", Methodology: "skills/methodology/01.5-session-plan.md", Directory: "01.5-session-plan"},
	{ID: "02", Name: "Injection", Methodology: "skills/methodology/02-injection.md", Directory: "02-injection"},
	{ID: "03", Name: "Authentication", Methodology: "skills/methodology/03-auth.md", Directory: "03-auth"},
	{ID: "04", Name: "Authorization", Methodology: "skills/methodology/04-authz.md", Directory: "04-authz"},
	{ID: "05", Name: "Cross-Site Scripting", Methodology: "skills/methodology/05-xss.md", Directory: "05-xss"},
	{ID: "06", Name: "Server-Side Request Forgery", Methodology: "skills/methodology/06-ssrf.md", Directory: "06-ssrf"},
	{ID: "07", Name: "Cloud Security", Methodology: "skills/methodology/07-cloud.md", Directory: "07-cloud"},
	{ID: "08", Name: "API Security", Methodology: "skills/methodology/08-api.md", Directory: "08-api"},
	{ID: "09", Name: "Evidence-Based Assessment Report", Methodology: "skills/methodology/09-report.md", Directory: "09-report"},
	{ID: "10", Name: "Optional Prove-by-Exploitation", Methodology: "skills/methodology/10-exploitation.md", Directory: "10-exploitation", Optional: true},
	{ID: "11", Name: "Exploit-Verified Final Report", Methodology: "skills/methodology/11-final-report.md", Directory: "11-final-report", Optional: true},
}
