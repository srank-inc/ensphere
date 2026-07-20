package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultWorkspace = "ensphere-pentest"
	statePending     = "PENDING"
	stateSkipped     = "SKIPPED"
	stateDone        = "DONE"
	stateBlocked     = "BLOCKED"
	stateNA          = "NOT_APPLICABLE"
)

func DefaultWorkspace() string { return defaultWorkspace }

func InitWorkspace(cfg InitConfig) (*Status, error) {
	if cfg.Workspace == "" {
		cfg.Workspace = defaultWorkspace
	}
	if cfg.TargetType == "" {
		cfg.TargetType = "auto"
	}
	if cfg.SourceCode == "" {
		cfg.SourceCode = "yes"
	}
	if cfg.Cloud == "" {
		cfg.Cloud = "none"
	}
	if cfg.InScope == "" {
		cfg.InScope = "All network-reachable endpoints of the target application"
	}
	if cfg.OutOfScope == "" {
		cfg.OutOfScope = "Third-party services, production systems"
	}
	if fileExists(configPath(cfg.Workspace)) || fileExists(progressPath(cfg.Workspace)) {
		return nil, fmt.Errorf("workspace already initialized at %s; use ensphere run status or ensphere run next to resume", cfg.Workspace)
	}
	if err := os.MkdirAll(cfg.Workspace, 0755); err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	for _, session := range Sessions {
		if err := os.MkdirAll(filepath.Join(cfg.Workspace, session.Directory), 0755); err != nil {
			return nil, fmt.Errorf("create session directory %s: %w", session.Directory, err)
		}
	}
	if err := os.WriteFile(configPath(cfg.Workspace), []byte(renderConfig(cfg)), 0644); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	if err := os.WriteFile(progressPath(cfg.Workspace), []byte(renderProgress(cfg.Workspace)), 0644); err != nil {
		return nil, fmt.Errorf("write progress: %w", err)
	}
	if _, err := WriteNextAction(cfg.Workspace); err != nil {
		return nil, err
	}
	return WorkspaceStatus(cfg.Workspace)
}

func WorkspaceStatus(workspace string) (*Status, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	states, err := readProgress(workspace)
	if err != nil {
		return nil, err
	}
	next := nextSession(states, session10Ready(workspace))
	planSummary := loadPlanSummary(workspace)
	nextDecision, validation := planDecisionForSession(workspace, next)
	if planSummary != nil && len(validation) > 0 {
		planSummary.Validation = validation
		planSummary.Valid = false
	}
	return &Status{
		Workspace:            workspace,
		ConfigPath:           configPath(workspace),
		ProgressPath:         progressPath(workspace),
		AssessmentPlanPath:   assessmentPlanPath(workspace),
		AssessmentPlanExists: fileExists(assessmentPlanPath(workspace)),
		AssessmentPlan:       planSummary,
		NextSession:          next,
		NextPlanDecision:     nextDecision,
		Sessions:             states,
	}, nil
}

func WriteNextAction(workspace string) (*NextAction, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	status, err := WorkspaceStatus(workspace)
	if err != nil {
		return nil, err
	}
	action := &NextAction{
		Workspace:    workspace,
		Session:      status.NextSession,
		PlanDecision: status.NextPlanDecision,
		ActionPath:   filepath.Join(workspace, "next-action.md"),
		PromptPath:   filepath.Join(workspace, "agent-prompt.md"),
	}
	if status.AssessmentPlan != nil {
		action.PlanValidation = status.AssessmentPlan.Validation
	}
	if status.NextSession == nil {
		action.Message = "No next session. Assessment is complete, optional impact validation is disabled, or no Session 10 findings have been selected."
	} else {
		action.Message = fmt.Sprintf("Next session: %s - %s", status.NextSession.ID, status.NextSession.Name)
	}
	if err := os.WriteFile(action.ActionPath, []byte(renderNextAction(action)), 0644); err != nil {
		return nil, fmt.Errorf("write next action: %w", err)
	}
	if err := os.WriteFile(action.PromptPath, []byte(renderAgentPrompt(action)), 0644); err != nil {
		return nil, fmt.Errorf("write agent prompt: %w", err)
	}
	return action, nil
}

func PrepareImpactValidation(workspace string, findings []string) (*ImpactValidationSelection, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}
	if !impactValidationEnabled(workspace) {
		return nil, fmt.Errorf("impact validation is not enabled; explicitly enable optional Session 10 in config or assessment-plan.yaml before selecting findings")
	}
	findings = cleanFindings(findings)
	if len(findings) == 0 {
		return nil, fmt.Errorf("at least one --finding is required")
	}
	registryPath := findingRegistryPath(workspace)
	if err := validateAssessmentPlanIfPresent(workspace); err != nil {
		return nil, err
	}
	if err := validateSelectedFindings(workspace, findings); err != nil {
		return nil, err
	}
	if err := requireSessionDone(workspace, "09", "Session 10 selection"); err != nil {
		return nil, err
	}
	gate, err := RunReport(workspace)
	if err != nil {
		return nil, fmt.Errorf("run Session 09 report gate: %w", err)
	}
	if !gate.Ready {
		return nil, fmt.Errorf("Session 09 report gate is not ready; resolve: %s", reportIssueCodes(gate.Issues))
	}
	policy := impactValidationPolicy(workspace)
	dir := filepath.Join(workspace, "10-impact-validation")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create impact validation directory: %w", err)
	}
	selectionPath := filepath.Join(dir, "selected-findings.yaml")
	if err := os.WriteFile(selectionPath, []byte(renderSelectedFindings(findings, registryPath, policy)), 0644); err != nil {
		return nil, fmt.Errorf("write selected findings: %w", err)
	}
	action := &NextAction{
		Workspace:  workspace,
		Session:    sessionByID("10"),
		ActionPath: filepath.Join(workspace, "next-action.md"),
		PromptPath: filepath.Join(workspace, "agent-prompt.md"),
		Message:    "Next session: 10 - Optional Human-Authorized Impact Validation",
	}
	if err := os.WriteFile(action.ActionPath, []byte(renderNextAction(action)), 0644); err != nil {
		return nil, fmt.Errorf("write next action: %w", err)
	}
	if err := os.WriteFile(action.PromptPath, []byte(renderAgentPrompt(action)), 0644); err != nil {
		return nil, fmt.Errorf("write agent prompt: %w", err)
	}
	return &ImpactValidationSelection{
		Workspace:                          workspace,
		Findings:                           findings,
		FindingRegistryPath:                registryPath,
		SelectionPath:                      selectionPath,
		ActionPath:                         action.ActionPath,
		PromptPath:                         action.PromptPath,
		MaxRisk:                            policy.MaxRisk,
		AllowedActions:                     policy.AllowedActions,
		ForbiddenActions:                   policy.ForbiddenActions,
		CleanupRequired:                    policy.CleanupRequired,
		CleanupEvidenceRequired:            policy.CleanupEvidenceRequired,
		HumanAuthorizationRequired:         true,
		AuthorizationRecordRequired:        true,
		EnvironmentAcknowledgementRequired: true,
		PermittedExecutors:                 []string{"human", "agent"},
		ValidationPlanRequired:             true,
		Message:                            "Selected findings validated against the Session 09 registry. Session 10 remains paused until a human authorizes the exact plan and executor for each finding.",
	}, nil
}

func renderConfig(cfg InitConfig) string {
	enabled := "false"
	if cfg.ImpactValidationEnabled {
		enabled = "true"
	}
	return fmt.Sprintf(`# Pentest Configuration

## Target
- URL: %s
- Source code: %s
- Target type: %s
- Cloud: %s

## Authentication
- Login URL: %s
- Username: %s
- Password: %s
- (Add additional accounts for multi-role testing)

## Scope
- In scope: %s
- Out of scope: %s
- Rules to avoid: no DoS, no data destruction
- Areas to focus: 

## Impact Validation
- Execution model: optional and human-authorized; executor is human or agent
- Enabled: %s
- Selected findings: []
- Max risk: 3
- Allowed actions: non_sensitive_canary_read, benign_browser_execution
- Forbidden actions: sensitive_data_access, data_deletion, persistence, credential_dumping
- Human authorization required: true
- Authorization record required: true
- Permitted executors: human, agent
- Cleanup required: true
- Cleanup evidence required: true

## Authorization
This test is fully authorized against the specified controlled environment.
This general assessment authorization does not authorize Session 10 actions.
`, cfg.TargetURL, cfg.SourceCode, cfg.TargetType, cfg.Cloud, cfg.LoginURL, cfg.Username, cfg.Password, cfg.InScope, cfg.OutOfScope, enabled)
}

func renderProgress(workspace string) string {
	var b strings.Builder
	b.WriteString("# Assessment Progress\n\n")
	b.WriteString("**Mode**: WHITE_BOX | BLACK_BOX\n")
	b.WriteString(fmt.Sprintf("**Assessment Plan**: %s\n\n", assessmentPlanPath(workspace)))
	b.WriteString("| Session | Category | Status | Findings |\n")
	b.WriteString("|---------|----------|--------|----------|\n")
	for _, session := range Sessions {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | |\n", session.ID, session.Name, statePending))
	}
	return b.String()
}

func renderNextAction(action *NextAction) string {
	if action.Session == nil {
		return "# Next Action\n\nNo next session. Assessment is complete, optional impact validation is disabled, or no Session 10 findings have been selected.\n"
	}
	var planBlock string
	if action.PlanDecision != nil {
		planBlock = fmt.Sprintf(`
## Assessment Plan Decision
- **Session Key**: %s
- **Decision**: %s
- **Applicability**: %s
- **Coverage Label**: %s
- **Reason**: %s
`, action.PlanDecision.SessionKey, action.PlanDecision.Decision, action.PlanDecision.Applicability, action.PlanDecision.CoverageLabel, action.PlanDecision.Reason)
		if len(action.PlanDecision.RequiredInput) > 0 {
			planBlock += "- **Required Input**:\n"
			for _, item := range action.PlanDecision.RequiredInput {
				planBlock += fmt.Sprintf("  - %s\n", item)
			}
		}
	} else if len(action.PlanValidation) > 0 {
		planBlock = "\n## Assessment Plan Validation\n"
		for _, issue := range action.PlanValidation {
			planBlock += fmt.Sprintf("- %s\n", issue)
		}
	}
	instruction := `Open the Ensphere skill, read the methodology file above, and run this session
against the configured target. Keep evidence factual and update progress when
the session completes.`
	if action.Session.ID == "10" {
		instruction = `Open the Ensphere skill and Session 10 methodology. Validate the handoff and
prepare a strict bounded YAML plan for each selected finding. Do not execute any
action until a human authorizes that exact plan SHA-256 and executor and
ensphere run impact-ready returns ready: true.`
	} else if action.Session.ID == "11" {
		instruction = `Open the Ensphere skill and Session 11 methodology. Produce the optional
derived report while preserving every Session 09 finding status.`
	}
	return fmt.Sprintf(`# Next Action

## Session
- **ID**: %s
- **Name**: %s
- **Methodology**: %s
- **Directory**: %s
- **Generated**: %s
%s

## Instruction
%s
`, action.Session.ID, action.Session.Name, action.Session.Methodology, action.Session.Directory, time.Now().UTC().Format(time.RFC3339), planBlock, instruction)
}

func renderAgentPrompt(action *NextAction) string {
	if action.Session == nil {
		return "ensphere status\n"
	}
	if action.Session.ID == "10" {
		return fmt.Sprintf("ensphere 10\n\nRead %s and prepare the strict human-authorized impact-validation plans using %s and %s. Do not execute until exact SHA-256 authorization is recorded and run impact-ready returns ready: true.\n", action.Session.Methodology, configPath(action.Workspace), progressPath(action.Workspace))
	}
	if action.Session.ID == "11" {
		return fmt.Sprintf("ensphere 11\n\nRead %s and write the derived validation-aware report using %s and %s. Preserve Session 09 finding statuses.\n", action.Session.Methodology, configPath(action.Workspace), progressPath(action.Workspace))
	}
	return fmt.Sprintf("ensphere %s\n\nRead %s and execute the session using %s and %s.\n", action.Session.ID, action.Session.Methodology, configPath(action.Workspace), progressPath(action.Workspace))
}

func renderSelectedFindings(findings []string, registryPath string, policy PlanImpactValidation) string {
	policy = normalizeImpactValidationPolicy(policy)
	var b strings.Builder
	b.WriteString("enabled: true\n")
	b.WriteString(fmt.Sprintf("finding_registry_path: %q\n", registryPath))
	b.WriteString(fmt.Sprintf("max_risk: %d\n", policy.MaxRisk))
	b.WriteString("allowed_actions:\n")
	for _, action := range policy.AllowedActions {
		b.WriteString(fmt.Sprintf("  - %q\n", action))
	}
	b.WriteString("forbidden_actions:\n")
	for _, action := range policy.ForbiddenActions {
		b.WriteString(fmt.Sprintf("  - %q\n", action))
	}
	b.WriteString("selected_findings:\n")
	for _, finding := range findings {
		b.WriteString(fmt.Sprintf("  - %q\n", finding))
	}
	b.WriteString(fmt.Sprintf("cleanup_required: %t\n", policy.CleanupRequired))
	b.WriteString(fmt.Sprintf("cleanup_evidence_required: %t\n", policy.CleanupEvidenceRequired))
	b.WriteString("human_authorization_required: true\n")
	b.WriteString("authorization_record_required: true\n")
	b.WriteString("environment_acknowledgement_required: true\n")
	b.WriteString("permitted_executors:\n")
	b.WriteString("  - \"human\"\n")
	b.WriteString("  - \"agent\"\n")
	b.WriteString("validation_plan_required: true\n")
	b.WriteString("evidence_paths:\n")
	b.WriteString("  evidence_jsonl: \"10-impact-validation/evidence.jsonl\"\n")
	b.WriteString("  transcript_dir: \"10-impact-validation/transcripts\"\n")
	b.WriteString("  artifact_dir: \"10-impact-validation/artifacts\"\n")
	b.WriteString("  authorization_dir: \"10-impact-validation/authorizations\"\n")
	b.WriteString("  readiness_dir: \"10-impact-validation/readiness\"\n")
	b.WriteString("  cleanup_report: \"10-impact-validation/cleanup.md\"\n")
	return b.String()
}

func readProgress(workspace string) (map[string]string, error) {
	raw, err := os.ReadFile(progressPath(workspace))
	if err != nil {
		return nil, fmt.Errorf("read progress: %w", err)
	}
	states := make(map[string]string, len(Sessions))
	for _, session := range Sessions {
		states[session.ID] = statePending
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || strings.Contains(line, "---") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		id := strings.TrimSpace(parts[1])
		if id == "Session" {
			continue
		}
		status := strings.TrimSpace(parts[3])
		if id != "" && status != "" {
			states[id] = status
		}
	}
	return states, nil
}

func cleanFindings(findings []string) []string {
	seen := make(map[string]struct{}, len(findings))
	cleaned := make([]string, 0, len(findings))
	for _, finding := range findings {
		finding = strings.TrimSpace(finding)
		if finding == "" {
			continue
		}
		if _, ok := seen[finding]; ok {
			continue
		}
		seen[finding] = struct{}{}
		cleaned = append(cleaned, finding)
	}
	return cleaned
}

func nextSession(states map[string]string, session10Ready bool) *Session {
	for _, session := range Sessions {
		if session.ID == "10" && !session10Ready {
			return nil
		}
		if session.ID == "11" {
			// Session 11 is invoked only through the explicit `run final` command.
			// It is never the automatic next session, even after Session 10 is done.
			return nil
		}
		state := strings.ToUpper(states[session.ID])
		switch state {
		case stateDone, stateSkipped, stateBlocked, stateNA:
			continue
		default:
			s := session
			return &s
		}
	}
	return nil
}

func session10Ready(workspace string) bool {
	if !impactValidationEnabled(workspace) {
		return false
	}
	if err := validateAssessmentPlanIfPresent(workspace); err != nil {
		return false
	}
	states, err := readProgress(workspace)
	if err != nil || strings.ToUpper(strings.TrimSpace(states["09"])) != stateDone {
		return false
	}
	findings := selectedFindingsFromHandoff(workspace)
	return len(findings) > 0 && validateSelectedFindings(workspace, findings) == nil && validateSession10Handoff(workspace) == nil
}

func requireSessionDone(workspace, id, gate string) error {
	states, err := readProgress(workspace)
	if err != nil {
		return err
	}
	status := strings.ToUpper(strings.TrimSpace(states[id]))
	if status != stateDone {
		if status == "" {
			status = statePending
		}
		return fmt.Errorf("%s requires Session %s to be DONE; current status is %s", gate, id, status)
	}
	return nil
}

func impactValidationEnabled(workspace string) bool {
	planPath := assessmentPlanPath(workspace)
	if fileExists(planPath) {
		plan, err := ReadAssessmentPlan(planPath)
		return err == nil && plan.ImpactValidation.Enabled
	}
	if cfg, err := readConfig(workspace); err == nil && cfg.ImpactValidationEnabled {
		return true
	}
	return false
}

func validateAssessmentPlanIfPresent(workspace string) error {
	path := assessmentPlanPath(workspace)
	if !fileExists(path) {
		return nil
	}
	plan, err := ReadAssessmentPlan(path)
	if err != nil {
		return err
	}
	if problems := ValidateAssessmentPlan(plan); len(problems) > 0 {
		return fmt.Errorf("assessment plan is invalid; resolve before Session 10 selection: %s", strings.Join(problems, "; "))
	}
	return nil
}

func impactValidationPolicy(workspace string) PlanImpactValidation {
	if plan, err := ReadAssessmentPlan(assessmentPlanPath(workspace)); err == nil {
		return normalizeImpactValidationPolicy(plan.ImpactValidation)
	}
	return normalizeImpactValidationPolicy(defaultImpactValidationPolicy(impactValidationEnabled(workspace)))
}

func defaultImpactValidationPolicy(enabled bool) PlanImpactValidation {
	return PlanImpactValidation{
		Enabled:                 enabled,
		SelectedFindings:        []string{},
		MaxRisk:                 3,
		AllowedActions:          []string{"non_sensitive_canary_read", "benign_browser_execution"},
		ForbiddenActions:        []string{"sensitive_data_access", "data_deletion", "persistence", "credential_dumping"},
		CleanupRequired:         true,
		CleanupEvidenceRequired: true,
	}
}

func normalizeImpactValidationPolicy(policy PlanImpactValidation) PlanImpactValidation {
	if policy.MaxRisk == 0 {
		policy.MaxRisk = 3
	}
	policy.AllowedActions = cleanFindings(policy.AllowedActions)
	if len(policy.AllowedActions) == 0 {
		policy.AllowedActions = []string{"non_sensitive_canary_read", "benign_browser_execution"}
	}
	policy.ForbiddenActions = cleanFindings(policy.ForbiddenActions)
	if len(policy.ForbiddenActions) == 0 {
		policy.ForbiddenActions = []string{"sensitive_data_access", "data_deletion", "persistence", "credential_dumping"}
	}
	return policy
}

func selectedFindingsFromHandoff(workspace string) []string {
	selection, err := readSelectedFindingsHandoff(workspace)
	if err == nil {
		findings := cleanFindings(selection.SelectedFindings)
		if len(findings) > 0 {
			return findings
		}
	}
	return nil
}

func readSelectedFindingsHandoff(workspace string) (*SelectedFindingsHandoff, error) {
	path := filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Session 10 handoff: %w", err)
	}
	var selection SelectedFindingsHandoff
	if err := decodeStrictYAML(raw, &selection); err != nil {
		return nil, fmt.Errorf("parse Session 10 handoff: %w", err)
	}
	return &selection, nil
}

func validateSession10Handoff(workspace string) error {
	selection, err := readSelectedFindingsHandoff(workspace)
	if err != nil {
		return err
	}
	if !selection.Enabled {
		return fmt.Errorf("Session 10 handoff must set enabled: true")
	}
	if filepath.Clean(selection.FindingRegistryPath) != filepath.Clean(findingRegistryPath(workspace)) {
		return fmt.Errorf("Session 10 handoff finding_registry_path must reference the current Session 09 registry")
	}
	if len(cleanFindings(selection.SelectedFindings)) == 0 {
		return fmt.Errorf("Session 10 handoff must select at least one finding")
	}
	if selection.MaxRisk < 1 || selection.MaxRisk > 5 {
		return fmt.Errorf("Session 10 handoff max_risk must be between 1 and 5")
	}
	if len(cleanFindings(selection.AllowedActions)) == 0 || len(cleanFindings(selection.ForbiddenActions)) == 0 {
		return fmt.Errorf("Session 10 handoff must define allowed_actions and forbidden_actions")
	}
	for _, action := range selection.AllowedActions {
		if containsRegistryValue(selection.ForbiddenActions, action) {
			return fmt.Errorf("Session 10 handoff action %q cannot be both allowed and forbidden", action)
		}
	}
	if !selection.HumanAuthorizationRequired || !selection.AuthorizationRecordRequired || !selection.EnvironmentAcknowledgementRequired {
		return fmt.Errorf("Session 10 handoff must require human authorization, an authorization record, and environment acknowledgement")
	}
	if !selection.ValidationPlanRequired {
		return fmt.Errorf("Session 10 handoff must require a per-finding validation plan")
	}
	if !selection.CleanupRequired || !selection.CleanupEvidenceRequired {
		return fmt.Errorf("Session 10 handoff must require cleanup and cleanup evidence")
	}
	if len(selection.PermittedExecutors) != 2 || !containsRegistryValue(selection.PermittedExecutors, "human") || !containsRegistryValue(selection.PermittedExecutors, "agent") {
		return fmt.Errorf("Session 10 handoff permitted_executors must be exactly human and agent")
	}
	for _, executor := range selection.PermittedExecutors {
		if !validImpactValidationExecutor(executor) {
			return fmt.Errorf("Session 10 handoff executor %q is invalid", executor)
		}
	}
	requiredEvidencePaths := map[string]string{
		"evidence_jsonl":    "10-impact-validation/evidence.jsonl",
		"transcript_dir":    "10-impact-validation/transcripts",
		"artifact_dir":      "10-impact-validation/artifacts",
		"authorization_dir": "10-impact-validation/authorizations",
		"readiness_dir":     "10-impact-validation/readiness",
		"cleanup_report":    "10-impact-validation/cleanup.md",
	}
	if len(selection.EvidencePaths) != len(requiredEvidencePaths) {
		return fmt.Errorf("Session 10 handoff evidence_paths must use the canonical current paths")
	}
	for key, expected := range requiredEvidencePaths {
		if selection.EvidencePaths[key] != expected {
			return fmt.Errorf("Session 10 handoff evidence_paths.%s must be %q", key, expected)
		}
	}
	return nil
}

func validImpactValidationExecutor(value string) bool {
	switch strings.TrimSpace(value) {
	case "human", "agent":
		return true
	default:
		return false
	}
}

func validateSelectedFindings(workspace string, findings []string) error {
	registryPath := findingRegistryPath(workspace)
	if !fileExists(registryPath) {
		return fmt.Errorf("finding registry is required before Session 10 selection; run Session 09 and write %s", registryPath)
	}
	issues := validateFindingRegistry(registryPath)
	if len(issues) > 0 {
		return fmt.Errorf("finding registry is invalid; run ensphere run report and resolve %s: %s", registryPath, reportIssueCodes(issues))
	}
	registry, err := readFindingRegistry(registryPath)
	if err != nil {
		return err
	}
	known := make(map[string]struct{}, len(registry.Findings))
	for _, finding := range registry.Findings {
		known[strings.TrimSpace(finding.ID)] = struct{}{}
	}
	var missing []string
	for _, finding := range findings {
		if _, ok := known[finding]; !ok {
			missing = append(missing, finding)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("selected finding(s) not found in %s: %s", registryPath, strings.Join(missing, ", "))
	}
	return nil
}

func reportIssueCodes(issues []ReportGateIssue) string {
	codes := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue.Code != "" {
			codes = append(codes, issue.Code)
		}
	}
	if len(codes) == 0 {
		return "reported issues"
	}
	return strings.Join(codes, ", ")
}

func sessionByID(id string) *Session {
	for _, session := range Sessions {
		if session.ID == id {
			s := session
			return &s
		}
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func configPath(workspace string) string   { return filepath.Join(workspace, "config.md") }
func progressPath(workspace string) string { return filepath.Join(workspace, "progress.md") }
func assessmentPlanPath(workspace string) string {
	return filepath.Join(workspace, "assessment-plan.yaml")
}
