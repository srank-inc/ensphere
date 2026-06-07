package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
	"gopkg.in/yaml.v3"
)

var reportRequiredSessions = []Session{
	{ID: "01", Directory: "01-recon"},
	{ID: "01.5", Directory: "01.5-session-plan"},
	{ID: "02", Directory: "02-injection"},
	{ID: "03", Directory: "03-auth"},
	{ID: "04", Directory: "04-authz"},
	{ID: "05", Directory: "05-xss"},
	{ID: "06", Directory: "06-ssrf"},
	{ID: "07", Directory: "07-cloud"},
	{ID: "08", Directory: "08-api"},
}

func RunReport(workspace string) (*ReportGateOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}

	gate := buildReportGate(workspace)
	if err := writeReportGate(workspace, gate); err != nil {
		return nil, err
	}
	if gate.Ready {
		action, err := WriteNextAction(workspace)
		if err != nil {
			return nil, err
		}
		gate.NextActionPath = action.ActionPath
		gate.PromptPath = action.PromptPath
	} else if err := writeBlockedReportAction(workspace, gate); err != nil {
		return nil, err
	}
	return gate, nil
}

func buildReportGate(workspace string) *ReportGateOutput {
	issues := make([]ReportGateIssue, 0)
	states, err := readProgress(workspace)
	if err != nil {
		issues = append(issues, gateIssue("error", "progress_read_failed", progressPath(workspace), err.Error()))
	}

	if !fileExists(assessmentPlanPath(workspace)) {
		issues = append(issues, gateIssue("error", "assessment_plan_missing", assessmentPlanPath(workspace), "assessment-plan.yaml is required before Session 09"))
	} else {
		plan, err := ReadAssessmentPlan(assessmentPlanPath(workspace))
		if err != nil {
			issues = append(issues, gateIssue("error", "assessment_plan_parse_failed", assessmentPlanPath(workspace), err.Error()))
		} else {
			for _, problem := range ValidateAssessmentPlan(plan) {
				issues = append(issues, gateIssue("error", "assessment_plan_invalid", assessmentPlanPath(workspace), problem))
			}
		}
	}

	if states != nil {
		issues = append(issues, validateSessionReportReadiness(workspace, states)...)
	}
	issues = append(issues, validateEvidenceFiles(workspace)...)

	registryPath := findingRegistryPath(workspace)
	registryState := "missing"
	if fileExists(registryPath) {
		registryState = "valid"
		registryIssues := validateFindingRegistry(registryPath)
		if len(registryIssues) > 0 {
			registryState = "invalid"
			issues = append(issues, registryIssues...)
		}
	}

	ready := !hasErrorIssue(issues)
	message := "Report gate passed. Session 09 can generate or refresh the evidence-backed assessment report."
	if !ready {
		message = "Report gate blocked. Resolve error issues before treating Session 09 as ready."
	}

	return &ReportGateOutput{
		SchemaVersion:        1,
		Workspace:            workspace,
		Ready:                ready,
		GatePath:             reportGatePath(workspace),
		GateMarkdownPath:     reportGateMarkdownPath(workspace),
		FindingRegistryPath:  registryPath,
		FindingRegistryState: registryState,
		Issues:               issues,
		NextActionPath:       filepath.Join(workspace, "next-action.md"),
		PromptPath:           filepath.Join(workspace, "agent-prompt.md"),
		Message:              message,
	}
}

func validateSessionReportReadiness(workspace string, states map[string]string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, session := range reportRequiredSessions {
		state := strings.ToUpper(strings.TrimSpace(states[session.ID]))
		if !isTerminalState(state) {
			issues = append(issues, gateIssue("error", "session_not_terminal", progressPath(workspace), fmt.Sprintf("Session %s is %s; Session 09 requires sessions 01, 01.5, and 02-08 to be DONE, SKIPPED, BLOCKED, or NOT_APPLICABLE", session.ID, state)))
			continue
		}
		reportPath := filepath.Join(workspace, session.Directory, "report.md")
		if !fileExists(reportPath) {
			issues = append(issues, gateIssue("error", "session_report_missing", reportPath, fmt.Sprintf("Session %s is %s but report.md is missing", session.ID, state)))
			continue
		}
		if isEmptyFile(reportPath) {
			issues = append(issues, gateIssue("error", "session_report_empty", reportPath, fmt.Sprintf("Session %s report.md is empty", session.ID)))
		}
	}
	return issues
}

func validateEvidenceFiles(workspace string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "evidence.jsonl")
		if !fileExists(path) {
			continue
		}
		result, err := evidence.VerifyChain(path)
		if err != nil {
			issues = append(issues, gateIssue("error", "evidence_verify_failed", path, err.Error()))
			continue
		}
		if !result.Valid {
			issues = append(issues, gateIssue("error", "evidence_hash_chain_invalid", path, fmt.Sprintf("hash chain invalid at %s: %s", result.BrokenAt, result.Error)))
		}
		if result.SkippedLines > 0 {
			issues = append(issues, gateIssue("warning", "evidence_skipped_lines", path, fmt.Sprintf("%d malformed evidence line(s) were skipped", result.SkippedLines)))
		}
	}
	return issues
}

func validateFindingRegistry(path string) []ReportGateIssue {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "finding_registry_read_failed", path, err.Error())}
	}
	registry, err := parseFindingRegistry(raw)
	if err != nil {
		return []ReportGateIssue{gateIssue("error", "finding_registry_parse_failed", path, err.Error())}
	}
	var issues []ReportGateIssue
	if registry.SchemaVersion != 1 {
		issues = append(issues, gateIssue("error", "finding_registry_invalid", path, "schema_version must be 1"))
	}
	seen := make(map[string]struct{}, len(registry.Findings))
	for i, finding := range registry.Findings {
		refPath := fmt.Sprintf("%s#findings[%d]", path, i)
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			issues = append(issues, gateIssue("error", "finding_id_missing", refPath, "finding id is required"))
		} else if _, ok := seen[id]; ok {
			issues = append(issues, gateIssue("error", "finding_id_duplicate", refPath, fmt.Sprintf("duplicate finding id %s", id)))
		} else {
			seen[id] = struct{}{}
		}
		if strings.TrimSpace(finding.Title) == "" {
			issues = append(issues, gateIssue("error", "finding_title_missing", refPath, "finding title is required"))
		}
		if strings.TrimSpace(finding.Category) == "" {
			issues = append(issues, gateIssue("error", "finding_category_missing", refPath, "finding category is required"))
		}
		if strings.TrimSpace(finding.Status) == "" {
			issues = append(issues, gateIssue("error", "finding_status_missing", refPath, "finding status is required"))
		} else if !validFindingStatus(finding.Status) {
			issues = append(issues, gateIssue("error", "finding_status_invalid", refPath, fmt.Sprintf("finding status %q is invalid", finding.Status)))
		}
		if strings.TrimSpace(finding.Confidence) == "" {
			issues = append(issues, gateIssue("error", "finding_confidence_missing", refPath, "finding confidence is required"))
		} else if !validFindingConfidence(finding.Confidence) {
			issues = append(issues, gateIssue("error", "finding_confidence_invalid", refPath, fmt.Sprintf("finding confidence %q is invalid", finding.Confidence)))
		}
		if strings.TrimSpace(finding.Severity) == "" {
			issues = append(issues, gateIssue("error", "finding_severity_missing", refPath, "finding severity is required"))
		} else if !validFindingSeverity(finding.Severity) {
			issues = append(issues, gateIssue("error", "finding_severity_invalid", refPath, fmt.Sprintf("finding severity %q is invalid", finding.Severity)))
		}
		if !findingHasCitation(finding) {
			issues = append(issues, gateIssue("error", "finding_uncited", refPath, fmt.Sprintf("finding %s has no evidence_ids, transcripts, import_refs, or manual_notes", displayFindingID(id))))
		}
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "transcripts", finding.Transcripts)...)
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "artifact_paths", finding.ArtifactPaths)...)
		issues = append(issues, validateCitationPaths(workspaceRootForArtifact(path), refPath, "cleanup_evidence", finding.CleanupEvidence)...)
		if len(finding.EvidenceCategories) == 0 {
			issues = append(issues, gateIssue("error", "finding_evidence_category_missing", refPath, "at least one evidence category is required"))
		}
		for _, category := range finding.EvidenceCategories {
			if !validEvidenceCategory(category) {
				issues = append(issues, gateIssue("error", "finding_evidence_category_invalid", refPath, fmt.Sprintf("evidence category %q is invalid", category)))
			}
		}
		if strings.TrimSpace(finding.CoverageLabel) == "" {
			issues = append(issues, gateIssue("error", "finding_coverage_missing", refPath, "coverage_label is required"))
		} else if !validCoverageLabel(finding.CoverageLabel) {
			issues = append(issues, gateIssue("error", "finding_coverage_invalid", refPath, fmt.Sprintf("coverage_label %q is invalid", finding.CoverageLabel)))
		}
	}
	return issues
}

func readFindingRegistry(path string) (*FindingRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read finding registry: %w", err)
	}
	return parseFindingRegistry(raw)
}

func parseFindingRegistry(raw []byte) (*FindingRegistry, error) {
	var registry FindingRegistry
	if err := yaml.Unmarshal(raw, &registry); err != nil {
		return nil, fmt.Errorf("parse finding registry: %w", err)
	}
	return &registry, nil
}

func writeReportGate(workspace string, gate *ReportGateOutput) error {
	if err := os.MkdirAll(filepath.Join(workspace, "09-report"), 0755); err != nil {
		return fmt.Errorf("create report gate directory: %w", err)
	}
	raw, err := yaml.Marshal(gate)
	if err != nil {
		return fmt.Errorf("encode report gate: %w", err)
	}
	if err := os.WriteFile(reportGatePath(workspace), raw, 0644); err != nil {
		return fmt.Errorf("write report gate: %w", err)
	}
	if err := os.WriteFile(reportGateMarkdownPath(workspace), []byte(renderReportGateMarkdown(gate)), 0644); err != nil {
		return fmt.Errorf("write report gate markdown: %w", err)
	}
	return nil
}

func writeBlockedReportAction(workspace string, gate *ReportGateOutput) error {
	actionPath := filepath.Join(workspace, "next-action.md")
	promptPath := filepath.Join(workspace, "agent-prompt.md")
	if err := os.WriteFile(actionPath, []byte(renderBlockedReportAction(gate)), 0644); err != nil {
		return fmt.Errorf("write report gate action: %w", err)
	}
	if err := os.WriteFile(promptPath, []byte(fmt.Sprintf("ensphere status\n\nResolve report gate issues listed in %s before running Session 09.\n", gate.GateMarkdownPath)), 0644); err != nil {
		return fmt.Errorf("write report gate prompt: %w", err)
	}
	gate.NextActionPath = actionPath
	gate.PromptPath = promptPath
	return nil
}

func renderReportGateMarkdown(gate *ReportGateOutput) string {
	var b strings.Builder
	b.WriteString("# Session 09 Report Gate\n\n")
	b.WriteString(fmt.Sprintf("- **Ready**: %t\n", gate.Ready))
	b.WriteString(fmt.Sprintf("- **Finding Registry**: %s\n", gate.FindingRegistryState))
	b.WriteString(fmt.Sprintf("- **Finding Registry Path**: %s\n\n", gate.FindingRegistryPath))
	if len(gate.Issues) == 0 {
		b.WriteString("No blocking or warning issues detected.\n")
		return b.String()
	}
	b.WriteString("| Severity | Code | Path | Message |\n")
	b.WriteString("|----------|------|------|---------|\n")
	for _, issue := range gate.Issues {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", escapeMarkdownCell(issue.Severity), escapeMarkdownCell(issue.Code), escapeMarkdownCell(issue.Path), escapeMarkdownCell(issue.Message)))
	}
	return b.String()
}

func renderBlockedReportAction(gate *ReportGateOutput) string {
	var b strings.Builder
	b.WriteString("# Next Action\n\n")
	b.WriteString("Session 09 is blocked by report gate errors.\n\n")
	b.WriteString(fmt.Sprintf("- **Gate Report**: %s\n", gate.GateMarkdownPath))
	b.WriteString(fmt.Sprintf("- **Machine Gate**: %s\n\n", gate.GatePath))
	for _, issue := range gate.Issues {
		if issue.Severity != "error" {
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s`: %s", issue.Code, issue.Message))
		if issue.Path != "" {
			b.WriteString(fmt.Sprintf(" (`%s`)", issue.Path))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func gateIssue(severity, code, path, message string) ReportGateIssue {
	return ReportGateIssue{
		Severity: severity,
		Code:     code,
		Path:     path,
		Message:  message,
	}
}

func hasErrorIssue(issues []ReportGateIssue) bool {
	for _, issue := range issues {
		if issue.Severity == "error" {
			return true
		}
	}
	return false
}

func isTerminalState(state string) bool {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case stateDone, stateSkipped, stateBlocked, stateNA:
		return true
	default:
		return false
	}
}

func isEmptyFile(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(raw)) == ""
}

func findingHasCitation(finding FindingSummary) bool {
	return hasNonEmptyString(finding.EvidenceIDs) ||
		hasNonEmptyString(finding.Transcripts) ||
		hasNonEmptyString(finding.ArtifactPaths) ||
		hasNonEmptyString(finding.CleanupEvidence) ||
		hasNonEmptyString(finding.ImportRefs) ||
		hasNonEmptyString(finding.ManualNotes)
}

func hasNonEmptyString(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func validFindingStatus(value string) bool {
	switch normalizeRegistryValue(value) {
	case "exploited",
		"strong_evidence_not_exploited",
		"blocked_by_security",
		"blocked_by_operational_constraint",
		"false_positive",
		"not_tested":
		return true
	default:
		return false
	}
}

func validFindingConfidence(value string) bool {
	switch normalizeRegistryValue(value) {
	case "high", "medium", "low", "not_applicable", "none":
		return true
	default:
		return false
	}
}

func validFindingSeverity(value string) bool {
	switch normalizeRegistryValue(value) {
	case "critical", "high", "medium", "low", "info", "informational", "not_applicable", "none":
		return true
	default:
		return false
	}
}

func validEvidenceCategory(value string) bool {
	switch normalizeRegistryValue(value) {
	case "imported_lead",
		"ensphere_measurement",
		"agent_judgment",
		"exploit_attempt",
		"exploit_result":
		return true
	default:
		return false
	}
}

func normalizeRegistryValue(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "-", "_")))
}

func displayFindingID(id string) string {
	if id == "" {
		return "<missing-id>"
	}
	return id
}

func escapeMarkdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func validateCitationPaths(workspace, refPath, field string, values []string) []ReportGateIssue {
	var issues []ReportGateIssue
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !safeWorkspaceRelativePath(value) {
			issues = append(issues, gateIssue("error", "finding_path_unsafe", refPath, fmt.Sprintf("%s path %q must be workspace-relative and must not escape the workspace", field, value)))
			continue
		}
		if workspace != "" {
			clean := cleanCitationPath(value)
			joined := filepath.Join(workspace, filepath.FromSlash(clean))
			rel, err := filepath.Rel(workspace, joined)
			if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				issues = append(issues, gateIssue("error", "finding_path_unsafe", refPath, fmt.Sprintf("%s path %q resolves outside workspace", field, value)))
			}
		}
	}
	return issues
}

func safeWorkspaceRelativePath(value string) bool {
	path := cleanCitationPath(value)
	if path == "" || path == "." {
		return false
	}
	if strings.Contains(path, "\x00") || strings.Contains(path, "\\") || strings.Contains(path, "://") || strings.HasPrefix(path, "~") {
		return false
	}
	if len(path) >= 2 && path[1] == ':' {
		return false
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "/") {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	return clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func cleanCitationPath(value string) string {
	value = strings.TrimSpace(value)
	if before, _, ok := strings.Cut(value, "#"); ok {
		value = before
	}
	return strings.TrimSpace(value)
}

func workspaceRootForArtifact(path string) string {
	dir := filepath.Dir(path)
	if filepath.Base(dir) == "09-report" || filepath.Base(dir) == "11-final-report" {
		return filepath.Dir(dir)
	}
	return filepath.Dir(dir)
}

func reportGatePath(workspace string) string {
	return filepath.Join(workspace, "09-report", "report-gate.yaml")
}

func reportGateMarkdownPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "report-gate.md")
}

func findingRegistryPath(workspace string) string {
	return filepath.Join(workspace, "09-report", "finding-registry.yaml")
}
