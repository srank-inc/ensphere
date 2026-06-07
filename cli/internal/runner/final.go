package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func RunFinalReport(workspace string) (*FinalReportOutput, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}

	out := &FinalReportOutput{
		SchemaVersion:      1,
		Workspace:          workspace,
		SourceRegistryPath: findingRegistryPath(workspace),
		OutcomePath:        exploitOutcomesPath(workspace),
		FinalRegistryPath:  finalFindingRegistryPath(workspace),
		EvidenceAppendix:   filepath.Join(workspace, "11-final-report", "evidence-appendix.md"),
		NextActionPath:     filepath.Join(workspace, "next-action.md"),
		PromptPath:         filepath.Join(workspace, "agent-prompt.md"),
	}

	issues := validateFinalReportInputs(workspace)
	out.Issues = append(out.Issues, issues...)
	if hasErrorIssue(out.Issues) {
		out.Ready = false
		out.Message = "Final report gate blocked. Resolve Session 10 outcome and registry issues before producing Session 11 artifacts."
		if err := writeBlockedFinalAction(workspace, out); err != nil {
			return nil, err
		}
		return out, nil
	}

	registry, err := readFindingRegistry(out.SourceRegistryPath)
	if err != nil {
		return nil, err
	}
	outcomes, err := readExploitOutcomes(out.OutcomePath)
	if err != nil {
		return nil, err
	}
	finalRegistry, updated, preserved := mergeFinalFindingRegistry(registry, outcomes)
	out.UpdatedFindings = updated
	out.PreservedFindings = preserved
	if err := writeFinalRegistry(workspace, finalRegistry, out); err != nil {
		return nil, err
	}
	out.Ready = true
	out.Message = "Session 11 finding registry derived from Session 09 registry and Session 10 outcomes. Original evidence rows and Session 09 registry were not modified."
	action := &NextAction{
		SchemaVersion: 1,
		Workspace:     workspace,
		Session:       sessionByID("11"),
		ActionPath:    out.NextActionPath,
		PromptPath:    out.PromptPath,
		Message:       "Next session: 11 - Exploit-Verified Final Report",
	}
	if err := os.WriteFile(action.ActionPath, []byte(renderNextAction(action)), 0644); err != nil {
		return nil, fmt.Errorf("write next action: %w", err)
	}
	if err := os.WriteFile(action.PromptPath, []byte(renderAgentPrompt(action)), 0644); err != nil {
		return nil, fmt.Errorf("write agent prompt: %w", err)
	}
	return out, nil
}

func validateFinalReportInputs(workspace string) []ReportGateIssue {
	var issues []ReportGateIssue
	states, err := readProgress(workspace)
	if err != nil {
		issues = append(issues, gateIssue("error", "progress_read_failed", progressPath(workspace), err.Error()))
	} else if strings.ToUpper(strings.TrimSpace(states["10"])) != stateDone {
		issues = append(issues, gateIssue("error", "session10_not_done", progressPath(workspace), "Session 11 requires Session 10 to be marked DONE"))
	}

	registryPath := findingRegistryPath(workspace)
	if !fileExists(registryPath) {
		issues = append(issues, gateIssue("error", "finding_registry_missing", registryPath, "Session 09 finding registry is required"))
	} else {
		issues = append(issues, validateFindingRegistry(registryPath)...)
	}
	selected := selectedFindingsFromHandoff(workspace)
	if len(selected) == 0 {
		issues = append(issues, gateIssue("error", "selected_findings_missing", filepath.Join(workspace, "10-exploitation", "selected-findings.yaml"), "Session 11 requires selected findings from Session 10"))
	} else if err := validateSelectedFindings(workspace, selected); err != nil {
		issues = append(issues, gateIssue("error", "selected_findings_invalid", filepath.Join(workspace, "10-exploitation", "selected-findings.yaml"), err.Error()))
	}

	outcomePath := exploitOutcomesPath(workspace)
	if !fileExists(outcomePath) {
		issues = append(issues, gateIssue("error", "exploit_outcomes_missing", outcomePath, "Session 10 exploit-outcomes.yaml is required"))
		return issues
	}
	outcomes, err := readExploitOutcomes(outcomePath)
	if err != nil {
		issues = append(issues, gateIssue("error", "exploit_outcomes_parse_failed", outcomePath, err.Error()))
		return issues
	}
	issues = append(issues, validateExploitOutcomes(workspace, outcomes, selected)...)
	return issues
}

func readExploitOutcomes(path string) (*ExploitOutcomes, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read exploit outcomes: %w", err)
	}
	var outcomes ExploitOutcomes
	if err := yaml.Unmarshal(raw, &outcomes); err != nil {
		return nil, fmt.Errorf("parse exploit outcomes: %w", err)
	}
	return &outcomes, nil
}

func validateExploitOutcomes(workspace string, outcomes *ExploitOutcomes, selected []string) []ReportGateIssue {
	var issues []ReportGateIssue
	path := exploitOutcomesPath(workspace)
	if outcomes.SchemaVersion != 1 {
		issues = append(issues, gateIssue("error", "exploit_outcomes_invalid", path, "schema_version must be 1"))
	}
	registry, err := readFindingRegistry(findingRegistryPath(workspace))
	if err != nil {
		return append(issues, gateIssue("error", "finding_registry_read_failed", findingRegistryPath(workspace), err.Error()))
	}
	known := make(map[string]struct{}, len(registry.Findings))
	for _, finding := range registry.Findings {
		known[strings.TrimSpace(finding.ID)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(outcomes.Outcomes))
	for i, outcome := range outcomes.Outcomes {
		refPath := fmt.Sprintf("%s#outcomes[%d]", path, i)
		id := strings.TrimSpace(outcome.ID)
		if id == "" {
			issues = append(issues, gateIssue("error", "exploit_outcome_id_missing", refPath, "outcome id is required"))
		} else if _, ok := known[id]; !ok {
			issues = append(issues, gateIssue("error", "exploit_outcome_unknown_finding", refPath, fmt.Sprintf("outcome id %s is not in the Session 09 finding registry", id)))
		} else if _, ok := seen[id]; ok {
			issues = append(issues, gateIssue("error", "exploit_outcome_duplicate", refPath, fmt.Sprintf("duplicate outcome id %s", id)))
		} else {
			seen[id] = struct{}{}
		}
		if !validFinalOutcomeStatus(outcome.Status) {
			issues = append(issues, gateIssue("error", "exploit_outcome_status_invalid", refPath, fmt.Sprintf("status %q is invalid for Session 11", outcome.Status)))
		}
		if !exploitOutcomeHasCitation(outcome) {
			issues = append(issues, gateIssue("error", "exploit_outcome_uncited", refPath, fmt.Sprintf("outcome %s has no evidence_ids, transcripts, artifact_paths, cleanup_evidence, or notes", displayFindingID(id))))
		}
		if normalizeRegistryValue(outcome.Status) == "exploited" && !exploitOutcomeHasProofCitation(outcome) {
			issues = append(issues, gateIssue("error", "exploit_outcome_proof_missing", refPath, fmt.Sprintf("exploited outcome %s requires evidence_ids, transcripts, or artifact_paths", displayFindingID(id))))
		}
		if strings.TrimSpace(outcome.CleanupStatus) == "" {
			issues = append(issues, gateIssue("error", "exploit_cleanup_status_missing", refPath, fmt.Sprintf("outcome %s requires cleanup_status", displayFindingID(id))))
		} else if !validCleanupStatus(outcome.CleanupStatus) {
			issues = append(issues, gateIssue("error", "exploit_cleanup_status_invalid", refPath, fmt.Sprintf("cleanup_status %q is invalid", outcome.CleanupStatus)))
		}
		issues = append(issues, validateCitationPaths(workspace, refPath, "transcripts", outcome.Transcripts)...)
		issues = append(issues, validateCitationPaths(workspace, refPath, "artifact_paths", outcome.ArtifactPaths)...)
		issues = append(issues, validateCitationPaths(workspace, refPath, "cleanup_evidence", outcome.CleanupEvidence)...)
		for _, category := range outcome.EvidenceCategories {
			if !validEvidenceCategory(category) {
				issues = append(issues, gateIssue("error", "exploit_outcome_evidence_category_invalid", refPath, fmt.Sprintf("evidence category %q is invalid", category)))
			}
		}
	}
	for _, finding := range selected {
		finding = strings.TrimSpace(finding)
		if finding == "" {
			continue
		}
		if _, ok := seen[finding]; !ok {
			issues = append(issues, gateIssue("error", "exploit_outcome_missing_selected", path, fmt.Sprintf("selected finding %s has no Session 10 outcome", finding)))
		}
	}
	return issues
}

func mergeFinalFindingRegistry(registry *FindingRegistry, outcomes *ExploitOutcomes) (*FindingRegistry, []string, []string) {
	byID := make(map[string]ExploitOutcome, len(outcomes.Outcomes))
	for _, outcome := range outcomes.Outcomes {
		byID[strings.TrimSpace(outcome.ID)] = outcome
	}
	finalRegistry := &FindingRegistry{
		SchemaVersion: 1,
		GeneratedFrom: "Session 11 derived from Session 09 finding registry and Session 10 outcomes",
		Findings:      make([]FindingSummary, 0, len(registry.Findings)),
	}
	var updated []string
	var preserved []string
	for _, finding := range registry.Findings {
		merged := finding
		merged.OriginalStatus = finding.Status
		if outcome, ok := byID[strings.TrimSpace(finding.ID)]; ok {
			status := normalizeRegistryValue(outcome.Status)
			merged.Status = status
			merged.SelectedForExploitation = true
			merged.ExploitVerified = status == "exploited"
			merged.ExploitOutcomeReason = outcome.OutcomeReason
			merged.CleanupStatus = outcome.CleanupStatus
			merged.EvidenceIDs = appendUniqueStrings(merged.EvidenceIDs, outcome.EvidenceIDs)
			merged.Transcripts = appendUniqueStrings(merged.Transcripts, outcome.Transcripts)
			merged.ArtifactPaths = appendUniqueStrings(merged.ArtifactPaths, outcome.ArtifactPaths)
			merged.CleanupEvidence = appendUniqueStrings(merged.CleanupEvidence, outcome.CleanupEvidence)
			merged.EvidenceCategories = appendUniqueStrings(merged.EvidenceCategories, finalEvidenceCategories(outcome))
			if outcome.Notes != "" {
				merged.Notes = strings.TrimSpace(strings.TrimSpace(merged.Notes) + "\n" + outcome.Notes)
			}
			updated = append(updated, finding.ID)
		} else {
			merged.SelectedForExploitation = false
			preserved = append(preserved, finding.ID)
		}
		finalRegistry.Findings = append(finalRegistry.Findings, merged)
	}
	return finalRegistry, updated, preserved
}

func writeFinalRegistry(workspace string, registry *FindingRegistry, out *FinalReportOutput) error {
	dir := filepath.Join(workspace, "11-final-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create final report directory: %w", err)
	}
	raw, err := yaml.Marshal(registry)
	if err != nil {
		return fmt.Errorf("encode final finding registry: %w", err)
	}
	if err := os.WriteFile(out.FinalRegistryPath, raw, 0644); err != nil {
		return fmt.Errorf("write final finding registry: %w", err)
	}
	if err := os.WriteFile(out.EvidenceAppendix, []byte(renderFinalEvidenceAppendix(out, registry)), 0644); err != nil {
		return fmt.Errorf("write final evidence appendix: %w", err)
	}
	return nil
}

func renderFinalEvidenceAppendix(out *FinalReportOutput, registry *FindingRegistry) string {
	var b strings.Builder
	b.WriteString("# Session 11 Evidence Appendix\n\n")
	b.WriteString("This appendix is generated from the derived Session 11 finding registry. Session 09 evidence rows are not modified.\n\n")
	b.WriteString(fmt.Sprintf("- **Source Registry**: %s\n", out.SourceRegistryPath))
	b.WriteString(fmt.Sprintf("- **Outcome File**: %s\n", out.OutcomePath))
	b.WriteString(fmt.Sprintf("- **Final Registry**: %s\n\n", out.FinalRegistryPath))
	b.WriteString("| Finding | Status | Original Status | Evidence IDs | Transcripts | Artifacts | Cleanup Evidence |\n")
	b.WriteString("|---------|--------|-----------------|--------------|-------------|-----------|------------------|\n")
	for _, finding := range registry.Findings {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdownCell(finding.ID),
			escapeMarkdownCell(finding.Status),
			escapeMarkdownCell(finding.OriginalStatus),
			escapeMarkdownCell(strings.Join(finding.EvidenceIDs, ", ")),
			escapeMarkdownCell(strings.Join(finding.Transcripts, ", ")),
			escapeMarkdownCell(strings.Join(finding.ArtifactPaths, ", ")),
			escapeMarkdownCell(strings.Join(finding.CleanupEvidence, ", ")),
		))
	}
	return b.String()
}

func writeBlockedFinalAction(workspace string, out *FinalReportOutput) error {
	var b strings.Builder
	b.WriteString("# Next Action\n\n")
	b.WriteString("Session 11 is blocked by final report gate errors.\n\n")
	for _, issue := range out.Issues {
		if issue.Severity != "error" {
			continue
		}
		b.WriteString(fmt.Sprintf("- `%s`: %s", issue.Code, issue.Message))
		if issue.Path != "" {
			b.WriteString(fmt.Sprintf(" (`%s`)", issue.Path))
		}
		b.WriteString("\n")
	}
	if err := os.WriteFile(out.NextActionPath, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("write final gate action: %w", err)
	}
	if err := os.WriteFile(out.PromptPath, []byte(fmt.Sprintf("ensphere status\n\nResolve Session 11 gate issues before writing the exploit-verified final report. Outcome file: %s\n", out.OutcomePath)), 0644); err != nil {
		return fmt.Errorf("write final gate prompt: %w", err)
	}
	return nil
}

func validFinalOutcomeStatus(value string) bool {
	switch normalizeRegistryValue(value) {
	case "exploited",
		"strong_evidence_not_exploited",
		"blocked_by_security",
		"blocked_by_operational_constraint",
		"false_positive":
		return true
	default:
		return false
	}
}

func exploitOutcomeHasCitation(outcome ExploitOutcome) bool {
	return hasNonEmptyString(outcome.EvidenceIDs) ||
		hasNonEmptyString(outcome.Transcripts) ||
		hasNonEmptyString(outcome.ArtifactPaths) ||
		hasNonEmptyString(outcome.CleanupEvidence) ||
		strings.TrimSpace(outcome.Notes) != ""
}

func exploitOutcomeHasProofCitation(outcome ExploitOutcome) bool {
	return hasNonEmptyString(outcome.EvidenceIDs) ||
		hasNonEmptyString(outcome.Transcripts) ||
		hasNonEmptyString(outcome.ArtifactPaths)
}

func finalEvidenceCategories(outcome ExploitOutcome) []string {
	if len(outcome.EvidenceCategories) > 0 {
		return outcome.EvidenceCategories
	}
	return []string{"exploit_attempt", "exploit_result"}
}

func validCleanupStatus(value string) bool {
	switch normalizeRegistryValue(value) {
	case "verified", "not_needed", "not_applicable", "partial", "blocked", "failed":
		return true
	default:
		return false
	}
}

func appendUniqueStrings(base []string, additions ...[]string) []string {
	seen := make(map[string]struct{}, len(base))
	out := make([]string, 0, len(base))
	for _, value := range base {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, values := range additions {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func exploitOutcomesPath(workspace string) string {
	return filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml")
}

func finalFindingRegistryPath(workspace string) string {
	return filepath.Join(workspace, "11-final-report", "finding-registry.yaml")
}
