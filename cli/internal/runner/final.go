package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
	"github.com/srank/ensphere/internal/verify"
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
		Workspace:          workspace,
		SourceRegistryPath: findingRegistryPath(workspace),
		OutcomePath:        impactValidationOutcomesPath(workspace),
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
	outcomes, err := readImpactValidationOutcomes(out.OutcomePath)
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
	out.Message = "Session 11 registry derived without modifying Session 09 evidence, registry, or finding statuses. Human-authorized Session 10 outcomes are attached as a separate dimension."
	action := &NextAction{
		Workspace:  workspace,
		Session:    sessionByID("11"),
		ActionPath: out.NextActionPath,
		PromptPath: out.PromptPath,
		Message:    "Next session: 11 - Optional Validation-Aware Final Report",
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
	reportGate := buildReportGate(workspace)
	for _, issue := range reportGate.Issues {
		if issue.Severity == "error" {
			issues = append(issues, issue)
		}
	}
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
		issues = append(issues, gateIssue("error", "selected_findings_missing", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), "Session 11 requires selected findings from Session 10"))
	} else if err := validateSelectedFindings(workspace, selected); err != nil {
		issues = append(issues, gateIssue("error", "selected_findings_invalid", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), err.Error()))
	}
	if err := validateSession10Handoff(workspace); err != nil {
		issues = append(issues, gateIssue("error", "session10_handoff_invalid", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), err.Error()))
	}
	session10Report := filepath.Join(workspace, "10-impact-validation", "report.md")
	if !fileExists(session10Report) || isEmptyFile(session10Report) {
		issues = append(issues, gateIssue("error", "session10_report_missing", session10Report, "a non-empty human-authorized Session 10 report is required"))
	}

	outcomePath := impactValidationOutcomesPath(workspace)
	if !fileExists(outcomePath) {
		issues = append(issues, gateIssue("error", "impact_validation_outcomes_missing", outcomePath, "Session 10 impact-validation-outcomes.yaml is required"))
		return issues
	}
	outcomes, err := readImpactValidationOutcomes(outcomePath)
	if err != nil {
		issues = append(issues, gateIssue("error", "impact_validation_outcomes_parse_failed", outcomePath, err.Error()))
		return issues
	}
	issues = append(issues, validateImpactValidationOutcomes(workspace, outcomes, selected)...)
	return issues
}

func readImpactValidationOutcomes(path string) (*ImpactValidationOutcomes, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read impact-validation outcomes: %w", err)
	}
	var outcomes ImpactValidationOutcomes
	if err := decodeStrictYAML(raw, &outcomes); err != nil {
		return nil, fmt.Errorf("parse impact-validation outcomes: %w", err)
	}
	return &outcomes, nil
}

func validateImpactValidationOutcomes(workspace string, outcomes *ImpactValidationOutcomes, selected []string) []ReportGateIssue {
	var issues []ReportGateIssue
	path := impactValidationOutcomesPath(workspace)
	if strings.TrimSpace(outcomes.GeneratedFrom) == "" {
		issues = append(issues, gateIssue("error", "impact_validation_generated_from_missing", path, "generated_from is required"))
	}
	handoff, err := readSelectedFindingsHandoff(workspace)
	if err != nil {
		return append(issues, gateIssue("error", "session10_handoff_read_failed", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), err.Error()))
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
	selectedSet := make(map[string]struct{}, len(selected))
	for _, id := range selected {
		selectedSet[strings.TrimSpace(id)] = struct{}{}
	}
	for i, outcome := range outcomes.Outcomes {
		refPath := fmt.Sprintf("%s#outcomes[%d]", path, i)
		id := strings.TrimSpace(outcome.ID)
		if id == "" {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_id_missing", refPath, "outcome id is required"))
		} else if _, ok := known[id]; !ok {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_unknown_finding", refPath, fmt.Sprintf("outcome id %s is not in the Session 09 finding registry", id)))
		} else if _, ok := seen[id]; ok {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_duplicate", refPath, fmt.Sprintf("duplicate outcome id %s", id)))
		} else {
			seen[id] = struct{}{}
		}
		if _, ok := selectedSet[id]; id != "" && !ok {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_not_selected", refPath, fmt.Sprintf("outcome id %s was not selected for Session 10", id)))
		}
		if !validFinalOutcomeStatus(outcome.Status) {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_status_invalid", refPath, fmt.Sprintf("status %q is invalid for Session 11", outcome.Status)))
		}
		if !validImpactValidationExecutor(outcome.Executor) {
			issues = append(issues, gateIssue("error", "impact_validation_executor_invalid", refPath, fmt.Sprintf("executor %q is invalid", outcome.Executor)))
		} else if !containsRegistryValue(handoff.PermittedExecutors, outcome.Executor) {
			issues = append(issues, gateIssue("error", "impact_validation_executor_not_permitted", refPath, fmt.Sprintf("executor %q is not permitted by the Session 10 handoff", outcome.Executor)))
		}
		if strings.TrimSpace(outcome.OutcomeReason) == "" {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_reason_missing", refPath, "outcome_reason is required"))
		}
		authorization, plan, authorizationIssues := validateSession10Authorization(workspace, refPath, outcome, handoff)
		issues = append(issues, authorizationIssues...)
		if authorization != nil && plan != nil {
			issues = append(issues, validateImpactReadinessAttestation(workspace, refPath, outcome, authorization)...)
			issues = append(issues, validateSession10Execution(workspace, refPath, outcome, authorization, plan)...)
		}
		if !impactValidationOutcomeHasCitation(outcome) {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_uncited", refPath, fmt.Sprintf("outcome %s has no evidence_ids, transcripts, artifact_paths, cleanup_evidence, or notes", displayFindingID(id))))
		}
		if strings.TrimSpace(outcome.Status) == "objective_achieved" && !impactValidationOutcomeHasProofCitation(outcome) {
			issues = append(issues, gateIssue("error", "impact_validation_proof_missing", refPath, fmt.Sprintf("objective_achieved outcome %s requires evidence_ids, transcripts, or artifact_paths", displayFindingID(id))))
		}
		if strings.TrimSpace(outcome.CleanupStatus) == "" {
			issues = append(issues, gateIssue("error", "impact_validation_cleanup_status_missing", refPath, fmt.Sprintf("outcome %s requires cleanup_status", displayFindingID(id))))
		} else if !validCleanupStatus(outcome.CleanupStatus) {
			issues = append(issues, gateIssue("error", "impact_validation_cleanup_status_invalid", refPath, fmt.Sprintf("cleanup_status %q is invalid", outcome.CleanupStatus)))
		}
		if handoff.CleanupEvidenceRequired && !hasNonEmptyString(outcome.CleanupEvidence) {
			issues = append(issues, gateIssue("error", "impact_validation_cleanup_evidence_missing", refPath, fmt.Sprintf("outcome %s requires cleanup_evidence", displayFindingID(id))))
		}
		issues = append(issues, validateCitationPaths(workspace, refPath, "transcripts", outcome.Transcripts)...)
		issues = append(issues, validateCitationPaths(workspace, refPath, "artifact_paths", outcome.ArtifactPaths)...)
		issues = append(issues, validateCitationPaths(workspace, refPath, "cleanup_evidence", outcome.CleanupEvidence)...)
		issues = append(issues, validateSession10EvidenceIDs(workspace, refPath, outcome, handoff)...)
		for _, category := range outcome.EvidenceCategories {
			if !validEvidenceCategory(category) {
				issues = append(issues, gateIssue("error", "impact_validation_evidence_category_invalid", refPath, fmt.Sprintf("evidence category %q is invalid", category)))
			}
		}
		if !containsRegistryValue(outcome.EvidenceCategories, "human_authorization") {
			issues = append(issues, gateIssue("error", "human_authorization_category_missing", refPath, fmt.Sprintf("outcome %s requires human_authorization evidence", displayFindingID(id))))
		}
		executionCategory := strings.TrimSpace(outcome.Executor) + "_execution"
		if validImpactValidationExecutor(outcome.Executor) && !containsRegistryValue(outcome.EvidenceCategories, executionCategory) {
			issues = append(issues, gateIssue("error", "executor_evidence_category_missing", refPath, fmt.Sprintf("outcome %s requires %s evidence", displayFindingID(id), executionCategory)))
		}
		for _, category := range []string{"impact_validation_attempt", "impact_validation_result"} {
			if !containsRegistryValue(outcome.EvidenceCategories, category) {
				issues = append(issues, gateIssue("error", "impact_validation_evidence_category_missing", refPath, fmt.Sprintf("outcome %s requires %s evidence", displayFindingID(id), category)))
			}
		}
	}
	for _, finding := range selected {
		finding = strings.TrimSpace(finding)
		if finding == "" {
			continue
		}
		if _, ok := seen[finding]; !ok {
			issues = append(issues, gateIssue("error", "impact_validation_outcome_missing_selected", path, fmt.Sprintf("selected finding %s has no Session 10 outcome", finding)))
		}
	}
	return issues
}

func validateSession10EvidenceIDs(workspace, refPath string, outcome ImpactValidationOutcome, handoff *SelectedFindingsHandoff) []ReportGateIssue {
	var issues []ReportGateIssue
	if len(cleanFindings(outcome.EvidenceIDs)) == 0 {
		return issues
	}
	relativePath := handoff.EvidencePaths["evidence_jsonl"]
	path := filepath.Join(workspace, filepath.FromSlash(relativePath))
	if !fileExists(path) {
		return append(issues, gateIssue("error", "impact_validation_evidence_file_missing", refPath, fmt.Sprintf("Session 10 evidence file %q is required for cited evidence IDs", relativePath)))
	}
	chain, err := evidence.VerifyChain(path)
	if err != nil {
		return append(issues, gateIssue("error", "impact_validation_evidence_read_failed", refPath, err.Error()))
	}
	if !chain.Valid || chain.SkippedLines > 0 {
		issues = append(issues, gateIssue("error", "impact_validation_evidence_chain_invalid", refPath, fmt.Sprintf("Session 10 evidence chain is invalid at %s: %s", chain.BrokenAt, chain.Error)))
		return issues
	}
	entries, _, err := evidence.ReadAll(path)
	if err != nil {
		return append(issues, gateIssue("error", "impact_validation_evidence_read_failed", refPath, err.Error()))
	}
	byID := make(map[string]evidence.Entry, len(entries))
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	for _, id := range outcome.EvidenceIDs {
		entry, ok := byID[strings.TrimSpace(id)]
		if !ok {
			issues = append(issues, gateIssue("error", "impact_validation_evidence_id_missing", refPath, fmt.Sprintf("evidence ID %q is absent from %s", id, relativePath)))
			continue
		}
		if strings.TrimSpace(entry.FindingRef) != strings.TrimSpace(outcome.ID) || entry.SessionNumber != 10 {
			issues = append(issues, gateIssue("error", "impact_validation_evidence_provenance_mismatch", refPath, fmt.Sprintf("evidence ID %q must reference finding %s and session 10", id, outcome.ID)))
		}
	}
	return issues
}

func validateImpactReadinessAttestation(workspace, refPath string, outcome ImpactValidationOutcome, auth *Session10Authorization) []ReportGateIssue {
	var issues []ReportGateIssue
	readinessPath := strings.TrimSpace(outcome.ReadinessPath)
	if readinessPath == "" {
		return append(issues, gateIssue("error", "impact_readiness_path_missing", refPath, "readiness_path from run impact-ready is required"))
	}
	pathIssues := validateCitationPaths(workspace, refPath, "readiness_path", []string{readinessPath})
	issues = append(issues, pathIssues...)
	if len(pathIssues) > 0 {
		return issues
	}
	raw, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(cleanCitationPath(readinessPath))))
	if err != nil {
		return append(issues, gateIssue("error", "impact_readiness_read_failed", refPath, err.Error()))
	}
	var attestation ImpactValidationReadinessAttestation
	if err := decodeStrictYAML(raw, &attestation); err != nil {
		return append(issues, gateIssue("error", "impact_readiness_invalid", refPath, err.Error()))
	}
	if !attestation.Ready || attestation.FindingID != outcome.ID || attestation.Executor != outcome.Executor || attestation.AuthorizationPath != outcome.AuthorizationPath || attestation.PlanPath != auth.PlanPath || attestation.PlanSHA256 != auth.PlanSHA256 {
		issues = append(issues, gateIssue("error", "impact_readiness_contract_mismatch", refPath, "readiness attestation must match the outcome, authorization, executor, and current plan hash"))
	}
	authorizationRaw, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(cleanCitationPath(outcome.AuthorizationPath))))
	if err == nil {
		authorizationHash := sha256.Sum256(authorizationRaw)
		if attestation.AuthorizationSHA256 != "sha256:"+hex.EncodeToString(authorizationHash[:]) {
			issues = append(issues, gateIssue("error", "impact_readiness_authorization_changed", refPath, "authorization record changed after run impact-ready; run the gate again"))
		}
	}
	checkedAt, checkedErr := time.Parse(time.RFC3339, strings.TrimSpace(attestation.CheckedAt))
	authorizedAt, authorizedErr := time.Parse(time.RFC3339, strings.TrimSpace(auth.AuthorizedAt))
	startedAt, startedErr := time.Parse(time.RFC3339, strings.TrimSpace(outcome.Execution.StartedAt))
	if checkedErr != nil {
		issues = append(issues, gateIssue("error", "impact_readiness_timestamp_invalid", refPath, "readiness checked_at must be RFC3339"))
	} else if authorizedErr == nil && checkedAt.Before(authorizedAt) {
		issues = append(issues, gateIssue("error", "readiness_precedes_authorization", refPath, "readiness.checked_at must not precede authorization.authorized_at"))
	} else if startedErr == nil && startedAt.Before(checkedAt) {
		issues = append(issues, gateIssue("error", "execution_precedes_readiness", refPath, "execution.started_at must not precede the readiness attestation"))
	}
	return issues
}

func validateSession10Authorization(workspace, refPath string, outcome ImpactValidationOutcome, handoff *SelectedFindingsHandoff) (*Session10Authorization, *Session10Plan, []ReportGateIssue) {
	var issues []ReportGateIssue
	authorizationPath := strings.TrimSpace(outcome.AuthorizationPath)
	if authorizationPath == "" {
		return nil, nil, append(issues, gateIssue("error", "authorization_path_missing", refPath, "authorization_path is required"))
	}
	pathIssues := validateCitationPaths(workspace, refPath, "authorization_path", []string{authorizationPath})
	issues = append(issues, pathIssues...)
	if len(pathIssues) > 0 {
		return nil, nil, issues
	}
	raw, err := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(cleanCitationPath(authorizationPath))))
	if err != nil {
		return nil, nil, append(issues, gateIssue("error", "authorization_record_read_failed", refPath, err.Error()))
	}
	var auth Session10Authorization
	if err := decodeStrictYAML(raw, &auth); err != nil {
		return nil, nil, append(issues, gateIssue("error", "authorization_record_invalid", refPath, err.Error()))
	}
	if strings.TrimSpace(auth.FindingID) != strings.TrimSpace(outcome.ID) {
		issues = append(issues, gateIssue("error", "authorization_finding_mismatch", refPath, "authorization.finding_id must match outcome.id"))
	}
	if strings.TrimSpace(auth.PlanPath) == "" {
		issues = append(issues, gateIssue("error", "authorization_plan_path_missing", refPath, "authorization.plan_path is required"))
	} else {
		issues = append(issues, validateCitationPaths(workspace, refPath, "authorization.plan_path", []string{auth.PlanPath})...)
	}
	if strings.TrimSpace(auth.PlanRevision) == "" {
		issues = append(issues, gateIssue("error", "authorization_plan_revision_missing", refPath, "authorization.plan_revision is required"))
	}
	var plan *Session10Plan
	if !validSHA256Reference(auth.PlanSHA256) {
		issues = append(issues, gateIssue("error", "authorization_plan_sha256_invalid", refPath, "authorization.plan_sha256 must be sha256:<64 lowercase hex characters>"))
	} else if strings.TrimSpace(auth.PlanPath) != "" && safeWorkspaceRelativePath(auth.PlanPath) {
		planPath := filepath.Join(workspace, filepath.FromSlash(cleanCitationPath(auth.PlanPath)))
		if planRaw, err := os.ReadFile(planPath); err == nil {
			actual := sha256.Sum256(planRaw)
			actualRef := "sha256:" + hex.EncodeToString(actual[:])
			if strings.TrimSpace(auth.PlanSHA256) != actualRef {
				issues = append(issues, gateIssue("error", "authorization_plan_sha256_mismatch", refPath, "authorization.plan_sha256 does not match the current plan bytes; reauthorization is required"))
			}
			var decoded Session10Plan
			if err := decodeStrictYAML(planRaw, &decoded); err != nil {
				issues = append(issues, gateIssue("error", "authorization_plan_invalid", refPath, err.Error()))
			} else {
				plan = &decoded
				issues = append(issues, validateSession10Plan(workspace, refPath, &decoded, &auth, handoff)...)
			}
		}
	}
	if strings.TrimSpace(auth.AuthorizedBy) == "" {
		issues = append(issues, gateIssue("error", "authorization_authorizer_missing", refPath, "authorization.authorized_by is required"))
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(auth.AuthorizedAt)); err != nil {
		issues = append(issues, gateIssue("error", "authorization_timestamp_invalid", refPath, "authorization.authorized_at must be an RFC3339 timestamp"))
	}
	if auth.Executor != outcome.Executor {
		issues = append(issues, gateIssue("error", "authorization_executor_mismatch", refPath, "authorization.executor must match outcome.executor"))
	}
	if strings.TrimSpace(auth.Environment) == "" || !auth.EnvironmentAcknowledged {
		issues = append(issues, gateIssue("error", "authorization_environment_missing", refPath, "authorization requires a named environment and environment_acknowledged: true"))
	}
	if len(auth.AuthorizedActionIDs) == 0 {
		issues = append(issues, gateIssue("error", "authorization_actions_missing", refPath, "authorization.authorized_action_ids is required"))
	}
	if auth.MaxActions < 1 {
		issues = append(issues, gateIssue("error", "authorization_max_actions_invalid", refPath, "authorization.max_actions must be at least 1"))
	}
	if auth.MaxDurationMinutes < 1 {
		issues = append(issues, gateIssue("error", "authorization_max_duration_invalid", refPath, "authorization.max_duration_minutes must be at least 1"))
	}
	if auth.MaxRisk < 1 || auth.MaxRisk > handoff.MaxRisk {
		issues = append(issues, gateIssue("error", "authorization_max_risk_invalid", refPath, fmt.Sprintf("authorization.max_risk must be between 1 and the handoff max_risk %d", handoff.MaxRisk)))
	}
	return &auth, plan, issues
}

func validateSession10Execution(workspace, refPath string, outcome ImpactValidationOutcome, auth *Session10Authorization, plan *Session10Plan) []ReportGateIssue {
	var issues []ReportGateIssue
	execution := outcome.Execution
	startedAt, startedErr := time.Parse(time.RFC3339, strings.TrimSpace(execution.StartedAt))
	completedAt, completedErr := time.Parse(time.RFC3339, strings.TrimSpace(execution.CompletedAt))
	authorizedAt, authorizedErr := time.Parse(time.RFC3339, strings.TrimSpace(auth.AuthorizedAt))
	if startedErr != nil {
		issues = append(issues, gateIssue("error", "execution_started_at_invalid", refPath, "execution.started_at must be an RFC3339 timestamp"))
	}
	if completedErr != nil {
		issues = append(issues, gateIssue("error", "execution_completed_at_invalid", refPath, "execution.completed_at must be an RFC3339 timestamp"))
	}
	if startedErr == nil && completedErr == nil {
		if authorizedErr == nil && startedAt.Before(authorizedAt) {
			issues = append(issues, gateIssue("error", "execution_precedes_authorization", refPath, "execution.started_at must not precede authorization.authorized_at"))
		}
		if completedAt.Before(startedAt) {
			issues = append(issues, gateIssue("error", "execution_time_order_invalid", refPath, "execution.completed_at must not precede execution.started_at"))
		} else if completedAt.Sub(startedAt) > time.Duration(auth.MaxDurationMinutes)*time.Minute {
			issues = append(issues, gateIssue("error", "execution_duration_exceeded", refPath, "execution duration exceeds the authorized maximum"))
		}
	}
	if strings.TrimSpace(execution.Environment) == "" || strings.TrimSpace(execution.Environment) != strings.TrimSpace(auth.Environment) || strings.TrimSpace(execution.Environment) != strings.TrimSpace(plan.Environment) {
		issues = append(issues, gateIssue("error", "execution_environment_mismatch", refPath, "execution.environment must match the plan and authorization"))
	}
	if execution.ActionCount != len(execution.PerformedActions) || execution.ActionCount < 0 || execution.ActionCount > auth.MaxActions {
		issues = append(issues, gateIssue("error", "execution_action_count_invalid", refPath, "execution.action_count must equal performed_actions length and remain within the authorized maximum"))
	}
	if strings.TrimSpace(outcome.Status) != "blocked_by_constraint" && execution.ActionCount == 0 {
		issues = append(issues, gateIssue("error", "execution_actions_missing", refPath, "this outcome requires at least one performed action"))
	}
	for i, action := range execution.PerformedActions {
		if i >= len(plan.Actions) || !containsRegistryValue(auth.AuthorizedActionIDs, action.ID) {
			issues = append(issues, gateIssue("error", "execution_action_unauthorized", refPath, fmt.Sprintf("performed action %q was not authorized", action.ID)))
			continue
		}
		planned := plan.Actions[i]
		if action.ID != planned.ID || action.Target != planned.Target || action.Operation != planned.Operation || action.Identity != plan.Identity || action.Role != plan.Role {
			issues = append(issues, gateIssue("error", "execution_action_plan_mismatch", refPath, fmt.Sprintf("performed action %q does not exactly match plan sequence %d", action.ID, i+1)))
		}
		if strings.TrimSpace(action.ExitStatus) == "" || strings.TrimSpace(action.ResultSummary) == "" {
			issues = append(issues, gateIssue("error", "execution_action_result_missing", refPath, fmt.Sprintf("performed action %q requires exit_status and factual result_summary", action.ID)))
		}
		actionStart, actionStartErr := time.Parse(time.RFC3339, strings.TrimSpace(action.StartedAt))
		actionEnd, actionEndErr := time.Parse(time.RFC3339, strings.TrimSpace(action.CompletedAt))
		if actionStartErr != nil || actionEndErr != nil || actionEnd.Before(actionStart) {
			issues = append(issues, gateIssue("error", "execution_action_time_invalid", refPath, fmt.Sprintf("performed action %q requires ordered RFC3339 timestamps", action.ID)))
		} else if startedErr == nil && completedErr == nil && (actionStart.Before(startedAt) || actionEnd.After(completedAt)) {
			issues = append(issues, gateIssue("error", "execution_action_time_outside_session", refPath, fmt.Sprintf("performed action %q timestamps must be within the execution window", action.ID)))
		}
		if action.TranscriptPath != plan.TranscriptPath || !containsRegistryValue(outcome.Transcripts, action.TranscriptPath) {
			issues = append(issues, gateIssue("error", "execution_action_transcript_mismatch", refPath, fmt.Sprintf("performed action %q must cite the planned transcript in outcome.transcripts", action.ID)))
		}
		issues = append(issues, validateCitationPaths(workspace, refPath, "execution.transcript_path", []string{action.TranscriptPath})...)
		for _, artifact := range action.ArtifactPaths {
			if !containsRegistryValue(outcome.ArtifactPaths, artifact) {
				issues = append(issues, gateIssue("error", "execution_action_artifact_mismatch", refPath, fmt.Sprintf("performed action %q artifact %q is missing from outcome.artifact_paths", action.ID, artifact)))
			}
		}
	}
	if execution.StopConditionTriggered && strings.TrimSpace(execution.StopConditionReason) == "" {
		issues = append(issues, gateIssue("error", "execution_stop_reason_missing", refPath, "execution.stop_condition_reason is required when a stop condition was triggered"))
	}
	if execution.RollbackStatus != "completed" && execution.RollbackStatus != "not_needed" {
		issues = append(issues, gateIssue("error", "execution_rollback_incomplete", refPath, "execution.rollback_status must be completed or not_needed before Session 11"))
	}
	return issues
}

func validateSession10Plan(workspace, refPath string, plan *Session10Plan, auth *Session10Authorization, handoff *SelectedFindingsHandoff) []ReportGateIssue {
	var issues []ReportGateIssue
	if strings.TrimSpace(plan.FindingID) == "" || plan.FindingID != auth.FindingID {
		issues = append(issues, gateIssue("error", "authorization_plan_finding_mismatch", refPath, "plan.finding_id must match authorization.finding_id"))
	}
	if strings.TrimSpace(plan.Objective) == "" || len(cleanFindings(plan.Session09EvidenceIDs)) == 0 {
		issues = append(issues, gateIssue("error", "authorization_plan_basis_missing", refPath, "plan requires objective and session09_evidence_ids"))
	} else if registry, err := readFindingRegistry(findingRegistryPath(workspace)); err == nil {
		var baseEvidence []string
		for _, finding := range registry.Findings {
			if strings.TrimSpace(finding.ID) == strings.TrimSpace(plan.FindingID) {
				baseEvidence = finding.EvidenceIDs
				break
			}
		}
		for _, evidenceID := range plan.Session09EvidenceIDs {
			if !containsRegistryValue(baseEvidence, evidenceID) {
				issues = append(issues, gateIssue("error", "authorization_plan_evidence_unknown", refPath, fmt.Sprintf("session09_evidence_id %q is not cited by the selected Session 09 finding", evidenceID)))
			}
		}
	}
	if plan.Executor != auth.Executor || !containsRegistryValue(handoff.PermittedExecutors, plan.Executor) {
		issues = append(issues, gateIssue("error", "authorization_plan_executor_mismatch", refPath, "plan.executor must match the authorization and handoff"))
	}
	if strings.TrimSpace(plan.Environment) == "" || plan.Environment != auth.Environment || strings.TrimSpace(plan.Identity) == "" || strings.TrimSpace(plan.Role) == "" {
		issues = append(issues, gateIssue("error", "authorization_plan_context_mismatch", refPath, "plan requires the authorized environment plus exact identity and role"))
	}
	if len(plan.Actions) == 0 || plan.MaxActions != len(plan.Actions) || plan.MaxActions != auth.MaxActions {
		issues = append(issues, gateIssue("error", "authorization_plan_action_count_mismatch", refPath, "plan actions, plan.max_actions, and authorization.max_actions must match exactly"))
	}
	if plan.MaxDurationMinutes != auth.MaxDurationMinutes || plan.MaxRisk != auth.MaxRisk || plan.MaxRisk > handoff.MaxRisk {
		issues = append(issues, gateIssue("error", "authorization_plan_limits_mismatch", refPath, "plan duration/risk limits must exactly match authorization and remain within the handoff"))
	}
	actionIDs := make([]string, 0, len(plan.Actions))
	seen := make(map[string]struct{}, len(plan.Actions))
	for i, action := range plan.Actions {
		path := fmt.Sprintf("%s#actions[%d]", refPath, i)
		if strings.TrimSpace(action.ID) == "" {
			issues = append(issues, gateIssue("error", "authorization_plan_action_id_missing", path, "plan action id is required"))
		} else if _, ok := seen[action.ID]; ok {
			issues = append(issues, gateIssue("error", "authorization_plan_action_duplicate", path, fmt.Sprintf("duplicate action id %q", action.ID)))
		} else {
			seen[action.ID] = struct{}{}
			actionIDs = append(actionIDs, action.ID)
		}
		if !containsRegistryValue(handoff.AllowedActions, action.ActionType) || containsRegistryValue(handoff.ForbiddenActions, action.ActionType) {
			issues = append(issues, gateIssue("error", "authorization_plan_action_type_disallowed", path, fmt.Sprintf("action_type %q is not allowed by the handoff", action.ActionType)))
		}
		if strings.TrimSpace(action.Target) == "" || strings.TrimSpace(action.Operation) == "" || len(cleanFindings(action.ExpectedObservations)) == 0 {
			issues = append(issues, gateIssue("error", "authorization_plan_action_incomplete", path, "each action requires target, exact operation, and expected_observations"))
		}
		if action.Risk < 1 || action.Risk > plan.MaxRisk {
			issues = append(issues, gateIssue("error", "authorization_plan_action_risk_invalid", path, "each action risk must be between 1 and plan.max_risk"))
		}
		if err := validateSession10ActionScope(workspace, action.Target); err != nil {
			issues = append(issues, gateIssue("error", "authorization_plan_action_out_of_scope", path, err.Error()))
		}
	}
	if !equalOrderedValues(actionIDs, auth.AuthorizedActionIDs) {
		issues = append(issues, gateIssue("error", "authorization_plan_action_ids_mismatch", refPath, "authorization.authorized_action_ids must exactly match the ordered plan action IDs"))
	}
	if len(cleanFindings(plan.StopConditions)) == 0 || len(cleanFindings(plan.RollbackSteps)) == 0 || len(cleanFindings(plan.CleanupVerification)) == 0 {
		issues = append(issues, gateIssue("error", "authorization_plan_safety_steps_missing", refPath, "plan requires stop_conditions, rollback_steps, and cleanup_verification"))
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "transcript_path", value: plan.TranscriptPath},
		{field: "artifact_directory", value: plan.ArtifactDirectory},
		{field: "cleanup_evidence_path", value: plan.CleanupEvidencePath},
	} {
		if !safeWorkspaceRelativePath(item.value) {
			issues = append(issues, gateIssue("error", "authorization_plan_path_unsafe", refPath, fmt.Sprintf("plan.%s must be workspace-relative", item.field)))
		}
	}
	if !strings.HasPrefix(cleanCitationPath(plan.TranscriptPath), "10-impact-validation/transcripts/") || cleanCitationPath(plan.ArtifactDirectory) != "10-impact-validation/artifacts" || cleanCitationPath(plan.CleanupEvidencePath) != "10-impact-validation/cleanup.md" {
		issues = append(issues, gateIssue("error", "authorization_plan_path_noncanonical", refPath, "plan evidence paths must use the canonical Session 10 transcript, artifact, and cleanup locations"))
	}
	return issues
}

func validateSession10ActionScope(workspace, target string) error {
	assessment, err := ReadAssessmentPlan(assessmentPlanPath(workspace))
	if err != nil {
		return fmt.Errorf("read assessment plan for action scope: %w", err)
	}
	scope := append([]string(nil), assessment.Target.Scope...)
	if parsedTarget, err := url.Parse(assessment.Target.URL); err == nil && parsedTarget.Hostname() != "" {
		scope = append(scope, parsedTarget.Hostname())
	}
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		return verify.CheckScope(target, scope)
	}
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return verify.CheckCloudScope(parsed.Scheme, parsed.Host, scope)
	}
	for _, allowed := range append(scope, assessment.Target.URL) {
		if strings.TrimSpace(target) == strings.TrimSpace(allowed) {
			return nil
		}
	}
	return fmt.Errorf("action target %q is not within the assessment target or scope", target)
}

func equalOrderedValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.TrimSpace(a[i]) != strings.TrimSpace(b[i]) {
			return false
		}
	}
	return true
}

func validSHA256Reference(value string) bool {
	const prefix = "sha256:"
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && value == strings.ToLower(value)
}

func mergeFinalFindingRegistry(registry *FindingRegistry, outcomes *ImpactValidationOutcomes) (*FindingRegistry, []string, []string) {
	byID := make(map[string]ImpactValidationOutcome, len(outcomes.Outcomes))
	for _, outcome := range outcomes.Outcomes {
		byID[strings.TrimSpace(outcome.ID)] = outcome
	}
	finalRegistry := &FindingRegistry{
		GeneratedFrom: "Session 11 derived from Session 09 registry plus human-authorized Session 10 outcomes; base statuses preserved",
		Findings:      make([]FindingSummary, 0, len(registry.Findings)),
	}
	var updated []string
	var preserved []string
	for _, finding := range registry.Findings {
		merged := finding
		if outcome, ok := byID[strings.TrimSpace(finding.ID)]; ok {
			status := strings.TrimSpace(outcome.Status)
			merged.SelectedForImpactValidation = true
			merged.ImpactValidationOutcomeStatus = status
			merged.ImpactValidationOutcomeReason = outcome.OutcomeReason
			merged.ImpactValidationExecutor = outcome.Executor
			merged.ImpactValidationAuthorization = []string{outcome.AuthorizationPath}
			merged.ImpactValidationCleanupStatus = outcome.CleanupStatus
			merged.ImpactValidationEvidenceIDs = appendUniqueStrings(nil, outcome.EvidenceIDs)
			merged.ImpactValidationTranscripts = appendUniqueStrings(nil, outcome.Transcripts)
			merged.ImpactValidationArtifactPaths = appendUniqueStrings(nil, outcome.ArtifactPaths)
			merged.ImpactValidationCleanupEvidence = appendUniqueStrings(nil, outcome.CleanupEvidence)
			merged.ImpactValidationEvidenceCategories = appendUniqueStrings(nil, finalEvidenceCategories(outcome))
			merged.ImpactValidationNotes = strings.TrimSpace(outcome.Notes)
			updated = append(updated, finding.ID)
		} else {
			merged.SelectedForImpactValidation = false
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
	b.WriteString("This appendix is generated from the derived Session 11 registry. Session 09 evidence, judgments, and base statuses are not modified. Session 10 was explicitly human-authorized and covered only selected findings.\n\n")
	b.WriteString(fmt.Sprintf("- **Source Registry**: %s\n", out.SourceRegistryPath))
	b.WriteString(fmt.Sprintf("- **Outcome File**: %s\n", out.OutcomePath))
	b.WriteString(fmt.Sprintf("- **Final Registry**: %s\n\n", out.FinalRegistryPath))
	b.WriteString("| Finding | Base Status | Evidence Strength | Optional Outcome | Executor | Authorization | Evidence IDs | Transcripts | Artifacts | Cleanup Evidence |\n")
	b.WriteString("|---------|-------------|-------------------|------------------|----------|---------------|--------------|-------------|-----------|------------------|\n")
	for _, finding := range registry.Findings {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdownCell(finding.ID),
			escapeMarkdownCell(finding.Status),
			escapeMarkdownCell(finding.EvidenceStrength),
			escapeMarkdownCell(finding.ImpactValidationOutcomeStatus),
			escapeMarkdownCell(finding.ImpactValidationExecutor),
			escapeMarkdownCell(strings.Join(finding.ImpactValidationAuthorization, ", ")),
			escapeMarkdownCell(strings.Join(finding.ImpactValidationEvidenceIDs, ", ")),
			escapeMarkdownCell(strings.Join(finding.ImpactValidationTranscripts, ", ")),
			escapeMarkdownCell(strings.Join(finding.ImpactValidationArtifactPaths, ", ")),
			escapeMarkdownCell(strings.Join(finding.ImpactValidationCleanupEvidence, ", ")),
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
	if err := os.WriteFile(out.PromptPath, []byte(fmt.Sprintf("ensphere status\n\nResolve Session 11 gate issues before writing the optional validation-aware report. Outcome file: %s\n", out.OutcomePath)), 0644); err != nil {
		return fmt.Errorf("write final gate prompt: %w", err)
	}
	return nil
}

func validFinalOutcomeStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "objective_achieved",
		"objective_not_achieved",
		"blocked_by_control",
		"blocked_by_constraint",
		"inconclusive":
		return true
	default:
		return false
	}
}

func impactValidationOutcomeHasCitation(outcome ImpactValidationOutcome) bool {
	return hasNonEmptyString(outcome.EvidenceIDs) ||
		hasNonEmptyString(outcome.Transcripts) ||
		hasNonEmptyString(outcome.ArtifactPaths) ||
		hasNonEmptyString(outcome.CleanupEvidence) ||
		strings.TrimSpace(outcome.Notes) != ""
}

func impactValidationOutcomeHasProofCitation(outcome ImpactValidationOutcome) bool {
	return hasNonEmptyString(outcome.EvidenceIDs) ||
		hasNonEmptyString(outcome.Transcripts) ||
		hasNonEmptyString(outcome.ArtifactPaths)
}

func finalEvidenceCategories(outcome ImpactValidationOutcome) []string {
	if len(outcome.EvidenceCategories) > 0 {
		return outcome.EvidenceCategories
	}
	return []string{"impact_validation_attempt", "impact_validation_result"}
}

func containsRegistryValue(values []string, expected string) bool {
	expected = strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

func validCleanupStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case "verified", "not_needed":
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

func impactValidationOutcomesPath(workspace string) string {
	return filepath.Join(workspace, "10-impact-validation", "impact-validation-outcomes.yaml")
}

func finalFindingRegistryPath(workspace string) string {
	return filepath.Join(workspace, "11-final-report", "finding-registry.yaml")
}
