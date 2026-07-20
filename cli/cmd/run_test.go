package cmd

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srank/ensphere/internal/evidence"
)

func TestCLIRunInitStatusAndNext(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	initResult := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://staging.example.com",
		"--source", "yes",
		"--target-type", "api_backend",
		"--in-scope", "staging.example.com",
	)
	if initResult.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", initResult.code, initResult.stderr)
	}
	var initOut struct {
		NextSession *struct {
			ID string `json:"id"`
		} `json:"next_session"`
	}
	decodeJSON(t, initResult.stdout, &initOut)
	if initOut.NextSession == nil || initOut.NextSession.ID != "01" {
		t.Fatalf("unexpected run init output: %+v", initOut)
	}
	for _, name := range []string{"config.md", "progress.md", "next-action.md", "agent-prompt.md"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}

	statusResult := runCLISplit(t, "run", "--workspace", workspace, "status")
	if statusResult.code != 0 {
		t.Fatalf("run status exit %d stderr=%s", statusResult.code, statusResult.stderr)
	}
	if !strings.Contains(statusResult.stdout, `"assessment_plan_exists": false`) {
		t.Fatalf("status missing assessment plan flag:\n%s", statusResult.stdout)
	}

	nextResult := runCLISplit(t, "run", "--workspace", workspace, "next")
	if nextResult.code != 0 {
		t.Fatalf("run next exit %d stderr=%s", nextResult.code, nextResult.stderr)
	}
	if !strings.Contains(nextResult.stdout, `"action_path"`) || !strings.Contains(nextResult.stdout, `"prompt_path"`) {
		t.Fatalf("next output missing handoff paths:\n%s", nextResult.stdout)
	}
}

func TestCLIRunPlanWritesAssessmentPlan(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	initResult := runCLISplit(t, "run", "--workspace", workspace, "init",
		"--target", "https://api.example.com",
		"--source", "no",
		"--target-type", "api_backend",
		"--cloud", "aws",
		"--in-scope", "api.example.com, aws://123456789012",
	)
	if initResult.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", initResult.code, initResult.stderr)
	}
	planResult := runCLISplit(t, "run", "--workspace", workspace, "plan")
	if planResult.code != 0 {
		t.Fatalf("run plan exit %d stderr=%s", planResult.code, planResult.stderr)
	}
	if !strings.Contains(planResult.stdout, `"written": true`) ||
		!strings.Contains(planResult.stdout, `"target_type":`) && !strings.Contains(planResult.stdout, `"type": "api_backend"`) {
		t.Fatalf("run plan output missing generated plan:\n%s", planResult.stdout)
	}
	for _, path := range []string{
		filepath.Join(workspace, "assessment-plan.yaml"),
		filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected assessment plan artifact %s: %v", path, err)
		}
	}

	statusResult := runCLISplit(t, "run", "--workspace", workspace, "status")
	if statusResult.code != 0 {
		t.Fatalf("run status exit %d stderr=%s", statusResult.code, statusResult.stderr)
	}
	if !strings.Contains(statusResult.stdout, `"assessment_plan_exists": true`) ||
		!strings.Contains(statusResult.stdout, `"target_type": "api_backend"`) {
		t.Fatalf("status missing plan summary:\n%s", statusResult.stdout)
	}
}

func TestCLIRunReportWritesGate(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	if result := runCLISplit(t, "run", "--workspace", workspace, "plan"); result.code != 0 {
		t.Fatalf("run plan exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "report")
	if result.code != 0 {
		t.Fatalf("run report exit %d stderr=%s", result.code, result.stderr)
	}
	if !strings.Contains(result.stdout, `"ready": false`) || !strings.Contains(result.stdout, `"session_not_terminal"`) {
		t.Fatalf("report gate output missing blocking issue:\n%s", result.stdout)
	}
	for _, path := range []string{
		filepath.Join(workspace, "09-report", "report-gate.yaml"),
		filepath.Join(workspace, "09-report", "report-gate.md"),
		filepath.Join(workspace, "next-action.md"),
		filepath.Join(workspace, "agent-prompt.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected report gate artifact %s: %v", path, err)
		}
	}
}

func TestCLIRunImpactValidationRequiresFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--impact-validation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	missing := runCLISplit(t, "run", "--workspace", workspace, "validate-impact")
	if missing.code != 2 {
		t.Fatalf("expected usage exit 2, got %d stdout=%s stderr=%s", missing.code, missing.stdout, missing.stderr)
	}

	writeCLIFindingRegistry(t, workspace, "VULN-001", "VULN-004")
	writeCLISession09DoneProgress(t, workspace)
	selected := runCLISplit(t, "run", "--workspace", workspace, "validate-impact", "--finding", "VULN-001", "--finding", "VULN-004")
	if selected.code != 0 {
		t.Fatalf("run validate-impact exit %d stderr=%s", selected.code, selected.stderr)
	}
	if !strings.Contains(selected.stdout, `"VULN-001"`) || !strings.Contains(selected.stdout, `"selection_path"`) {
		t.Fatalf("unexpected run validate-impact output:\n%s", selected.stdout)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"))
	if err != nil {
		t.Fatalf("read selected findings: %v", err)
	}
	if !strings.Contains(string(raw), `"VULN-004"`) {
		t.Fatalf("selected findings missing VULN-004:\n%s", raw)
	}
	if !strings.Contains(string(raw), "human_authorization_required: true") ||
		!strings.Contains(string(raw), "authorization_record_required: true") ||
		!strings.Contains(string(raw), "permitted_executors:") ||
		!strings.Contains(string(raw), "max_risk: 3") {
		t.Fatalf("selected findings missing safety policy:\n%s", raw)
	}
}

func TestCLIRunImpactValidationRequiresEnabledGate(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "validate-impact", "--finding", "VULN-001")
	if result.code != 2 {
		t.Fatalf("expected gate exit 2, got %d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "impact validation is not enabled") {
		t.Fatalf("unexpected stderr:\n%s", result.stderr)
	}
}

func TestCLIRunImpactValidationRequiresFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--impact-validation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "validate-impact", "--finding", "VULN-001")
	if result.code != 2 {
		t.Fatalf("expected registry gate exit 2, got %d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "finding registry is required") {
		t.Fatalf("unexpected stderr:\n%s", result.stderr)
	}
}

func TestCLIRunFinalWritesDerivedRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--impact-validation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	writeCLISession09DoneProgress(t, workspace)
	writeCLIFinalProgress(t, workspace)
	writeCLIFindingRegistry(t, workspace, "VULN-001")
	writeCLISelectedFindings(t, workspace, "VULN-001")
	preflight := runCLISplit(t, "run", "--workspace", workspace, "impact-ready",
		"--finding", "VULN-001",
		"--authorization", "10-impact-validation/authorizations/VULN-001-human.yaml",
	)
	if preflight.code != 0 || !strings.Contains(preflight.stdout, `"ready": true`) {
		t.Fatalf("unexpected impact-ready output: code=%d stdout=%s stderr=%s", preflight.code, preflight.stdout, preflight.stderr)
	}
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Read-only impact proof achieved.
    executor: human
    authorization_path: 10-impact-validation/authorizations/VULN-001-human.yaml
    readiness_path: 10-impact-validation/readiness/VULN-001-human.yaml
    execution:
      started_at: 2099-07-18T10:01:00Z
      completed_at: 2099-07-18T10:02:00Z
      environment: local-test
      performed_actions:
        - id: action-1
          target: https://example.com/canary
          operation: GET /canary
          identity: test-identity
          role: test-role
          started_at: 2099-07-18T10:01:10Z
          completed_at: 2099-07-18T10:01:50Z
          exit_status: completed
          result_summary: Controlled test observation recorded.
          transcript_path: 10-impact-validation/transcripts/VULN-001.md
      action_count: 1
      stop_condition_triggered: false
      rollback_status: not_needed
    evidence_ids:
      - EVID-010
    transcripts:
      - 10-impact-validation/transcripts/VULN-001.md
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
    cleanup_status: verified
    evidence_categories:
      - human_authorization
      - human_execution
      - impact_validation_attempt
      - impact_validation_result
`
	if err := os.WriteFile(filepath.Join(workspace, "10-impact-validation", "impact-validation-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "final")
	if result.code != 0 {
		t.Fatalf("run final exit %d stderr=%s", result.code, result.stderr)
	}
	if !strings.Contains(result.stdout, `"ready": true`) || !strings.Contains(result.stdout, `"updated_findings"`) {
		t.Fatalf("unexpected run final output:\n%s", result.stdout)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "11-final-report", "finding-registry.yaml"))
	if err != nil {
		t.Fatalf("read final registry: %v", err)
	}
	if !strings.Contains(string(raw), "status: confirmed") || !strings.Contains(string(raw), "impact_validation_outcome_status: objective_achieved") {
		t.Fatalf("final registry missing merged state:\n%s", raw)
	}
}

func writeCLIFindingRegistry(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	dir := filepath.Join(workspace, "09-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir finding registry dir: %v", err)
	}
	var b strings.Builder
	b.WriteString("generated_from: Session 09\n")
	b.WriteString("findings:\n")
	for _, id := range ids {
		b.WriteString("  - id: " + id + "\n")
		b.WriteString("    title: Registry finding " + id + "\n")
		b.WriteString("    category: injection\n")
		b.WriteString("    status: confirmed\n")
		b.WriteString("    confidence: high\n")
		b.WriteString("    evidence_strength: direct\n")
		b.WriteString("    severity: high\n")
		b.WriteString("    priority: P1\n")
		b.WriteString("    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N\n")
		b.WriteString("    affected_assets: [test.example.invalid]\n")
		b.WriteString("    affected_locations: [GET /test]\n")
		b.WriteString("    observed_facts: [Controlled observation]\n")
		b.WriteString("    root_cause: Missing control\n")
		b.WriteString("    security_impact: Controlled impact\n")
		b.WriteString("    business_impact: Test business impact\n")
		b.WriteString("    remediation: Add the control\n")
		b.WriteString("    validation_criteria: [Unauthorized control is denied]\n")
		b.WriteString("    coverage_label: full\n")
		b.WriteString("    evidence_categories:\n")
		b.WriteString("      - ensphere_measurement\n")
		b.WriteString("      - agent_judgment\n")
		b.WriteString("    evidence_ids:\n")
		b.WriteString("      - EVID-001\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "finding-registry.yaml"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write finding registry: %v", err)
	}
	report := `# Security Assessment Report
## Authorization
Authorized.
## Executive Summary
Summary.
## Scope and Methodology
Scope.
## Coverage
Coverage.
## Finding Summary
Summary.
## Detailed Findings
Details.
## Tested Defenses
Controls.
## Unresolved and Not-Tested Areas
Limitations.
## Attack Paths and Risk Scenarios
None.
## Remediation Roadmap
Roadmap.
## Contextual Compliance Mapping
Context.
`
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(report), 0644); err != nil {
		t.Fatalf("write Session 09 report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-appendix.md"), []byte("# Evidence Appendix\n\nProvenance.\n"), 0644); err != nil {
		t.Fatalf("write Session 09 appendix: %v", err)
	}
}

func writeCLISelectedFindings(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	dir := filepath.Join(workspace, "10-impact-validation")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir selected findings dir: %v", err)
	}
	var b strings.Builder
	b.WriteString("enabled: true\n")
	b.WriteString("finding_registry_path: \"" + filepath.Join(workspace, "09-report", "finding-registry.yaml") + "\"\n")
	b.WriteString("selected_findings:\n")
	for _, id := range ids {
		b.WriteString("  - \"" + id + "\"\n")
	}
	b.WriteString("cleanup_required: true\n")
	b.WriteString("cleanup_evidence_required: true\n")
	b.WriteString("human_authorization_required: true\n")
	b.WriteString("authorization_record_required: true\n")
	b.WriteString("environment_acknowledgement_required: true\n")
	b.WriteString("permitted_executors: [human, agent]\n")
	b.WriteString("validation_plan_required: true\n")
	b.WriteString("max_risk: 3\n")
	b.WriteString("allowed_actions: [non_sensitive_canary_read, benign_browser_execution]\n")
	b.WriteString("forbidden_actions: [destructive_action, persistence, uncontrolled_data_access]\n")
	b.WriteString("evidence_paths:\n")
	b.WriteString("  evidence_jsonl: 10-impact-validation/evidence.jsonl\n")
	b.WriteString("  transcript_dir: 10-impact-validation/transcripts\n")
	b.WriteString("  artifact_dir: 10-impact-validation/artifacts\n")
	b.WriteString("  authorization_dir: 10-impact-validation/authorizations\n")
	b.WriteString("  readiness_dir: 10-impact-validation/readiness\n")
	b.WriteString("  cleanup_report: 10-impact-validation/cleanup.md\n")
	if err := os.WriteFile(filepath.Join(dir, "selected-findings.yaml"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write selected findings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte("# Human-Authorized Session 10 Report\n\nAuthorization and outcome.\n"), 0644); err != nil {
		t.Fatalf("write Session 10 report: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "transcripts"), 0755); err != nil {
		t.Fatalf("mkdir transcripts: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "plans"), 0755); err != nil {
		t.Fatalf("mkdir plans: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "authorizations"), 0755); err != nil {
		t.Fatalf("mkdir authorizations: %v", err)
	}
	for _, id := range ids {
		plan := []byte(fmt.Sprintf(`finding_id: %s
objective: Observe the bounded canary result.
session09_evidence_ids: [EVID-001]
executor: human
environment: local-test
identity: test-identity
role: test-role
actions:
  - id: action-1
    action_type: non_sensitive_canary_read
    target: https://example.com/canary
    operation: GET /canary
    risk: 2
    expected_observations: [status code, response hash]
max_actions: 1
max_duration_minutes: 5
max_risk: 2
stop_conditions: [unexpected state change]
rollback_steps: [no state change expected]
cleanup_verification: [verify canary state unchanged]
transcript_path: 10-impact-validation/transcripts/%s.md
artifact_directory: 10-impact-validation/artifacts
cleanup_evidence_path: 10-impact-validation/cleanup.md#%s
`, id, id, id))
		planPath := "10-impact-validation/plans/" + id + "-human.yaml"
		if err := os.WriteFile(filepath.Join(workspace, filepath.FromSlash(planPath)), plan, 0644); err != nil {
			t.Fatalf("write impact-validation plan: %v", err)
		}
		planHash := sha256.Sum256(plan)
		authorization := fmt.Sprintf(`finding_id: %s
plan_path: %s
plan_revision: rev-1
plan_sha256: sha256:%x
authorized_by: test-human
authorized_at: 2000-01-01T00:00:00Z
executor: human
environment: local-test
environment_acknowledged: true
authorized_action_ids: [action-1]
max_actions: 1
max_duration_minutes: 5
max_risk: 2
`, id, planPath, planHash)
		if err := os.WriteFile(filepath.Join(dir, "authorizations", id+"-human.yaml"), []byte(authorization), 0644); err != nil {
			t.Fatalf("write authorization record: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "transcripts", id+".md"), []byte("# Execution Transcript\n"), 0644); err != nil {
			t.Fatalf("write transcript: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "cleanup.md"), []byte("# Cleanup\n\n## VULN-001\n\nNo persistent change.\n"), 0644); err != nil {
		t.Fatalf("write cleanup report: %v", err)
	}
	writer, err := evidence.NewWriter(filepath.Join(dir, "evidence.jsonl"))
	if err != nil {
		t.Fatalf("create Session 10 evidence writer: %v", err)
	}
	entry := evidence.Entry{
		ID:            "EVID-010",
		SessionNumber: 10,
		FindingRef:    ids[0],
		Timestamp:     "2099-07-18T10:01:30Z",
		ProbeType:     "impact_validation",
		Technique:     "authorized_action",
		URL:           "https://example.com/canary",
		StatusCode:    200,
		Duration:      "40s",
		Result:        evidence.ResultProbe,
	}
	if err := writer.Write(entry); err != nil {
		_ = writer.Close()
		t.Fatalf("write Session 10 evidence: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close Session 10 evidence: %v", err)
	}
}

func writeCLIFinalProgress(t *testing.T, workspace string) {
	t.Helper()
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | SKIPPED | |
| 04 | Authorization | SKIPPED | |
| 05 | Cross-Site Scripting | SKIPPED | |
| 06 | Server-Side Request Forgery | SKIPPED | |
| 07 | Cloud Security | SKIPPED | |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | DONE | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
}

func writeCLISession09DoneProgress(t *testing.T, workspace string) {
	t.Helper()
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | SKIPPED | |
| 04 | Authorization | SKIPPED | |
| 05 | Cross-Site Scripting | SKIPPED | |
| 06 | Server-Side Request Forgery | SKIPPED | |
| 07 | Cloud Security | SKIPPED | |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | PENDING | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	if result := runCLISplit(t, "run", "--workspace", workspace, "plan"); result.code != 0 {
		t.Fatalf("write assessment plan fixture: %s", result.stderr)
	}
	for _, dir := range []string{"01-recon", "01.5-session-plan", "02-injection", "03-auth", "04-authz", "05-xss", "06-ssrf", "07-cloud", "08-api"} {
		if err := os.WriteFile(filepath.Join(workspace, dir, "report.md"), []byte("# Session report\n\nFixture coverage and limitations.\n"), 0644); err != nil {
			t.Fatalf("write report fixture for %s: %v", dir, err)
		}
	}
}
