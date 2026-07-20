package runner

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srank/ensphere/internal/evidence"
)

func TestInitWorkspaceWritesCoreArtifacts(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	status, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://staging.example.com",
		SourceCode: "yes",
		TargetType: "api_backend",
		Cloud:      "none",
		InScope:    "staging.example.com",
	})
	if err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if status.NextSession == nil || status.NextSession.ID != "01" {
		t.Fatalf("expected next session 01, got %+v", status.NextSession)
	}
	for _, path := range []string{
		filepath.Join(workspace, "config.md"),
		filepath.Join(workspace, "progress.md"),
		filepath.Join(workspace, "next-action.md"),
		filepath.Join(workspace, "agent-prompt.md"),
		filepath.Join(workspace, "01.5-session-plan"),
		filepath.Join(workspace, "10-impact-validation"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	config, err := os.ReadFile(filepath.Join(workspace, "config.md"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(config), "Target type: api_backend") {
		t.Fatalf("config missing target type:\n%s", config)
	}
	progress, err := os.ReadFile(filepath.Join(workspace, "progress.md"))
	if err != nil {
		t.Fatalf("read progress: %v", err)
	}
	if !strings.Contains(string(progress), filepath.Join(workspace, "assessment-plan.yaml")) {
		t.Fatalf("progress uses wrong assessment plan path:\n%s", progress)
	}
	prompt, err := os.ReadFile(filepath.Join(workspace, "agent-prompt.md"))
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	if !strings.Contains(string(prompt), filepath.Join(workspace, "config.md")) ||
		!strings.Contains(string(prompt), filepath.Join(workspace, "progress.md")) {
		t.Fatalf("prompt uses wrong workspace paths:\n%s", prompt)
	}
}

func TestInitWorkspaceRefusesExistingWorkspace(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	_, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("expected existing workspace error, got %v", err)
	}
}

func TestWriteNextActionSkipsOptionalImpactValidationWhenDisabled(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | DONE | |
| 04 | Authorization | DONE | |
| 05 | Cross-Site Scripting | DONE | |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud Security | DONE | |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | PENDING | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected no next session when impact validation disabled, got %+v", action.Session)
	}
}

func TestWriteNextActionRequiresSelectedFindingsForSession10(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | DONE | |
| 04 | Authorization | DONE | |
| 05 | Cross-Site Scripting | DONE | |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud Security | DONE | |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | PENDING | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action without selected findings: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected no Session 10 until findings are selected, got %+v", action.Session)
	}

	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeReportGatePrerequisites(t, workspace)
	if _, err := PrepareImpactValidation(workspace, []string{"VULN-001"}); err != nil {
		t.Fatalf("prepare impact validation: %v", err)
	}
	status, err := WorkspaceStatus(workspace)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.NextSession == nil || status.NextSession.ID != "10" {
		t.Fatalf("expected Session 10 after selected findings, got %+v", status.NextSession)
	}
}

func TestWriteNextActionBlocksSession10WhenAssessmentPlanInvalid(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte("draft: false\n"), 0644); err != nil {
		t.Fatalf("write invalid plan: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected invalid assessment plan to block Session 10, got %+v", action.Session)
	}
}

func TestWriteNextActionNeverStartsSession11Automatically(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	if _, err := PrepareImpactValidation(workspace, []string{"VULN-001"}); err != nil {
		t.Fatalf("prepare impact validation: %v", err)
	}
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | DONE | |
| 04 | Authorization | DONE | |
| 05 | Cross-Site Scripting | DONE | |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud Security | DONE | |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | SKIPPED | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write skipped progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action after skipped Session 10: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected no Session 11 when Session 10 is skipped, got %+v", action.Session)
	}

	progress = strings.Replace(progress, "| 10 | Optional Human-Authorized Impact Validation | SKIPPED | |", "| 10 | Optional Human-Authorized Impact Validation | DONE | |", 1)
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write done progress: %v", err)
	}
	action, err = WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action after done Session 10: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected Session 11 to require explicit run final invocation, got %+v", action.Session)
	}
}

func TestRunPlanWritesDraftAndStatusSummary(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{
		Workspace:  workspace,
		TargetURL:  "https://api.example.com",
		SourceCode: "no",
		TargetType: "api_backend",
		Cloud:      "aws",
		InScope:    "api.example.com, aws://123456789012",
	}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}

	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Written || !out.Valid {
		t.Fatalf("expected written valid plan, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
	if out.Plan.Target.Type != "api_backend" || out.Plan.Target.SourceMode != "black_box" {
		t.Fatalf("unexpected target summary: %+v", out.Plan.Target)
	}
	if out.Plan.Sessions["05-xss"].Decision != decisionSkip {
		t.Fatalf("expected API backend XSS skip, got %+v", out.Plan.Sessions["05-xss"])
	}
	if out.Plan.Sessions["07-cloud"].Decision != decisionRun {
		t.Fatalf("expected cloud run, got %+v", out.Plan.Sessions["07-cloud"])
	}
	for _, path := range []string{
		filepath.Join(workspace, "assessment-plan.yaml"),
		filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected plan artifact %s: %v", path, err)
		}
	}

	status, err := WorkspaceStatus(workspace)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.AssessmentPlan == nil || !status.AssessmentPlan.Exists || !status.AssessmentPlan.Valid {
		t.Fatalf("expected valid plan summary, got %+v", status.AssessmentPlan)
	}
	if status.AssessmentPlan.SessionDecisions["07-cloud"] != decisionRun {
		t.Fatalf("status missing cloud decision: %+v", status.AssessmentPlan.SessionDecisions)
	}
}

func TestRunPlanValidatesExistingPlanWithoutOverwrite(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte("draft: false\n"), 0644); err != nil {
		t.Fatalf("write invalid plan: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate existing plan: %v", err)
	}
	if out.Written || out.Valid {
		t.Fatalf("expected invalid existing plan without overwrite, got written=%v valid=%v", out.Written, out.Valid)
	}
	if len(out.Validation) == 0 {
		t.Fatal("expected validation errors")
	}

	out, err = RunPlan(workspace, true)
	if err != nil {
		t.Fatalf("force plan: %v", err)
	}
	if !out.Written || !out.Valid {
		t.Fatalf("expected force-generated valid plan, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
}

func TestRunPlanMirrorsExistingPlanWithoutRewritingRoot(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, true); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	rootPath := filepath.Join(workspace, "assessment-plan.yaml")
	mirrorPath := filepath.Join(workspace, "01.5-session-plan", "assessment-plan.yaml")
	rootRaw, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root plan: %v", err)
	}
	rootRaw = append([]byte("# analyst comment that should survive\n"), rootRaw...)
	if err := os.WriteFile(rootPath, rootRaw, 0644); err != nil {
		t.Fatalf("write commented root plan: %v", err)
	}
	if err := os.Remove(mirrorPath); err != nil {
		t.Fatalf("remove mirror: %v", err)
	}

	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("validate existing plan: %v", err)
	}
	if out.Written || !out.Valid {
		t.Fatalf("expected existing valid plan without rewrite, got written=%v valid=%v validation=%v", out.Written, out.Valid, out.Validation)
	}
	rootAfter, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read root after plan: %v", err)
	}
	mirrorRaw, err := os.ReadFile(mirrorPath)
	if err != nil {
		t.Fatalf("read mirror after plan: %v", err)
	}
	if string(rootAfter) != string(rootRaw) {
		t.Fatalf("root plan was rewritten:\n%s", rootAfter)
	}
	if string(mirrorRaw) != string(rootRaw) {
		t.Fatalf("mirror was not synced from root:\n%s", mirrorRaw)
	}
}

func TestRunPlanUsesReconTargetProfileForClientOnlyTarget(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", TargetType: "auto"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: mobile_client_offline
  source_mode: source_only
  coverage_label: client_only
  classification_confidence: high
  rationale:
    - "Session 01 found only Android client code and no configured backend URL."
  evidence_refs:
    - "01-recon/report.md#target-classification"
signals:
  client_only: true
  api_surface: false
  server_side_surface: false
  authentication: false
  outbound_fetch_surface: false
client_exposure_review:
  - "Review hardcoded endpoints, embedded keys, local storage, and WebView bridges."
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid || out.Plan.Target.Type != "mobile_client_offline" || out.Plan.Target.ClassificationConfidence != "high" {
		t.Fatalf("expected recon-classified client-only target, valid=%v validation=%v target=%+v", out.Valid, out.Validation, out.Plan.Target)
	}
	if out.Plan.Target.ClassificationSource != "01-recon/target-profile.yaml" || len(out.Plan.Target.ClientExposureReview) == 0 {
		t.Fatalf("target profile metadata missing: %+v", out.Plan.Target)
	}
	if out.Plan.Sessions["02-injection"].Decision != decisionNotApplicable || out.Plan.Sessions["08-api"].Decision != decisionNotApplicable {
		t.Fatalf("client-only target should stop normal web/API workflow, sessions=%+v", out.Plan.Sessions)
	}
}

func TestRunPlanRecordsReconBackendInventory(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://mobile.example.com", TargetType: "auto", Username: "user"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: mobile_client_remote_backend
  source_mode: white_box
  classification_confidence: high
  rationale:
    - "Session 01 extracted API base URLs from mobile source and traffic capture."
  evidence_refs:
    - "01-recon/report.md#backend-inventory"
backend_inventory:
  - name: primary-api
    base_url: https://api.example.com
    kind: rest
    source: mobile source constants
    evidence_refs:
      - "01-recon/report.md#backend-inventory"
signals:
  api_surface: true
  server_side_surface: true
  authentication: true
  authorization_boundaries: true
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if !out.Valid {
		t.Fatalf("expected valid plan, validation=%v", out.Validation)
	}
	if len(out.Plan.Target.BackendInventory) != 1 || out.Plan.Target.BackendInventory[0].BaseURL != "https://api.example.com" {
		t.Fatalf("backend inventory missing from plan: %+v", out.Plan.Target.BackendInventory)
	}
	if out.Plan.Sessions["08-api"].Decision != decisionLimited || out.Plan.Sessions["04-authz"].Decision != decisionLimited {
		t.Fatalf("unexpected mobile remote backend decisions: api=%+v authz=%+v", out.Plan.Sessions["08-api"], out.Plan.Sessions["04-authz"])
	}
}

func TestRunPlanSurfacesInvalidReconTargetProfile(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", TargetType: "auto"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	profile := `target:
  type: not_a_target
  source_mode: white_box
  classification_confidence: impossible
`
	if err := os.WriteFile(filepath.Join(workspace, "01-recon", "target-profile.yaml"), []byte(profile), 0644); err != nil {
		t.Fatalf("write target profile: %v", err)
	}
	out, err := RunPlan(workspace, false)
	if err != nil {
		t.Fatalf("run plan: %v", err)
	}
	if out.Valid || len(out.Validation) == 0 {
		t.Fatalf("expected invalid target profile validation, got valid=%v validation=%v", out.Valid, out.Validation)
	}
}

func TestWriteNextActionIncludesPlanDecision(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://api.example.com", TargetType: "api_backend"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | PENDING | |
| 03 | Authentication | PENDING | |
| 04 | Authorization | PENDING | |
| 05 | Cross-Site Scripting | PENDING | |
| 06 | Server-Side Request Forgery | PENDING | |
| 07 | Cloud Security | PENDING | |
| 08 | API Security | PENDING | |
| 09 | Evidence-Based Assessment Report | PENDING | |
| 10 | Optional Human-Authorized Impact Validation | PENDING | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session == nil || action.Session.ID != "02" {
		t.Fatalf("expected next session 02, got %+v", action.Session)
	}
	if action.PlanDecision == nil || action.PlanDecision.SessionKey != "02-injection" {
		t.Fatalf("expected plan decision for 02, got %+v", action.PlanDecision)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "next-action.md"))
	if err != nil {
		t.Fatalf("read next-action: %v", err)
	}
	if !strings.Contains(string(raw), "Assessment Plan Decision") {
		t.Fatalf("next-action missing plan block:\n%s", raw)
	}
}

func TestRunReportBlocksUntilSessionsAreReady(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready {
		t.Fatal("expected report gate to block on pending sessions")
	}
	if !hasIssue(gate.Issues, "session_not_terminal") {
		t.Fatalf("expected session_not_terminal issue, got %+v", gate.Issues)
	}
	for _, path := range []string{gate.GatePath, gate.GateMarkdownPath, gate.NextActionPath, gate.PromptPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected gate artifact %s: %v", path, err)
		}
	}
}

func TestRunReportPassesWhenSessionsHaveReports(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)

	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if !gate.Ready {
		t.Fatalf("expected report gate ready, got issues %+v", gate.Issues)
	}
	if gate.FindingRegistryState != "missing" {
		t.Fatalf("expected missing optional finding registry, got %s", gate.FindingRegistryState)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "next-action.md"))
	if err != nil {
		t.Fatalf("read next action: %v", err)
	}
	if !strings.Contains(string(raw), "Session") || !strings.Contains(string(raw), "09") {
		t.Fatalf("expected Session 09 handoff, got:\n%s", raw)
	}
}

func TestRunReportRejectsUncitedFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    title: Missing citation
    category: injection
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
    affected_assets: [test.example.invalid]
    affected_locations: [GET /test]
    observed_facts: [Controlled observation]
    root_cause: Missing control
    security_impact: Controlled impact
    business_impact: Test business impact
    remediation: Add the control
    validation_criteria: [Unauthorized control is denied]
    evidence_categories:
      - ensphere_measurement
      - agent_judgment
    coverage_label: full
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready {
		t.Fatal("expected report gate to reject uncited finding")
	}
	if gate.FindingRegistryState != "invalid" || !hasIssue(gate.Issues, "finding_uncited") {
		t.Fatalf("expected finding_uncited issue, state=%s issues=%+v", gate.FindingRegistryState, gate.Issues)
	}

	registry = `generated_from: Session 09
findings:
  - id: VULN-001
    title: Cited finding
    category: injection
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
    affected_assets: [test.example.invalid]
    affected_locations: [GET /test]
    observed_facts: [Controlled observation]
    root_cause: Missing control
    security_impact: Controlled impact
    business_impact: Test business impact
    remediation: Add the control
    validation_criteria: [Unauthorized control is denied]
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
      - agent_judgment
    evidence_ids:
      - EVID-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write cited registry: %v", err)
	}
	gate, err = RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate with cited registry: %v", err)
	}
	if !gate.Ready || gate.FindingRegistryState != "valid" {
		t.Fatalf("expected cited registry ready, state=%s issues=%+v", gate.FindingRegistryState, gate.Issues)
	}
}

func TestRunReportRejectsInvalidFindingRegistryEnums(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    title: Bad enum values
    category: injection
    status: impossible
    confidence: certain
    evidence_strength: direct
    severity: severe
    priority: P1
    coverage_label: broad
    evidence_categories:
      - scanner_says_so
    evidence_ids:
      - EVID-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	for _, code := range []string{
		"finding_status_invalid",
		"finding_confidence_invalid",
		"finding_severity_invalid",
		"finding_evidence_category_invalid",
		"finding_coverage_invalid",
	} {
		if !hasIssue(gate.Issues, code) {
			t.Fatalf("expected %s in issues %+v", code, gate.Issues)
		}
	}
}

func TestRunReportRejectsConfirmedFindingWithIndicativeEvidence(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	path := findingRegistryPath(workspace)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read registry: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), "evidence_strength: direct", "evidence_strength: indicative", 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_confirmed_evidence_weak") {
		t.Fatalf("expected weak confirmed evidence rejection, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRequiresStructuredFinalArtifacts(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "report.md"), []byte("# Security Assessment Report\n\n## Executive Summary\nIncomplete.\n"), 0644); err != nil {
		t.Fatalf("write incomplete report: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "final_report_section_missing") {
		t.Fatalf("expected report structure rejection, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRejectsEmptyCitationPlaceholders(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    title: Blank citation placeholder
    category: injection
    status: not_supported
    confidence: medium
    evidence_strength: direct
    severity: high
    priority: P3
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
    evidence_ids:
      - " "
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_uncited") {
		t.Fatalf("expected blank citation to be rejected, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestRunReportRejectsUnsafeFindingRegistryPaths(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `generated_from: Session 09
findings:
  - id: VULN-001
    title: Unsafe citation paths
    category: injection
    status: not_supported
    confidence: medium
    evidence_strength: direct
    severity: high
    priority: P3
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
    transcripts:
      - /tmp/outside.md
    artifact_paths:
      - ../outside.txt
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
`
	if err := os.WriteFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"), []byte(registry), 0644); err != nil {
		t.Fatalf("write registry: %v", err)
	}
	gate, err := RunReport(workspace)
	if err != nil {
		t.Fatalf("run report gate: %v", err)
	}
	if gate.Ready || !hasIssue(gate.Issues, "finding_path_unsafe") {
		t.Fatalf("expected unsafe path issue, ready=%v issues=%+v", gate.Ready, gate.Issues)
	}
}

func TestPrepareImpactValidationWritesSelectionAndPrompt(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-004")
	selection, err := PrepareImpactValidation(workspace, []string{"VULN-001", "VULN-004"})
	if err != nil {
		t.Fatalf("prepare impact validation: %v", err)
	}
	raw, err := os.ReadFile(selection.SelectionPath)
	if err != nil {
		t.Fatalf("read selected findings: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"VULN-001"`) ||
		!strings.Contains(text, "finding_registry_path:") ||
		!strings.Contains(text, "max_risk: 3") ||
		!strings.Contains(text, "human_authorization_required: true") ||
		!strings.Contains(text, "authorization_record_required: true") ||
		!strings.Contains(text, "permitted_executors:") ||
		!strings.Contains(text, `evidence_jsonl: "10-impact-validation/evidence.jsonl"`) ||
		!strings.Contains(text, `authorization_dir: "10-impact-validation/authorizations"`) ||
		!strings.Contains(text, "cleanup_evidence_required: true") {
		t.Fatalf("unexpected selected findings:\n%s", text)
	}
	if selection.MaxRisk != 3 || len(selection.AllowedActions) == 0 || len(selection.ForbiddenActions) == 0 {
		t.Fatalf("selection response missing impact-validation policy: %+v", selection)
	}
	if !selection.HumanAuthorizationRequired || !selection.AuthorizationRecordRequired || !selection.EnvironmentAcknowledgementRequired || !selection.ValidationPlanRequired || len(selection.PermittedExecutors) != 2 {
		t.Fatalf("selection response does not enforce human-authorized execution: %+v", selection)
	}
	prompt, err := os.ReadFile(filepath.Join(workspace, "agent-prompt.md"))
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	if !strings.Contains(string(prompt), "ensphere 10") || !strings.Contains(string(prompt), "run impact-ready returns ready: true") {
		t.Fatalf("expected session 10 prompt, got:\n%s", prompt)
	}
}

func TestSession10ReadinessRejectsUnknownExecutor(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	path := filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read handoff: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), `  - "agent"`, `  - "robot"`, 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write handoff: %v", err)
	}
	status, err := WorkspaceStatus(workspace)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.NextSession != nil {
		t.Fatalf("expected invalid Session 10 handoff to block Session 10, got %+v", status.NextSession)
	}
}

func TestSession10ReadinessRejectsAuthorizationTimestampInFuture(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	authorizationPath := "10-impact-validation/authorizations/VULN-001-agent.yaml"
	path := filepath.Join(workspace, filepath.FromSlash(authorizationPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read authorization: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), "authorized_at: 2026-07-18T10:00:00Z", "authorized_at: 2999-07-18T10:00:00Z", 1))
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatalf("write authorization: %v", err)
	}
	readiness, err := CheckImpactValidationReady(workspace, "VULN-001", authorizationPath)
	if err != nil {
		t.Fatalf("check impact readiness: %v", err)
	}
	if readiness.Ready || !hasIssue(readiness.Issues, "readiness_precedes_authorization") {
		t.Fatalf("expected future authorization timestamp to block readiness: %+v", readiness)
	}
}

func TestFinalGateRejectsReadinessBeforeAuthorization(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	writeSelectedFindings(t, workspace, "VULN-001")
	readinessPath := filepath.Join(workspace, "10-impact-validation", "readiness", "VULN-001-agent.yaml")
	raw, err := os.ReadFile(readinessPath)
	if err != nil {
		t.Fatalf("read readiness attestation: %v", err)
	}
	raw = []byte(strings.Replace(string(raw), "checked_at: 2026-07-18T10:00:30Z", "checked_at: 2026-07-18T09:59:59Z", 1))
	if err := os.WriteFile(readinessPath, raw, 0644); err != nil {
		t.Fatalf("write readiness attestation: %v", err)
	}
	authorizationRaw, err := os.ReadFile(filepath.Join(workspace, "10-impact-validation", "authorizations", "VULN-001-agent.yaml"))
	if err != nil {
		t.Fatalf("read authorization: %v", err)
	}
	var auth Session10Authorization
	if err := decodeStrictYAML(authorizationRaw, &auth); err != nil {
		t.Fatalf("decode authorization: %v", err)
	}
	outcome := ImpactValidationOutcome{
		ID:                "VULN-001",
		Executor:          "agent",
		AuthorizationPath: "10-impact-validation/authorizations/VULN-001-agent.yaml",
		ReadinessPath:     "10-impact-validation/readiness/VULN-001-agent.yaml",
		Execution:         Session10Execution{StartedAt: "2099-07-18T10:01:00Z"},
	}
	issues := validateImpactReadinessAttestation(workspace, readinessPath, outcome, &auth)
	if !hasIssue(issues, "readiness_precedes_authorization") {
		t.Fatalf("expected readiness ordering issue: %+v", issues)
	}
}

func TestPrepareImpactValidationRequiresEnabledWorkspace(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := PrepareImpactValidation(workspace, []string{"VULN-001"}); err == nil {
		t.Fatal("expected uninitialized workspace error")
	}
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := PrepareImpactValidation(workspace, []string{"VULN-001"}); err == nil {
		t.Fatal("expected impact validation disabled error")
	}
}

func TestPrepareImpactValidationRequiresSession09Done(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeValidFindingRegistry(t, workspace, "VULN-001")
	_, err := PrepareImpactValidation(workspace, []string{"VULN-001"})
	if err == nil || !strings.Contains(err.Error(), "Session 09") {
		t.Fatalf("expected Session 09 completion error, got %v", err)
	}
}

func TestPrepareImpactValidationRequiresFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	_, err := PrepareImpactValidation(workspace, []string{"VULN-001"})
	if err == nil || !strings.Contains(err.Error(), "finding registry is required") {
		t.Fatalf("expected missing registry error, got %v", err)
	}
}

func TestPrepareImpactValidationRejectsUnknownFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeValidFindingRegistry(t, workspace, "VULN-001")
	_, err := PrepareImpactValidation(workspace, []string{"VULN-999"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected unknown finding error, got %v", err)
	}
}

func TestRunFinalReportWritesDerivedRegistryWithoutMutatingSession09(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-002")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Read-only impact proof achieved.
    executor: agent
    authorization_path: 10-impact-validation/authorizations/VULN-001-agent.yaml
    readiness_path: 10-impact-validation/readiness/VULN-001-agent.yaml
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
    artifact_paths:
      - 10-impact-validation/artifacts/VULN-001-response.txt
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
    cleanup_status: verified
    evidence_categories:
      - human_authorization
      - agent_execution
      - impact_validation_attempt
      - impact_validation_result
`
	if err := os.WriteFile(filepath.Join(workspace, "10-impact-validation", "impact-validation-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	originalRaw, err := os.ReadFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"))
	if err != nil {
		t.Fatalf("read original registry: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if !out.Ready || len(out.UpdatedFindings) != 1 || len(out.PreservedFindings) != 1 {
		t.Fatalf("unexpected final output: %+v", out)
	}
	finalRaw, err := os.ReadFile(out.FinalRegistryPath)
	if err != nil {
		t.Fatalf("read final registry: %v", err)
	}
	finalText := string(finalRaw)
	for _, expected := range []string{"status: confirmed", "impact_validation_outcome_status: objective_achieved", "impact_validation_executor: agent", "EVID-010", "10-impact-validation/transcripts/VULN-001.md"} {
		if !strings.Contains(finalText, expected) {
			t.Fatalf("final registry missing %q:\n%s", expected, finalText)
		}
	}
	afterRaw, err := os.ReadFile(filepath.Join(workspace, "09-report", "finding-registry.yaml"))
	if err != nil {
		t.Fatalf("read original registry after final: %v", err)
	}
	if string(afterRaw) != string(originalRaw) {
		t.Fatalf("Session 09 registry was mutated:\nbefore:\n%s\nafter:\n%s", originalRaw, afterRaw)
	}
}

func TestRunFinalReportRejectsPlanChangedAfterAuthorization(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	planPath := filepath.Join(workspace, "10-impact-validation", "plans", "VULN-001-agent.yaml")
	plan, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if err := os.WriteFile(planPath, append(plan, []byte("\nUnapproved material change.\n")...), 0644); err != nil {
		t.Fatalf("change plan: %v", err)
	}
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Changed-plan rejection fixture.
    executor: agent
    authorization_path: 10-impact-validation/authorizations/VULN-001-agent.yaml
    readiness_path: 10-impact-validation/readiness/VULN-001-agent.yaml
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
    evidence_ids: [EVID-010]
    cleanup_evidence: [10-impact-validation/cleanup.md#VULN-001]
    cleanup_status: verified
    evidence_categories: [human_authorization, agent_execution, impact_validation_attempt, impact_validation_result]
`
	if err := os.WriteFile(impactValidationOutcomesPath(workspace), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if out.Ready || !hasIssue(out.Issues, "authorization_plan_sha256_mismatch") {
		t.Fatalf("expected changed plan to invalidate authorization, ready=%v issues=%+v", out.Ready, out.Issues)
	}
}

func TestSession10EvidenceCitationMustResolveToChainedFindingEvidence(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	writeSelectedFindings(t, workspace, "VULN-001")
	handoff, err := readSelectedFindingsHandoff(workspace)
	if err != nil {
		t.Fatalf("read handoff: %v", err)
	}
	issues := validateSession10EvidenceIDs(workspace, "outcome", ImpactValidationOutcome{
		ID:          "VULN-001",
		EvidenceIDs: []string{"EVID-999"},
	}, handoff)
	if !hasIssue(issues, "impact_validation_evidence_id_missing") {
		t.Fatalf("expected unresolved Session 10 evidence ID rejection, issues=%+v", issues)
	}
}

func TestRunFinalReportRejectsUnsafeOutcomePath(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Unsafe transcript path fixture.
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
      - ../outside.md
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
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if out.Ready || !hasIssue(out.Issues, "finding_path_unsafe") {
		t.Fatalf("expected unsafe outcome path issue, ready=%v issues=%+v", out.Ready, out.Issues)
	}
}

func TestRunFinalReportRejectsMissingOutcomeArtifact(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Missing transcript fixture.
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
    transcripts:
      - 10-impact-validation/transcripts/missing.md
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
    cleanup_status: verified
    evidence_categories:
      - human_authorization
      - human_execution
      - impact_validation_attempt
      - impact_validation_result
`
	if err := os.WriteFile(impactValidationOutcomesPath(workspace), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if out.Ready || !hasIssue(out.Issues, "finding_path_missing") {
		t.Fatalf("expected missing artifact rejection, ready=%v issues=%+v", out.Ready, out.Issues)
	}
}

func TestRunFinalReportRequiresOutcomeForEverySelectedFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-002")
	writeSelectedFindings(t, workspace, "VULN-001", "VULN-002")
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: blocked_by_control
    outcome_reason: The bounded action was blocked by the target control.
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
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
    cleanup_status: not_needed
    evidence_categories:
      - human_authorization
      - human_execution
      - impact_validation_attempt
      - impact_validation_result
`
	if err := os.WriteFile(filepath.Join(workspace, "10-impact-validation", "impact-validation-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if out.Ready || !hasIssue(out.Issues, "impact_validation_outcome_missing_selected") {
		t.Fatalf("expected missing selected outcome issue, ready=%v issues=%+v", out.Ready, out.Issues)
	}
}

func TestRunFinalReportRequiresCleanupStatusAndProofForAchievedObjective(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ImpactValidationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `generated_from: Session 10
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: Narrative-only proof fixture.
    executor: agent
    authorization_path: 10-impact-validation/authorizations/VULN-001-agent.yaml
    readiness_path: 10-impact-validation/readiness/VULN-001-agent.yaml
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
    cleanup_evidence:
      - 10-impact-validation/cleanup.md#VULN-001
    evidence_categories:
      - human_authorization
      - agent_execution
      - impact_validation_attempt
      - impact_validation_result
    notes: "Narrative only is not proof."
`
	if err := os.WriteFile(filepath.Join(workspace, "10-impact-validation", "impact-validation-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	for _, code := range []string{"impact_validation_proof_missing", "impact_validation_cleanup_status_missing"} {
		if !hasIssue(out.Issues, code) {
			t.Fatalf("expected %s issue, ready=%v issues=%+v", code, out.Ready, out.Issues)
		}
	}
}

func writeReportReadyWorkspace(t *testing.T, workspace string) {
	t.Helper()
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | SKIPPED | No authentication mechanism |
| 04 | Authorization | BLOCKED | Missing second account |
| 05 | Cross-Site Scripting | NOT_APPLICABLE | API only |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud Security | SKIPPED | No cloud scope |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | PENDING | |
| 10 | Optional Human-Authorized Impact Validation | PENDING | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "report.md")
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir report dir: %v", err)
		}
		if err := os.WriteFile(path, []byte("# Session Report\n\nReason and evidence summary.\n"), 0644); err != nil {
			t.Fatalf("write report %s: %v", path, err)
		}
	}
	writeSession09Artifacts(t, workspace)
}

func writeFinalReadyProgress(t *testing.T, workspace string) {
	t.Helper()
	progress := `# Assessment Progress

| Session | Category | Status | Findings |
|---------|----------|--------|----------|
| 01 | Recon | DONE | |
| 01.5 | Session Applicability Plan | DONE | |
| 02 | Injection | DONE | |
| 03 | Authentication | SKIPPED | No authentication mechanism |
| 04 | Authorization | BLOCKED | Missing second account |
| 05 | Cross-Site Scripting | NOT_APPLICABLE | API only |
| 06 | Server-Side Request Forgery | DONE | |
| 07 | Cloud Security | SKIPPED | No cloud scope |
| 08 | API Security | DONE | |
| 09 | Evidence-Based Assessment Report | DONE | |
| 10 | Optional Human-Authorized Impact Validation | DONE | |
| 11 | Optional Validation-Aware Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	writeReportGatePrerequisites(t, workspace)
}

func writeSession09DoneProgress(t *testing.T, workspace string) {
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
	writeReportGatePrerequisites(t, workspace)
}

func writeReportGatePrerequisites(t *testing.T, workspace string) {
	t.Helper()
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("write assessment plan fixture: %v", err)
	}
	for _, session := range reportRequiredSessions {
		path := filepath.Join(workspace, session.Directory, "report.md")
		if err := os.WriteFile(path, []byte("# Session report\n\nFixture coverage and limitations.\n"), 0644); err != nil {
			t.Fatalf("write Session %s report fixture: %v", session.ID, err)
		}
	}
}

func writeSelectedFindings(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	dir := filepath.Join(workspace, "10-impact-validation")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir selected findings dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "selected-findings.yaml"), []byte(renderSelectedFindings(ids, findingRegistryPath(workspace), defaultImpactValidationPolicy(true))), 0644); err != nil {
		t.Fatalf("write selected findings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte("# Session 10: Human-Authorized Impact Validation\n\nAuthorization and outcome summary.\n"), 0644); err != nil {
		t.Fatalf("write Session 10 report: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "transcripts"), 0755); err != nil {
		t.Fatalf("mkdir transcripts: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "plans"), 0755); err != nil {
		t.Fatalf("mkdir plans: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "authorizations"), 0755); err != nil {
		t.Fatalf("mkdir authorizations: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "readiness"), 0755); err != nil {
		t.Fatalf("mkdir readiness: %v", err)
	}
	for _, id := range ids {
		for _, executor := range []string{"human", "agent"} {
			plan := []byte(fmt.Sprintf(`finding_id: %s
objective: Observe the bounded canary result.
session09_evidence_ids: [EVID-001]
executor: %s
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
`, id, executor, id, id))
			planPath := "10-impact-validation/plans/" + id + "-" + executor + ".yaml"
			if err := os.WriteFile(filepath.Join(workspace, filepath.FromSlash(planPath)), plan, 0644); err != nil {
				t.Fatalf("write impact-validation plan: %v", err)
			}
			planHash := sha256.Sum256(plan)
			authorization := fmt.Sprintf(`finding_id: %s
plan_path: %s
plan_revision: rev-1
plan_sha256: sha256:%x
authorized_by: test-human
authorized_at: 2026-07-18T10:00:00Z
executor: %s
environment: local-test
environment_acknowledged: true
authorized_action_ids: [action-1]
max_actions: 1
max_duration_minutes: 5
max_risk: 2
`, id, planPath, planHash, executor)
			if err := os.WriteFile(filepath.Join(dir, "authorizations", id+"-"+executor+".yaml"), []byte(authorization), 0644); err != nil {
				t.Fatalf("write authorization record: %v", err)
			}
			authorizationHash := sha256.Sum256([]byte(authorization))
			attestation := fmt.Sprintf(`finding_id: %s
authorization_path: 10-impact-validation/authorizations/%s-%s.yaml
authorization_sha256: sha256:%x
plan_path: %s
plan_sha256: sha256:%x
executor: %s
checked_at: 2026-07-18T10:00:30Z
ready: true
`, id, id, executor, authorizationHash, planPath, planHash, executor)
			if err := os.WriteFile(filepath.Join(dir, "readiness", id+"-"+executor+".yaml"), []byte(attestation), 0644); err != nil {
				t.Fatalf("write readiness attestation: %v", err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "transcripts", id+".md"), []byte("# Execution transcript\n"), 0644); err != nil {
			t.Fatalf("write transcript: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "artifacts", id+"-response.txt"), []byte("controlled result\n"), 0644); err != nil {
			t.Fatalf("write artifact: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "cleanup.md"), []byte("# Cleanup\n\n## VULN-001\n\nVerified.\n"), 0644); err != nil {
		t.Fatalf("write cleanup: %v", err)
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

func writeValidFindingRegistry(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	if len(ids) == 0 {
		ids = []string{"VULN-001"}
	}
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
	writeSession09Artifacts(t, workspace)
}

func writeSession09Artifacts(t *testing.T, workspace string) {
	t.Helper()
	dir := filepath.Join(workspace, "09-report")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir Session 09 dir: %v", err)
	}
	report := `# Security Assessment Report

## Authorization
Authorized test.
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
Context only.
`
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(report), 0644); err != nil {
		t.Fatalf("write Session 09 report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence-appendix.md"), []byte("# Evidence Appendix\n\nClaim-to-evidence provenance.\n"), 0644); err != nil {
		t.Fatalf("write Session 09 appendix: %v", err)
	}
}

func hasIssue(issues []ReportGateIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
