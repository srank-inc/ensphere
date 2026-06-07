package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		filepath.Join(workspace, "10-exploitation"),
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

func TestWriteNextActionSkipsOptionalExploitWhenDisabled(t *testing.T) {
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
	action, err := WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action: %v", err)
	}
	if action.Session != nil {
		t.Fatalf("expected no next session when exploitation disabled, got %+v", action.Session)
	}
}

func TestWriteNextActionRequiresSelectedFindingsForSession10(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
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
	if _, err := PrepareExploit(workspace, []string{"VULN-001"}); err != nil {
		t.Fatalf("prepare exploit: %v", err)
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
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte("schema_version: 1\n"), 0644); err != nil {
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

func TestWriteNextActionRequiresSession10DoneForSession11(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	if _, err := PrepareExploit(workspace, []string{"VULN-001"}); err != nil {
		t.Fatalf("prepare exploit: %v", err)
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
| 10 | Optional Prove-by-Exploitation | SKIPPED | |
| 11 | Exploit-Verified Final Report | PENDING | |
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

	progress = strings.Replace(progress, "| 10 | Optional Prove-by-Exploitation | SKIPPED | |", "| 10 | Optional Prove-by-Exploitation | DONE | |", 1)
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write done progress: %v", err)
	}
	action, err = WriteNextAction(workspace)
	if err != nil {
		t.Fatalf("write next action after done Session 10: %v", err)
	}
	if action.Session == nil || action.Session.ID != "11" {
		t.Fatalf("expected Session 11 after done Session 10, got %+v", action.Session)
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
	if err := os.WriteFile(filepath.Join(workspace, "assessment-plan.yaml"), []byte("schema_version: 1\n"), 0644); err != nil {
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
	profile := `schema_version: 1
target:
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
	profile := `schema_version: 1
target:
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
	profile := `schema_version: 1
target:
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
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
	registry := `schema_version: 1
generated_from: Session 09
findings:
  - id: VULN-001
    title: Missing citation
    category: injection
    status: strong_evidence_not_exploited
    confidence: medium
    severity: high
    evidence_categories:
      - ensphere_measurement
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

	registry = `schema_version: 1
generated_from: Session 09
findings:
  - id: VULN-001
    title: Cited finding
    category: injection
    status: strong_evidence_not_exploited
    confidence: medium
    severity: high
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
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
	registry := `schema_version: 1
generated_from: Session 09
findings:
  - id: VULN-001
    title: Bad enum values
    category: injection
    status: confirmed
    confidence: certain
    severity: severe
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

func TestRunReportRejectsEmptyCitationPlaceholders(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := RunPlan(workspace, false); err != nil {
		t.Fatalf("run plan: %v", err)
	}
	writeReportReadyWorkspace(t, workspace)
	registry := `schema_version: 1
generated_from: Session 09
findings:
  - id: VULN-001
    title: Blank citation placeholder
    category: injection
    status: strong_evidence_not_exploited
    confidence: medium
    severity: high
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
	registry := `schema_version: 1
generated_from: Session 09
findings:
  - id: VULN-001
    title: Unsafe citation paths
    category: injection
    status: strong_evidence_not_exploited
    confidence: medium
    severity: high
    coverage_label: full
    evidence_categories:
      - ensphere_measurement
    transcripts:
      - /tmp/outside.md
    artifact_paths:
      - ../outside.txt
    cleanup_evidence:
      - 10-exploitation/cleanup.md#VULN-001
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

func TestPrepareExploitWritesSelectionAndPrompt(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeSession09DoneProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-004")
	selection, err := PrepareExploit(workspace, []string{"VULN-001", "VULN-004"})
	if err != nil {
		t.Fatalf("prepare exploit: %v", err)
	}
	raw, err := os.ReadFile(selection.SelectionPath)
	if err != nil {
		t.Fatalf("read selected findings: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, `"VULN-001"`) ||
		!strings.Contains(text, "finding_registry_path:") ||
		!strings.Contains(text, "max_risk: 3") ||
		!strings.Contains(text, "human_approval_required: true") ||
		!strings.Contains(text, `evidence_jsonl: "10-exploitation/evidence.jsonl"`) ||
		!strings.Contains(text, "cleanup_evidence_required: true") {
		t.Fatalf("unexpected selected findings:\n%s", text)
	}
	if selection.MaxRisk != 3 || len(selection.AllowedActions) == 0 || len(selection.ForbiddenActions) == 0 {
		t.Fatalf("selection response missing exploit policy: %+v", selection)
	}
	prompt, err := os.ReadFile(filepath.Join(workspace, "agent-prompt.md"))
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	if !strings.Contains(string(prompt), "ensphere 10") {
		t.Fatalf("expected session 10 prompt, got:\n%s", prompt)
	}
}

func TestPrepareExploitRequiresEnabledWorkspace(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := PrepareExploit(workspace, []string{"VULN-001"}); err == nil {
		t.Fatal("expected uninitialized workspace error")
	}
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com"}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	if _, err := PrepareExploit(workspace, []string{"VULN-001"}); err == nil {
		t.Fatal("expected exploitation disabled error")
	}
}

func TestPrepareExploitRequiresSession09Done(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeValidFindingRegistry(t, workspace, "VULN-001")
	_, err := PrepareExploit(workspace, []string{"VULN-001"})
	if err == nil || !strings.Contains(err.Error(), "Session 09") {
		t.Fatalf("expected Session 09 completion error, got %v", err)
	}
}

func TestPrepareExploitRequiresFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	_, err := PrepareExploit(workspace, []string{"VULN-001"})
	if err == nil || !strings.Contains(err.Error(), "finding registry is required") {
		t.Fatalf("expected missing registry error, got %v", err)
	}
}

func TestPrepareExploitRejectsUnknownFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeValidFindingRegistry(t, workspace, "VULN-001")
	_, err := PrepareExploit(workspace, []string{"VULN-999"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected unknown finding error, got %v", err)
	}
}

func TestRunFinalReportWritesDerivedRegistryWithoutMutatingSession09(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-002")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `schema_version: 1
generated_from: Session 10
outcomes:
  - id: VULN-001
    status: exploited
    outcome_reason: Read-only impact proof achieved.
    evidence_ids:
      - EVID-010
    transcripts:
      - 10-exploitation/transcripts/VULN-001.md
    artifact_paths:
      - 10-exploitation/artifacts/VULN-001-response.txt
    cleanup_evidence:
      - 10-exploitation/cleanup.md#VULN-001
    cleanup_status: verified
`
	if err := os.WriteFile(filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
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
	for _, expected := range []string{"status: exploited", "original_status: strong_evidence_not_exploited", "EVID-010", "10-exploitation/transcripts/VULN-001.md"} {
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

func TestRunFinalReportRejectsUnsafeOutcomePath(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `schema_version: 1
generated_from: Session 10
outcomes:
  - id: VULN-001
    status: exploited
    evidence_ids:
      - EVID-010
    transcripts:
      - ../outside.md
    cleanup_status: verified
`
	if err := os.WriteFile(filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
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

func TestRunFinalReportRequiresOutcomeForEverySelectedFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001", "VULN-002")
	writeSelectedFindings(t, workspace, "VULN-001", "VULN-002")
	outcomes := `schema_version: 1
generated_from: Session 10
outcomes:
  - id: VULN-001
    status: blocked_by_security
    evidence_ids:
      - EVID-010
    cleanup_status: not_needed
`
	if err := os.WriteFile(filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	if out.Ready || !hasIssue(out.Issues, "exploit_outcome_missing_selected") {
		t.Fatalf("expected missing selected outcome issue, ready=%v issues=%+v", out.Ready, out.Issues)
	}
}

func TestRunFinalReportRequiresCleanupStatusAndProofForExploited(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if _, err := InitWorkspace(InitConfig{Workspace: workspace, TargetURL: "https://example.com", ExploitationEnabled: true}); err != nil {
		t.Fatalf("init workspace: %v", err)
	}
	writeFinalReadyProgress(t, workspace)
	writeValidFindingRegistry(t, workspace, "VULN-001")
	writeSelectedFindings(t, workspace, "VULN-001")
	outcomes := `schema_version: 1
generated_from: Session 10
outcomes:
  - id: VULN-001
    status: exploited
    notes: "Narrative only is not proof."
`
	if err := os.WriteFile(filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
		t.Fatalf("write outcomes: %v", err)
	}
	out, err := RunFinalReport(workspace)
	if err != nil {
		t.Fatalf("run final: %v", err)
	}
	for _, code := range []string{"exploit_outcome_proof_missing", "exploit_cleanup_status_missing"} {
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
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
| 10 | Optional Prove-by-Exploitation | DONE | |
| 11 | Exploit-Verified Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
}

func writeSelectedFindings(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	dir := filepath.Join(workspace, "10-exploitation")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir selected findings dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "selected-findings.yaml"), []byte(renderSelectedFindings(ids, findingRegistryPath(workspace), defaultExploitationPolicy(true))), 0644); err != nil {
		t.Fatalf("write selected findings: %v", err)
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
	b.WriteString("schema_version: 1\n")
	b.WriteString("generated_from: Session 09\n")
	b.WriteString("findings:\n")
	for _, id := range ids {
		b.WriteString("  - id: " + id + "\n")
		b.WriteString("    title: Registry finding " + id + "\n")
		b.WriteString("    category: injection\n")
		b.WriteString("    status: strong_evidence_not_exploited\n")
		b.WriteString("    confidence: medium\n")
		b.WriteString("    severity: high\n")
		b.WriteString("    coverage_label: full\n")
		b.WriteString("    evidence_categories:\n")
		b.WriteString("      - ensphere_measurement\n")
		b.WriteString("    evidence_ids:\n")
		b.WriteString("      - EVID-001\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "finding-registry.yaml"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write finding registry: %v", err)
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
