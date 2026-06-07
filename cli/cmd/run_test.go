package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		SchemaVersion int `json:"schema_version"`
		NextSession   *struct {
			ID string `json:"id"`
		} `json:"next_session"`
	}
	decodeJSON(t, initResult.stdout, &initOut)
	if initOut.SchemaVersion != 1 || initOut.NextSession == nil || initOut.NextSession.ID != "01" {
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

func TestCLIRunExploitRequiresFinding(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--exploitation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	missing := runCLISplit(t, "run", "--workspace", workspace, "exploit")
	if missing.code != 2 {
		t.Fatalf("expected usage exit 2, got %d stdout=%s stderr=%s", missing.code, missing.stdout, missing.stderr)
	}

	writeCLIFindingRegistry(t, workspace, "VULN-001", "VULN-004")
	writeCLISession09DoneProgress(t, workspace)
	selected := runCLISplit(t, "run", "--workspace", workspace, "exploit", "--finding", "VULN-001", "--finding", "VULN-004")
	if selected.code != 0 {
		t.Fatalf("run exploit exit %d stderr=%s", selected.code, selected.stderr)
	}
	if !strings.Contains(selected.stdout, `"VULN-001"`) || !strings.Contains(selected.stdout, `"selection_path"`) {
		t.Fatalf("unexpected run exploit output:\n%s", selected.stdout)
	}
	raw, err := os.ReadFile(filepath.Join(workspace, "10-exploitation", "selected-findings.yaml"))
	if err != nil {
		t.Fatalf("read selected findings: %v", err)
	}
	if !strings.Contains(string(raw), `"VULN-004"`) {
		t.Fatalf("selected findings missing VULN-004:\n%s", raw)
	}
	if !strings.Contains(string(raw), "human_approval_required: true") || !strings.Contains(string(raw), "max_risk: 3") {
		t.Fatalf("selected findings missing safety policy:\n%s", raw)
	}
}

func TestCLIRunExploitRequiresEnabledGate(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "exploit", "--finding", "VULN-001")
	if result.code != 2 {
		t.Fatalf("expected gate exit 2, got %d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "exploitation is not enabled") {
		t.Fatalf("unexpected stderr:\n%s", result.stderr)
	}
}

func TestCLIRunExploitRequiresFindingRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--exploitation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	result := runCLISplit(t, "run", "--workspace", workspace, "exploit", "--finding", "VULN-001")
	if result.code != 2 {
		t.Fatalf("expected registry gate exit 2, got %d stdout=%s stderr=%s", result.code, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr, "finding registry is required") {
		t.Fatalf("unexpected stderr:\n%s", result.stderr)
	}
}

func TestCLIRunFinalWritesDerivedRegistry(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "ensphere-pentest")
	if result := runCLISplit(t, "run", "--workspace", workspace, "init", "--target", "https://example.com", "--exploitation-enabled"); result.code != 0 {
		t.Fatalf("run init exit %d stderr=%s", result.code, result.stderr)
	}
	writeCLIFinalProgress(t, workspace)
	writeCLIFindingRegistry(t, workspace, "VULN-001")
	writeCLISelectedFindings(t, workspace, "VULN-001")
	outcomes := `schema_version: 1
generated_from: Session 10
outcomes:
  - id: VULN-001
    status: exploited
    evidence_ids:
      - EVID-010
    transcripts:
      - 10-exploitation/transcripts/VULN-001.md
    cleanup_status: verified
`
	if err := os.WriteFile(filepath.Join(workspace, "10-exploitation", "exploit-outcomes.yaml"), []byte(outcomes), 0644); err != nil {
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
	if !strings.Contains(string(raw), "status: exploited") || !strings.Contains(string(raw), "original_status: strong_evidence_not_exploited") {
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

func writeCLISelectedFindings(t *testing.T, workspace string, ids ...string) {
	t.Helper()
	dir := filepath.Join(workspace, "10-exploitation")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir selected findings dir: %v", err)
	}
	var b strings.Builder
	b.WriteString("schema_version: 1\n")
	b.WriteString("enabled: true\n")
	b.WriteString("finding_registry_path: \"" + filepath.Join(workspace, "09-report", "finding-registry.yaml") + "\"\n")
	b.WriteString("selected_findings:\n")
	for _, id := range ids {
		b.WriteString("  - \"" + id + "\"\n")
	}
	b.WriteString("cleanup_required: true\n")
	b.WriteString("cleanup_evidence_required: true\n")
	if err := os.WriteFile(filepath.Join(dir, "selected-findings.yaml"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write selected findings: %v", err)
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
| 10 | Optional Prove-by-Exploitation | DONE | |
| 11 | Exploit-Verified Final Report | PENDING | |
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
| 10 | Optional Prove-by-Exploitation | PENDING | |
| 11 | Exploit-Verified Final Report | PENDING | |
`
	if err := os.WriteFile(filepath.Join(workspace, "progress.md"), []byte(progress), 0644); err != nil {
		t.Fatalf("write progress: %v", err)
	}
}
