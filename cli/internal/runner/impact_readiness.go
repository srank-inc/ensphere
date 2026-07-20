package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CheckImpactValidationReady performs the deterministic pre-execution gate for
// one selected Session 10 finding. It validates records only and executes no
// target action.
func CheckImpactValidationReady(workspace, findingID, authorizationPath string) (*ImpactValidationReadiness, error) {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	if err := ensureWorkspaceInitialized(workspace); err != nil {
		return nil, err
	}
	out := &ImpactValidationReadiness{
		Workspace:         workspace,
		FindingID:         strings.TrimSpace(findingID),
		AuthorizationPath: strings.TrimSpace(authorizationPath),
	}
	var validatedAuth *Session10Authorization
	var authorizationSHA256 string
	checkedAt := time.Now().UTC()
	if !impactValidationEnabled(workspace) {
		out.Issues = append(out.Issues, gateIssue("error", "impact_validation_disabled", configPath(workspace), "Session 10 must be explicitly enabled"))
	}
	if out.FindingID == "" {
		out.Issues = append(out.Issues, gateIssue("error", "impact_validation_finding_missing", "", "finding ID is required"))
	}
	if out.AuthorizationPath == "" {
		out.Issues = append(out.Issues, gateIssue("error", "authorization_path_missing", "", "authorization path is required"))
	}

	gate, err := RunReport(workspace)
	if err != nil {
		return nil, fmt.Errorf("run Session 09 report gate: %w", err)
	}
	if !gate.Ready {
		for _, issue := range gate.Issues {
			if issue.Severity == "error" {
				out.Issues = append(out.Issues, issue)
			}
		}
	}

	handoff, err := readSelectedFindingsHandoff(workspace)
	if err != nil {
		out.Issues = append(out.Issues, gateIssue("error", "session10_handoff_read_failed", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), err.Error()))
	} else {
		if err := validateSession10Handoff(workspace); err != nil {
			out.Issues = append(out.Issues, gateIssue("error", "session10_handoff_invalid", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), err.Error()))
		}
		if out.FindingID != "" && !containsRegistryValue(handoff.SelectedFindings, out.FindingID) {
			out.Issues = append(out.Issues, gateIssue("error", "impact_validation_finding_not_selected", filepath.Join(workspace, "10-impact-validation", "selected-findings.yaml"), fmt.Sprintf("finding %s was not selected", out.FindingID)))
		}
		if out.AuthorizationPath != "" && safeWorkspaceRelativePath(out.AuthorizationPath) {
			raw, readErr := os.ReadFile(filepath.Join(workspace, filepath.FromSlash(cleanCitationPath(out.AuthorizationPath))))
			if readErr == nil {
				var auth Session10Authorization
				if decodeErr := decodeStrictYAML(raw, &auth); decodeErr == nil {
					authHash := sha256.Sum256(raw)
					authorizationSHA256 = "sha256:" + hex.EncodeToString(authHash[:])
					validatedAuth = &auth
					out.Executor = auth.Executor
					out.PlanPath = auth.PlanPath
					dummy := ImpactValidationOutcome{ID: out.FindingID, Executor: auth.Executor, AuthorizationPath: out.AuthorizationPath}
					_, _, authIssues := validateSession10Authorization(workspace, out.AuthorizationPath, dummy, handoff)
					out.Issues = append(out.Issues, authIssues...)
				} else {
					out.Issues = append(out.Issues, gateIssue("error", "authorization_record_invalid", out.AuthorizationPath, decodeErr.Error()))
				}
			} else {
				out.Issues = append(out.Issues, gateIssue("error", "authorization_record_read_failed", out.AuthorizationPath, readErr.Error()))
			}
		} else if out.AuthorizationPath != "" {
			out.Issues = append(out.Issues, gateIssue("error", "finding_path_unsafe", out.AuthorizationPath, "authorization path must be workspace-relative"))
		}
	}
	if validatedAuth != nil {
		if authorizedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(validatedAuth.AuthorizedAt)); err == nil && checkedAt.Before(authorizedAt) {
			out.Issues = append(out.Issues, gateIssue("error", "readiness_precedes_authorization", out.AuthorizationPath, "run impact-ready cannot attest readiness before authorization.authorized_at"))
		}
	}

	out.Ready = !hasErrorIssue(out.Issues)
	if out.Ready {
		attestation := ImpactValidationReadinessAttestation{
			FindingID:           out.FindingID,
			AuthorizationPath:   out.AuthorizationPath,
			AuthorizationSHA256: authorizationSHA256,
			PlanPath:            validatedAuth.PlanPath,
			PlanSHA256:          validatedAuth.PlanSHA256,
			Executor:            validatedAuth.Executor,
			CheckedAt:           checkedAt.Format(time.RFC3339),
			Ready:               true,
		}
		dir := filepath.Join(workspace, "10-impact-validation", "readiness")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create readiness directory: %w", err)
		}
		out.AttestationPath = filepath.ToSlash(filepath.Join("10-impact-validation", "readiness", out.FindingID+"-"+validatedAuth.Executor+".yaml"))
		raw, err := yaml.Marshal(attestation)
		if err != nil {
			return nil, fmt.Errorf("encode readiness attestation: %w", err)
		}
		if err := os.WriteFile(filepath.Join(workspace, filepath.FromSlash(out.AttestationPath)), raw, 0644); err != nil {
			return nil, fmt.Errorf("write readiness attestation: %w", err)
		}
		out.Message = "Pre-execution gate ready. Only the exact authorized plan actions may run; any change requires a new plan hash and human authorization."
	} else {
		out.Message = "Pre-execution gate blocked. Do not perform any Session 10 action."
	}
	return out, nil
}
