package cloud

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/verify"
)

// IAMConfig holds configuration for cloud IAM verification.
type IAMConfig struct {
	Provider  string
	Principal string // ARN, email, or service account
	AccountID string
	verify.ProbeConfig
}

// IAMMeasurements holds cloud IAM probe results.
type IAMMeasurements struct {
	Provider         string      `json:"provider"`
	Principal        string      `json:"principal"`
	AttachedPolicies []string    `json:"attached_policies"`
	InlinePolicies   []string    `json:"inline_policies"`
	MFAEnabled       *bool       `json:"mfa_enabled"`
	LastUsed         string      `json:"last_used"`
	DangerousCombos  []string    `json:"dangerous_combos"`
	CLIOutputs       []CLIResult `json:"cli_outputs"`
	ElapsedMs        int64       `json:"elapsed_ms"`
}

// Known dangerous IAM permission combinations (deterministic facts).
var dangerousPermPairs = []struct {
	perms []string
	desc  string
}{
	{[]string{"iam:PassRole", "lambda:CreateFunction"}, "Lambda privilege escalation via PassRole + CreateFunction"},
	{[]string{"iam:CreatePolicyVersion"}, "Policy version escalation via CreatePolicyVersion"},
	{[]string{"iam:AttachUserPolicy"}, "Self-policy attachment via AttachUserPolicy"},
	{[]string{"iam:AttachRolePolicy"}, "Role policy attachment via AttachRolePolicy"},
	{[]string{"iam:PutUserPolicy"}, "Inline policy injection via PutUserPolicy"},
	{[]string{"iam:PutRolePolicy"}, "Inline role policy injection via PutRolePolicy"},
}

// VerifyCloudIAM runs cloud IAM security checks.
func VerifyCloudIAM(cfg IAMConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var attachedPolicies, inlinePolicies []string
	var mfaEnabled *bool
	lastUsed := "unknown"
	var allActions []string

	timeout := cfg.TimeoutSec
	if timeout < 1 {
		timeout = 30
	}

	switch cfg.Provider {
	case "aws":
		cliName := "aws"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("aws CLI required: %w", err)
		}

		// Extract username from ARN if needed
		username := cfg.Principal
		if strings.Contains(username, ":user/") {
			parts := strings.Split(username, "/")
			username = parts[len(parts)-1]
		}

		// List attached policies
		args := []string{"iam", "list-attached-user-policies", "--user-name", username, "--output", "json"}
		attachedResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, attachedResult)
		if attachedResult.ExitCode == 0 {
			attachedPolicies = parseAWSAttachedPolicies(attachedResult.Stdout)
		}

		// List inline policies
		args = []string{"iam", "list-user-policies", "--user-name", username, "--output", "json"}
		inlineResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, inlineResult)
		if inlineResult.ExitCode == 0 {
			inlinePolicies = parseAWSInlinePolicies(inlineResult.Stdout)
		}

		// Check MFA
		args = []string{"iam", "list-mfa-devices", "--user-name", username, "--output", "json"}
		mfaResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, mfaResult)
		if mfaResult.ExitCode == 0 {
			m := parseAWSMFA(mfaResult.Stdout)
			mfaEnabled = &m
		}

		// Get user info for last used
		args = []string{"iam", "get-user", "--user-name", username, "--output", "json"}
		userResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, userResult)
		if userResult.ExitCode == 0 {
			lastUsed = parseAWSLastUsed(userResult.Stdout)
		}

		// Collect all actions from policy documents for dangerous combo check
		for _, policyARN := range attachedPolicies {
			policyActions, pResult := extractActionsFromPolicy(cliName, policyARN, timeout)
			cliOutputs = append(cliOutputs, pResult)
			allActions = append(allActions, policyActions...)
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		// Project IAM policy
		args := []string{"projects", "get-iam-policy", cfg.AccountID, "--format=json"}
		iamResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, iamResult)
		if iamResult.ExitCode == 0 {
			policies, dangerous := parseGCPIAMPolicy(iamResult.Stdout)
			attachedPolicies = policies
			allActions = append(allActions, dangerous...)
		}

		// Service account keys (if principal looks like a service account email)
		if strings.Contains(cfg.Principal, "iam.gserviceaccount.com") {
			args = []string{"iam", "service-accounts", "keys", "list", "--iam-account", cfg.Principal, "--format=json"}
			keysResult := RunCLI(cliName, args, timeout)
			cliOutputs = append(cliOutputs, keysResult)
		}

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"role", "assignment", "list", "--assignee", cfg.Principal, "--output", "json"}
		roleResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, roleResult)
		if roleResult.ExitCode == 0 {
			roles, dangerous := parseAzureRoleAssignments(roleResult.Stdout)
			attachedPolicies = roles
			allActions = append(allActions, dangerous...)
		}

		// Custom roles
		args = []string{"role", "definition", "list", "--custom-role-only", "true", "--output", "json"}
		customResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, customResult)

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	// Check for dangerous permission combinations
	dangerousCombos := checkDangerousCombos(allActions)

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		SchemaVersion: 2,
		VulnType:      "cloud_iam",
		Technique:     "cloud_audit",
		StartedAt:     timer.StartedAt(),
		ProbeCount:    len(cliOutputs),
		Duration:      timer.Elapsed(),
		Measurements: IAMMeasurements{
			Provider:         cfg.Provider,
			Principal:        cfg.Principal,
			AttachedPolicies: attachedPolicies,
			InlinePolicies:   inlinePolicies,
			MFAEnabled:       mfaEnabled,
			LastUsed:         lastUsed,
			DangerousCombos:  dangerousCombos,
			CLIOutputs:       cliOutputs,
			ElapsedMs:        elapsed,
		},
	}, nil
}

func parseAWSAttachedPolicies(stdout string) []string {
	var result struct {
		AttachedPolicies []struct {
			PolicyArn string `json:"PolicyArn"`
		} `json:"AttachedPolicies"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var policies []string
	for _, p := range result.AttachedPolicies {
		policies = append(policies, p.PolicyArn)
	}
	return policies
}

func parseAWSInlinePolicies(stdout string) []string {
	var result struct {
		PolicyNames []string `json:"PolicyNames"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	return result.PolicyNames
}

func parseAWSMFA(stdout string) bool {
	var result struct {
		MFADevices []struct{} `json:"MFADevices"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return false
	}
	return len(result.MFADevices) > 0
}

func parseAWSLastUsed(stdout string) string {
	var result struct {
		User struct {
			PasswordLastUsed string `json:"PasswordLastUsed"`
		} `json:"User"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.User.PasswordLastUsed == "" {
		return "never"
	}
	return result.User.PasswordLastUsed
}

func extractActionsFromPolicy(cliName, policyARN string, timeout int) ([]string, CLIResult) {
	// Step 1: get-policy to find DefaultVersionId
	args := []string{"iam", "get-policy", "--policy-arn", policyARN, "--output", "json"}
	policyResult := RunCLI(cliName, args, timeout)
	if policyResult.ExitCode != 0 {
		return nil, policyResult
	}

	var policyInfo struct {
		Policy struct {
			DefaultVersionId string `json:"DefaultVersionId"`
		} `json:"Policy"`
	}
	if err := json.Unmarshal([]byte(policyResult.Stdout), &policyInfo); err != nil || policyInfo.Policy.DefaultVersionId == "" {
		return nil, policyResult
	}

	// Step 2: get-policy-version
	args = []string{"iam", "get-policy-version", "--policy-arn", policyARN, "--version-id", policyInfo.Policy.DefaultVersionId, "--output", "json"}
	versionResult := RunCLI(cliName, args, timeout)
	if versionResult.ExitCode != 0 {
		return nil, versionResult
	}

	return parseActionsFromPolicyVersion(versionResult.Stdout), versionResult
}

func parseActionsFromPolicyVersion(stdout string) []string {
	var result struct {
		PolicyVersion struct {
			Document string `json:"Document"`
		} `json:"PolicyVersion"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	// Document is URL-encoded JSON
	doc := result.PolicyVersion.Document
	// Try URL-decode
	if decoded, err := url.QueryUnescape(doc); err == nil {
		doc = decoded
	}
	var policy struct {
		Statement []struct {
			Action interface{} `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &policy); err != nil {
		return nil
	}
	var actions []string
	for _, stmt := range policy.Statement {
		switch a := stmt.Action.(type) {
		case string:
			actions = append(actions, a)
		case []interface{}:
			for _, v := range a {
				if s, ok := v.(string); ok {
					actions = append(actions, s)
				}
			}
		}
	}
	return actions
}

func parseGCPIAMPolicy(stdout string) ([]string, []string) {
	var result struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, nil
	}
	var roles []string
	var dangerous []string
	dangerousRoles := map[string]bool{
		"roles/owner": true, "roles/editor": true, "roles/iam.securityAdmin": true,
		"roles/iam.serviceAccountAdmin": true, "roles/iam.serviceAccountKeyAdmin": true,
	}
	for _, b := range result.Bindings {
		roles = append(roles, b.Role)
		if dangerousRoles[b.Role] {
			dangerous = append(dangerous, b.Role)
		}
	}
	return roles, dangerous
}

func parseAzureRoleAssignments(stdout string) ([]string, []string) {
	var result []struct {
		RoleDefinitionName string `json:"roleDefinitionName"`
		Scope              string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil, nil
	}
	dangerousRoles := map[string]bool{
		"Owner": true, "Contributor": true, "User Access Administrator": true,
	}
	var roles []string
	var dangerous []string
	for _, r := range result {
		roles = append(roles, r.RoleDefinitionName)
		if dangerousRoles[r.RoleDefinitionName] {
			dangerous = append(dangerous, r.RoleDefinitionName)
		}
	}
	return roles, dangerous
}

func checkDangerousCombos(actions []string) []string {
	if len(actions) == 0 {
		return nil
	}
	actionSet := make(map[string]bool)
	for _, a := range actions {
		actionSet[a] = true
	}
	var combos []string
	for _, pair := range dangerousPermPairs {
		allPresent := true
		for _, p := range pair.perms {
			if !actionSet[p] {
				allPresent = false
				break
			}
		}
		if allPresent {
			combos = append(combos, pair.desc)
		}
	}
	return combos
}
