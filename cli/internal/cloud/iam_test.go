package cloud

import (
	"testing"
)

func TestParseAWSAttachedPolicies(t *testing.T) {
	input := `{
		"AttachedPolicies": [
			{"PolicyArn": "arn:aws:iam::123:policy/AdminAccess"},
			{"PolicyArn": "arn:aws:iam::123:policy/ReadOnly"}
		]
	}`
	policies := parseAWSAttachedPolicies(input)
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestParseAWSInlinePolicies(t *testing.T) {
	input := `{"PolicyNames": ["inline-1", "inline-2"]}`
	policies := parseAWSInlinePolicies(input)
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
}

func TestParseAWSMFA_Enabled(t *testing.T) {
	input := `{"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/user"}]}`
	if !parseAWSMFA(input) {
		t.Error("expected MFA enabled")
	}
}

func TestParseAWSMFA_Disabled(t *testing.T) {
	input := `{"MFADevices": []}`
	if parseAWSMFA(input) {
		t.Error("expected MFA disabled")
	}
}

func TestParseAWSLastUsed(t *testing.T) {
	input := `{"User": {"PasswordLastUsed": "2024-01-15T10:00:00Z"}}`
	lu := parseAWSLastUsed(input)
	if lu != "2024-01-15T10:00:00Z" {
		t.Errorf("expected timestamp, got %s", lu)
	}
}

func TestParseAWSLastUsed_Never(t *testing.T) {
	input := `{"User": {}}`
	lu := parseAWSLastUsed(input)
	if lu != "never" {
		t.Errorf("expected never, got %s", lu)
	}
}

func TestCheckDangerousCombos(t *testing.T) {
	actions := []string{"iam:PassRole", "lambda:CreateFunction", "s3:GetObject"}
	combos := checkDangerousCombos(actions)
	if len(combos) != 1 {
		t.Fatalf("expected 1 dangerous combo, got %d", len(combos))
	}
	if combos[0] != "Lambda privilege escalation via PassRole + CreateFunction" {
		t.Errorf("unexpected combo: %s", combos[0])
	}
}

func TestCheckDangerousCombos_None(t *testing.T) {
	actions := []string{"s3:GetObject", "s3:PutObject"}
	combos := checkDangerousCombos(actions)
	if len(combos) != 0 {
		t.Errorf("expected 0 combos, got %d", len(combos))
	}
}
