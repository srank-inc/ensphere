package cloud

import (
	"testing"
)

func TestParseAWSSecrets(t *testing.T) {
	input := `{
		"SecretList": [
			{
				"Name": "prod/db-password",
				"RotationEnabled": true,
				"LastRotatedDate": "2024-12-01T00:00:00Z",
				"KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc"
			},
			{
				"Name": "dev/api-key",
				"RotationEnabled": false,
				"KmsKeyId": ""
			}
		]
	}`
	secrets, rotEnabled, rotDisabled := parseAWSSecrets(input)
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
	if rotEnabled != 1 {
		t.Errorf("expected 1 rotation enabled, got %d", rotEnabled)
	}
	if rotDisabled != 1 {
		t.Errorf("expected 1 rotation disabled, got %d", rotDisabled)
	}
	if secrets[0].RotationEnabled == nil || !*secrets[0].RotationEnabled {
		t.Error("expected first secret rotation enabled")
	}
	if secrets[0].KMSKeyUsed == nil || !*secrets[0].KMSKeyUsed {
		t.Error("expected first secret to use KMS")
	}
	if secrets[0].LastRotated != "2024-12-01T00:00:00Z" {
		t.Errorf("unexpected LastRotated: %s", secrets[0].LastRotated)
	}
	if secrets[1].KMSKeyUsed == nil || *secrets[1].KMSKeyUsed {
		t.Error("expected second secret to NOT use KMS")
	}
}

func TestParseAWSSecrets_Empty(t *testing.T) {
	secrets, rotEnabled, rotDisabled := parseAWSSecrets(`{"SecretList": []}`)
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}
	if rotEnabled != 0 || rotDisabled != 0 {
		t.Error("expected 0 rotation counts for empty list")
	}
}

func TestParseGCPSecrets(t *testing.T) {
	input := `[
		{"name": "projects/p/secrets/db-pass", "rotation": {"rotationPeriod": "7776000s", "nextRotationTime": "2025-06-01T00:00:00Z"}},
		{"name": "projects/p/secrets/api-key"}
	]`
	secrets, rotEnabled, rotDisabled := parseGCPSecrets(input)
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
	if secrets[0].Name != "projects/p/secrets/db-pass" {
		t.Errorf("unexpected name: %s", secrets[0].Name)
	}
	if rotEnabled != 1 {
		t.Errorf("expected 1 rotation enabled, got %d", rotEnabled)
	}
	if rotDisabled != 1 {
		t.Errorf("expected 1 rotation disabled, got %d", rotDisabled)
	}
	if secrets[0].RotationEnabled == nil || !*secrets[0].RotationEnabled {
		t.Error("expected first secret rotation enabled")
	}
	if secrets[1].RotationEnabled == nil || *secrets[1].RotationEnabled {
		t.Error("expected second secret rotation disabled")
	}
}

func TestParseAzureKeyVaults(t *testing.T) {
	input := `[
		{"name": "prod-vault", "properties": {"enableSoftDelete": true, "enablePurgeProtection": true}},
		{"name": "dev-vault", "properties": {"enableSoftDelete": false, "enablePurgeProtection": false}}
	]`
	secrets, rotEnabled, rotDisabled := parseAzureKeyVaults(input)
	if len(secrets) != 2 {
		t.Fatalf("expected 2 vaults, got %d", len(secrets))
	}
	if secrets[0].Name != "prod-vault" {
		t.Errorf("unexpected name: %s", secrets[0].Name)
	}
	if rotEnabled != 0 {
		t.Errorf("expected 0 rotation enabled (Azure has no vault-level rotation), got %d", rotEnabled)
	}
	if rotDisabled != 2 {
		t.Errorf("expected 2 rotation disabled, got %d", rotDisabled)
	}
	if secrets[0].KMSKeyUsed == nil || !*secrets[0].KMSKeyUsed {
		t.Error("expected prod-vault to have purge protection")
	}
	if secrets[1].KMSKeyUsed == nil || *secrets[1].KMSKeyUsed {
		t.Error("expected dev-vault to NOT have purge protection")
	}
}

func TestParseAWSSecrets_InvalidJSON(t *testing.T) {
	secrets, re, rd := parseAWSSecrets("not json")
	if secrets != nil {
		t.Error("expected nil for invalid JSON")
	}
	if re != 0 || rd != 0 {
		t.Error("expected 0 counts for invalid JSON")
	}
}
