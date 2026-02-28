package cloud

import (
	"testing"
)

func TestParseAWSACL(t *testing.T) {
	input := `{
		"Grants": [
			{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers", "Type": "Group"}, "Permission": "READ"},
			{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}
		]
	}`
	entries := parseAWSACL(input)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0] != "http://acs.amazonaws.com/groups/global/AllUsers:READ" {
		t.Errorf("unexpected entry[0]: %s", entries[0])
	}
}

func TestParseAWSEncryption(t *testing.T) {
	input := `{
		"ServerSideEncryptionConfiguration": {
			"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
		}
	}`
	enc := parseAWSEncryption(input)
	if enc != "aws:kms" {
		t.Errorf("expected aws:kms, got %s", enc)
	}
}

func TestParseAWSEncryption_None(t *testing.T) {
	enc := parseAWSEncryption("{}")
	if enc != "none" {
		t.Errorf("expected none, got %s", enc)
	}
}

func TestParseAWSVersioning(t *testing.T) {
	input := `{"Status": "Enabled"}`
	v := parseAWSVersioning(input)
	if v != "Enabled" {
		t.Errorf("expected Enabled, got %s", v)
	}
}

func TestParseAWSVersioning_Disabled(t *testing.T) {
	v := parseAWSVersioning("{}")
	if v != "disabled" {
		t.Errorf("expected disabled, got %s", v)
	}
}

func TestParseAWSLogging_Enabled(t *testing.T) {
	input := `{"LoggingEnabled": {"TargetBucket": "logs"}}`
	l := parseAWSLogging(input)
	if l != "enabled" {
		t.Errorf("expected enabled, got %s", l)
	}
}

func TestParseAWSLogging_Disabled(t *testing.T) {
	l := parseAWSLogging("{}")
	if l != "disabled" {
		t.Errorf("expected disabled, got %s", l)
	}
}

func TestParseAWSPublicAccess_AllBlocked(t *testing.T) {
	input := `{
		"PublicAccessBlockConfiguration": {
			"BlockPublicAcls": true, "IgnorePublicAcls": true,
			"BlockPublicPolicy": true, "RestrictPublicBuckets": true
		}
	}`
	public := parseAWSPublicAccess(input)
	if public {
		t.Error("expected false (all blocked), got true")
	}
}

func TestParseAWSPublicAccess_SomeOpen(t *testing.T) {
	input := `{
		"PublicAccessBlockConfiguration": {
			"BlockPublicAcls": false, "IgnorePublicAcls": true,
			"BlockPublicPolicy": true, "RestrictPublicBuckets": true
		}
	}`
	public := parseAWSPublicAccess(input)
	if !public {
		t.Error("expected true (some open), got false")
	}
}
