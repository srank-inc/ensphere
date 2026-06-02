package cloud

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProwler(t *testing.T) {
	data := `[
		{"status_code": "FAIL", "severity": "high", "service_name": "s3", "check_id": "s3_bucket_public_access", "check_title": "S3 Bucket Public Access", "resource_arn": "arn:aws:s3:::my-bucket", "region": "us-east-1", "status_extended": "Bucket has public access"},
		{"status_code": "PASS", "severity": "low", "service_name": "s3", "check_id": "s3_bucket_encryption", "check_title": "S3 Encryption", "resource_arn": "arn:aws:s3:::my-bucket", "region": "us-east-1", "status_extended": "Encryption enabled"},
		{"status_code": "FAIL", "severity": "critical", "service_name": "iam", "check_id": "iam_root_mfa", "check_title": "Root MFA", "resource_arn": "arn:aws:iam::123:root", "region": "us-east-1", "status_extended": "Root has no MFA"}
	]`

	dir := t.TempDir()
	path := filepath.Join(dir, "prowler.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := ParseProwler(path)
	if err != nil {
		t.Fatalf("ParseProwler: %v", err)
	}

	if result.TotalFindings != 3 {
		t.Errorf("expected 3 total, got %d", result.TotalFindings)
	}
	if result.FailFindings != 2 {
		t.Errorf("expected 2 fails, got %d", result.FailFindings)
	}
	if result.BySeverity["high"] != 1 {
		t.Errorf("expected 1 high severity, got %d", result.BySeverity["high"])
	}
	if result.ByVulnType["cloud_storage"] != 1 {
		t.Errorf("expected 1 cloud_storage, got %d", result.ByVulnType["cloud_storage"])
	}
	if result.ByVulnType["cloud_iam"] != 1 {
		t.Errorf("expected 1 cloud_iam, got %d", result.ByVulnType["cloud_iam"])
	}
	if result.Findings[0].SeveritySource != "source_provided" {
		t.Fatalf("expected source-provided severity label, got %+v", result.Findings[0])
	}
}

func TestParseTrivy(t *testing.T) {
	data := `{
		"Results": [{
			"Type": "terraform",
			"Target": "main.tf",
			"Misconfigurations": [
				{"ID": "AVD-AWS-0086", "Title": "No encryption", "Description": "S3 bucket without encryption", "Severity": "HIGH", "Status": "FAIL"},
				{"ID": "AVD-AWS-0087", "Title": "Versioning", "Description": "S3 versioning enabled", "Severity": "LOW", "Status": "PASS"}
			]
		}]
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "trivy.json")
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := ParseTrivy(path)
	if err != nil {
		t.Fatalf("ParseTrivy: %v", err)
	}

	if result.TotalFindings != 2 {
		t.Errorf("expected 2 total, got %d", result.TotalFindings)
	}
	if result.FailFindings != 1 {
		t.Errorf("expected 1 fail, got %d", result.FailFindings)
	}
	if result.ByVulnType["cloud_storage"] != 1 {
		t.Errorf("expected 1 cloud_storage (AVD-AWS-0086), got %d", result.ByVulnType["cloud_storage"])
	}
	if result.Findings[0].SeveritySource != "source_provided" {
		t.Fatalf("expected source-provided severity label, got %+v", result.Findings[0])
	}
}

func TestMapTrivyTypeToVulnType(t *testing.T) {
	cases := []struct {
		trivyType string
		checkID   string
		want      string
	}{
		{"terraform", "AVD-AWS-0086", "cloud_storage"},
		{"terraform", "AVD-AWS-0007", "cloud_iam"},
		{"terraform", "AVD-AWS-0101", "cloud_network"},
		{"terraform", "AVD-AWS-0017", "cloud_logging"},
		{"terraform", "AVD-AWS-0104", "cloud_compute"},
		{"terraform", "AVD-AWS-9999", "iac_misconfig"},
		{"kubernetes", "KSV-001", "cloud_k8s"},
		{"dockerfile", "DS-001", "iac_misconfig"},
	}
	for _, tc := range cases {
		got := mapTrivyTypeToVulnType(tc.trivyType, tc.checkID)
		if got != tc.want {
			t.Errorf("mapTrivyTypeToVulnType(%q, %q) = %q, want %q", tc.trivyType, tc.checkID, got, tc.want)
		}
	}
}

func TestMapServiceToVulnType(t *testing.T) {
	cases := map[string]string{
		"iam":            "cloud_iam",
		"s3":             "cloud_storage",
		"ec2":            "cloud_network",
		"lambda":         "cloud_compute",
		"cloudtrail":     "cloud_logging",
		"kubernetes":     "cloud_k8s",
		"secretsmanager": "cloud_secrets",
		"unknown":        "iac_misconfig",
	}
	for service, want := range cases {
		got := mapServiceToVulnType(service)
		if got != want {
			t.Errorf("mapServiceToVulnType(%q) = %q, want %q", service, got, want)
		}
	}
}
