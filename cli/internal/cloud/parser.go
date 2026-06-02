package cloud

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ProwlerFinding represents a single Prowler JSON-OCSF finding.
type ProwlerFinding struct {
	StatusCode  string `json:"status_code"`
	Severity    string `json:"severity"`
	ServiceName string `json:"service_name"`
	CheckID     string `json:"check_id"`
	CheckTitle  string `json:"check_title"`
	ResourceARN string `json:"resource_arn"`
	Region      string `json:"region"`
	Description string `json:"status_extended"`
}

// TrivyFinding represents a single Trivy misconfiguration finding.
type TrivyFinding struct {
	Type           string `json:"Type"`
	Target         string `json:"Target"`
	MisconfSummary struct {
		Successes  int `json:"Successes"`
		Failures   int `json:"Failures"`
		Exceptions int `json:"Exceptions"`
	} `json:"MisconfSummary"`
	Misconfigurations []struct {
		ID          string `json:"ID"`
		Title       string `json:"Title"`
		Description string `json:"Description"`
		Severity    string `json:"Severity"`
		Status      string `json:"Status"`
	} `json:"Misconfigurations"`
}

// TrivyReport is the top-level Trivy JSON output.
type TrivyReport struct {
	Results []TrivyFinding `json:"Results"`
}

// MappedFinding represents a finding mapped to an Ensphere vuln type.
type MappedFinding struct {
	CheckID        string `json:"check_id"`
	CheckTitle     string `json:"check_title"`
	Severity       string `json:"severity"`
	SeveritySource string `json:"severity_source"`
	ResourceARN    string `json:"resource_arn"`
	VulnType       string `json:"vuln_type"`
	Description    string `json:"description"`
}

// ParseResult is the JSON output of a parser run.
type ParseResult struct {
	SchemaVersion int             `json:"schema_version"`
	Source        string          `json:"source"`
	TotalFindings int             `json:"total_findings"`
	FailFindings  int             `json:"fail_findings"`
	BySeverity    map[string]int  `json:"by_severity"`
	ByVulnType    map[string]int  `json:"by_vuln_type"`
	Findings      []MappedFinding `json:"findings"`
}

// ParseProwler reads and parses a Prowler JSON-OCSF output file.
func ParseProwler(filePath string) (*ParseResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var findings []ProwlerFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	result := &ParseResult{
		SchemaVersion: 2,
		Source:        "prowler",
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByVulnType:    make(map[string]int),
	}

	for _, f := range findings {
		if f.StatusCode != "FAIL" {
			continue
		}
		result.FailFindings++

		vulnType := mapServiceToVulnType(f.ServiceName)
		result.BySeverity[f.Severity]++
		result.ByVulnType[vulnType]++

		result.Findings = append(result.Findings, MappedFinding{
			CheckID:        f.CheckID,
			CheckTitle:     f.CheckTitle,
			Severity:       f.Severity,
			SeveritySource: "source_provided",
			ResourceARN:    f.ResourceARN,
			VulnType:       vulnType,
			Description:    f.Description,
		})
	}

	return result, nil
}

// ParseTrivy reads and parses a Trivy JSON output file.
func ParseTrivy(filePath string) (*ParseResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	result := &ParseResult{
		SchemaVersion: 2,
		Source:        "trivy",
		BySeverity:    make(map[string]int),
		ByVulnType:    make(map[string]int),
	}

	for _, tr := range report.Results {
		for _, m := range tr.Misconfigurations {
			result.TotalFindings++
			if m.Status != "FAIL" {
				continue
			}
			result.FailFindings++

			vulnType := mapTrivyTypeToVulnType(tr.Type, m.ID)
			result.BySeverity[m.Severity]++
			result.ByVulnType[vulnType]++

			result.Findings = append(result.Findings, MappedFinding{
				CheckID:        m.ID,
				CheckTitle:     m.Title,
				Severity:       m.Severity,
				SeveritySource: "source_provided",
				ResourceARN:    tr.Target,
				VulnType:       vulnType,
				Description:    m.Description,
			})
		}
	}

	return result, nil
}

// mapServiceToVulnType maps Prowler service names to Ensphere vuln types.
func mapServiceToVulnType(service string) string {
	s := strings.ToLower(service)
	switch {
	case s == "iam" || s == "accessanalyzer":
		return "cloud_iam"
	case s == "s3" || s == "storage":
		return "cloud_storage"
	case s == "ec2" || s == "vpc" || s == "securitygroup" || s == "firewall":
		return "cloud_network"
	case s == "lambda" || s == "ecs" || s == "eks":
		return "cloud_compute"
	case s == "cloudtrail" || s == "logging":
		return "cloud_logging"
	case s == "kubernetes" || s == "k8s":
		return "cloud_k8s"
	case s == "secretsmanager" || s == "kms":
		return "cloud_secrets"
	default:
		return "iac_misconfig"
	}
}

// mapTrivyTypeToVulnType maps Trivy result types to Ensphere vuln types.
// Uses check ID for specific resource mapping, falling back to type-based mapping.
func mapTrivyTypeToVulnType(trivyType, checkID string) string {
	id := strings.ToUpper(checkID)
	switch {
	case strings.HasPrefix(id, "AVD-AWS-0086"), strings.HasPrefix(id, "AVD-AWS-0088"),
		strings.HasPrefix(id, "AVD-AWS-0089"), strings.HasPrefix(id, "AVD-AWS-0090"),
		strings.HasPrefix(id, "AVD-AWS-0091"), strings.HasPrefix(id, "AVD-AWS-0132"):
		return "cloud_storage"
	case strings.HasPrefix(id, "AVD-AWS-0007"), strings.HasPrefix(id, "AVD-AWS-0057"),
		strings.HasPrefix(id, "AVD-AWS-0142"), strings.HasPrefix(id, "AVD-AWS-0143"),
		strings.HasPrefix(id, "AVD-AWS-0144"), strings.HasPrefix(id, "AVD-AWS-0145"):
		return "cloud_iam"
	case strings.HasPrefix(id, "AVD-AWS-0101"), strings.HasPrefix(id, "AVD-AWS-0105"):
		return "cloud_network"
	case strings.HasPrefix(id, "AVD-AWS-0017"), strings.HasPrefix(id, "AVD-AWS-0065"):
		return "cloud_logging"
	case strings.HasPrefix(id, "AVD-AWS-0104"):
		return "cloud_compute"
	}

	t := strings.ToLower(trivyType)
	switch {
	case strings.Contains(t, "terraform"):
		return "iac_misconfig"
	case strings.Contains(t, "cloudformation"):
		return "iac_misconfig"
	case strings.Contains(t, "kubernetes") || strings.Contains(t, "k8s"):
		return "cloud_k8s"
	case strings.Contains(t, "docker") || strings.Contains(t, "dockerfile"):
		return "iac_misconfig"
	default:
		return "iac_misconfig"
	}
}
