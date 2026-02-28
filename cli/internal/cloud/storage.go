package cloud

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/srank/ensphere/internal/verify"
)

// StorageConfig holds configuration for cloud storage verification.
type StorageConfig struct {
	Provider  string // aws, gcp, azure
	Bucket    string
	Region    string
	AccountID string
	verify.ProbeConfig
}

// StorageMeasurements holds cloud storage probe results.
type StorageMeasurements struct {
	Provider   string      `json:"provider"`
	Bucket     string      `json:"bucket"`
	PublicAccess *bool     `json:"public_access"`
	Encryption string      `json:"encryption"`
	Versioning string      `json:"versioning"`
	Logging    string      `json:"logging"`
	ACLEntries []string    `json:"acl_entries"`
	CLIOutputs []CLIResult `json:"cli_outputs"`
	ElapsedMs  int64       `json:"elapsed_ms"`
}

// VerifyCloudStorage runs cloud storage security checks.
func VerifyCloudStorage(cfg StorageConfig) (*verify.ProbeResult, error) {
	if err := verify.CheckCloudScope(cfg.Provider, cfg.AccountID, cfg.InScope); err != nil {
		return nil, err
	}
	if err := verify.CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := verify.NewTimer()
	start := time.Now()

	var cliOutputs []CLIResult
	var aclEntries []string
	encryption := "unknown"
	versioning := "unknown"
	logging := "unknown"
	var publicAccess *bool

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

		regionArgs := []string{}
		if cfg.Region != "" {
			regionArgs = []string{"--region", cfg.Region}
		}

		// Get bucket ACL
		args := append([]string{"s3api", "get-bucket-acl", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		aclResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, aclResult)
		if aclResult.ExitCode == 0 {
			aclEntries = parseAWSACL(aclResult.Stdout)
		}

		// Get encryption
		args = append([]string{"s3api", "get-bucket-encryption", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		encResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, encResult)
		if encResult.ExitCode == 0 {
			encryption = parseAWSEncryption(encResult.Stdout)
		} else {
			encryption = "none"
		}

		// Get versioning
		args = append([]string{"s3api", "get-bucket-versioning", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		verResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, verResult)
		if verResult.ExitCode == 0 {
			versioning = parseAWSVersioning(verResult.Stdout)
		}

		// Get logging
		args = append([]string{"s3api", "get-bucket-logging", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		logResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, logResult)
		if logResult.ExitCode == 0 {
			logging = parseAWSLogging(logResult.Stdout)
		}

		// Get public access block
		args = append([]string{"s3api", "get-public-access-block", "--bucket", cfg.Bucket, "--output", "json"}, regionArgs...)
		pubResult := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, pubResult)
		if pubResult.ExitCode == 0 {
			pa := parseAWSPublicAccess(pubResult.Stdout)
			publicAccess = &pa
		}

	case "gcp":
		cliName := "gcloud"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("gcloud CLI required: %w", err)
		}
		args := []string{"storage", "buckets", "describe", "gs://" + cfg.Bucket, "--format=json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)

	case "azure":
		cliName := "az"
		if err := CheckCLIInstalled(cliName); err != nil {
			return nil, fmt.Errorf("az CLI required: %w", err)
		}
		args := []string{"storage", "container", "show", "--name", cfg.Bucket, "--output", "json"}
		result := RunCLI(cliName, args, timeout)
		cliOutputs = append(cliOutputs, result)

	default:
		return nil, &verify.ScopeError{Msg: fmt.Sprintf("unsupported provider %q (aws, gcp, azure)", cfg.Provider)}
	}

	elapsed := time.Since(start).Milliseconds()

	return &verify.ProbeResult{
		SchemaVersion: 2,
		VulnType:      "cloud_storage",
		Technique:     "cloud_audit",
		StartedAt:     timer.StartedAt(),
		ProbeCount:    len(cliOutputs),
		Duration:      timer.Elapsed(),
		Measurements: StorageMeasurements{
			Provider:     cfg.Provider,
			Bucket:       cfg.Bucket,
			PublicAccess: publicAccess,
			Encryption:   encryption,
			Versioning:   versioning,
			Logging:      logging,
			ACLEntries:   aclEntries,
			CLIOutputs:   cliOutputs,
			ElapsedMs:    elapsed,
		},
	}, nil
}

func parseAWSACL(stdout string) []string {
	var result struct {
		Grants []struct {
			Grantee struct {
				URI  string `json:"URI"`
				Type string `json:"Type"`
			} `json:"Grantee"`
			Permission string `json:"Permission"`
		} `json:"Grants"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return nil
	}
	var entries []string
	for _, g := range result.Grants {
		id := g.Grantee.URI
		if id == "" {
			id = g.Grantee.Type
		}
		entries = append(entries, fmt.Sprintf("%s:%s", id, g.Permission))
	}
	return entries
}

func parseAWSEncryption(stdout string) string {
	var result struct {
		ServerSideEncryptionConfiguration struct {
			Rules []struct {
				ApplyServerSideEncryptionByDefault struct {
					SSEAlgorithm string `json:"SSEAlgorithm"`
				} `json:"ApplyServerSideEncryptionByDefault"`
			} `json:"Rules"`
		} `json:"ServerSideEncryptionConfiguration"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if len(result.ServerSideEncryptionConfiguration.Rules) > 0 {
		return result.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
	}
	return "none"
}

func parseAWSVersioning(stdout string) string {
	var result struct {
		Status string `json:"Status"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.Status == "" {
		return "disabled"
	}
	return result.Status
}

func parseAWSLogging(stdout string) string {
	var result struct {
		LoggingEnabled *struct{} `json:"LoggingEnabled"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return "unknown"
	}
	if result.LoggingEnabled != nil {
		return "enabled"
	}
	return "disabled"
}

func parseAWSPublicAccess(stdout string) bool {
	var result struct {
		PublicAccessBlockConfiguration struct {
			BlockPublicAcls       bool `json:"BlockPublicAcls"`
			IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
			BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
			RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
		} `json:"PublicAccessBlockConfiguration"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		return false
	}
	cfg := result.PublicAccessBlockConfiguration
	// If all blocks are enabled, public access is blocked (not public)
	allBlocked := cfg.BlockPublicAcls && cfg.IgnorePublicAcls && cfg.BlockPublicPolicy && cfg.RestrictPublicBuckets
	return !allBlocked
}
