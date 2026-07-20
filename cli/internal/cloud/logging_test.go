package cloud

import (
	"testing"
)

func TestParseAWSCloudTrails(t *testing.T) {
	input := `{
		"TrailList": [
			{
				"Name": "main-trail",
				"IsMultiRegionTrail": true,
				"LogFileValidationEnabled": true
			},
			{
				"Name": "regional-trail",
				"IsMultiRegionTrail": false,
				"LogFileValidationEnabled": false
			}
		]
	}`
	trails := parseAWSCloudTrails(input)
	if len(trails) != 2 {
		t.Fatalf("expected 2 trails, got %d", len(trails))
	}
	if trails[0].Name != "main-trail" {
		t.Errorf("expected main-trail, got %s", trails[0].Name)
	}
	if trails[0].IsMultiRegion == nil || !*trails[0].IsMultiRegion {
		t.Error("expected main-trail to be multi-region")
	}
	if trails[0].LogValidation == nil || !*trails[0].LogValidation {
		t.Error("expected main-trail to have log validation")
	}
	if trails[0].IsActive != nil {
		t.Error("expected activity to remain unobserved until get-trail-status succeeds")
	}
	if trails[1].IsMultiRegion == nil || *trails[1].IsMultiRegion {
		t.Error("expected regional-trail to NOT be multi-region")
	}
}

func TestParseAWSCloudTrails_Empty(t *testing.T) {
	trails := parseAWSCloudTrails(`{"TrailList": []}`)
	if len(trails) != 0 {
		t.Errorf("expected 0 trails, got %d", len(trails))
	}
}

func TestParseAWSTrailStatus_Logging(t *testing.T) {
	if !parseAWSTrailStatus(`{"IsLogging": true}`) {
		t.Error("expected IsLogging=true")
	}
}

func TestParseAWSTrailStatus_NotLogging(t *testing.T) {
	if parseAWSTrailStatus(`{"IsLogging": false}`) {
		t.Error("expected IsLogging=false")
	}
}

func TestParseGCPLoggingSinks(t *testing.T) {
	input := `[
		{"name": "default-sink", "destination": "storage.googleapis.com/logs", "disabled": false},
		{"name": "disabled-sink", "destination": "bigquery.googleapis.com/...", "disabled": true}
	]`
	trails, active := parseGCPLoggingSinks(input)
	if len(trails) != 2 {
		t.Fatalf("expected 2 sinks, got %d", len(trails))
	}
	if active != 1 {
		t.Errorf("expected 1 active sink, got %d", active)
	}
	if trails[0].IsActive == nil || !*trails[0].IsActive {
		t.Error("expected default-sink to be active")
	}
	if trails[1].IsActive == nil || *trails[1].IsActive {
		t.Error("expected disabled-sink to be inactive")
	}
}

func TestParseAzureDiagnosticSettings(t *testing.T) {
	input := `[
		{"name": "diag-1", "logs": [{"enabled": true}, {"enabled": false}]},
		{"name": "diag-2", "logs": [{"enabled": false}]}
	]`
	trails, active := parseAzureDiagnosticSettings(input)
	if len(trails) != 2 {
		t.Fatalf("expected 2 settings, got %d", len(trails))
	}
	if active != 1 {
		t.Errorf("expected 1 active, got %d", active)
	}
}

func TestParseAWSCloudTrails_InvalidJSON(t *testing.T) {
	trails := parseAWSCloudTrails("bad json")
	if trails != nil {
		t.Error("expected nil for invalid JSON")
	}
}
