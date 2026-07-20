package cloud

import (
	"testing"
)

func TestParseAWSLambdaFunctions(t *testing.T) {
	input := `{
		"Functions": [
			{
				"FunctionName": "api-handler",
				"Runtime": "nodejs18.x",
				"VpcConfig": {"SubnetIds": ["subnet-123"]},
				"Environment": {"Variables": {"DB_PASSWORD": "secret", "APP_NAME": "test"}}
			},
			{
				"FunctionName": "no-auth-func",
				"Runtime": "python3.11",
				"FunctionUrlConfig": {"AuthType": "NONE"},
				"Environment": {"Variables": {"API_KEY": "abc123"}}
			},
			{
				"FunctionName": "iam-auth-func",
				"Runtime": "go1.x",
				"FunctionUrlConfig": {"AuthType": "AWS_IAM"}
			}
		]
	}`
	functions, patterns, endpointConfiguredCount := parseAWSLambdaFunctions(input)
	if len(functions) != 3 {
		t.Fatalf("expected 3 functions, got %d", len(functions))
	}
	if endpointConfiguredCount != 2 {
		t.Errorf("expected 2 functions with endpoint configurations, got %d", endpointConfiguredCount)
	}
	if len(patterns) == 0 {
		t.Error("expected at least 1 env var secret pattern match")
	}
	// VPC check
	if functions[0].VPCAttached == nil || !*functions[0].VPCAttached {
		t.Error("expected first function to be VPC attached")
	}
	// Endpoint configuration check
	if functions[1].EndpointConfigured == nil || !*functions[1].EndpointConfigured {
		t.Error("expected second function to have endpoint configuration")
	}
	if functions[2].EndpointConfigured == nil || !*functions[2].EndpointConfigured || functions[2].EndpointAuthMode != "AWS_IAM" {
		t.Error("expected third function to record an AWS_IAM endpoint configuration")
	}
}

func TestParseAWSLambdaFunctions_Empty(t *testing.T) {
	functions, patterns, endpointConfiguredCount := parseAWSLambdaFunctions(`{"Functions": []}`)
	if len(functions) != 0 {
		t.Errorf("expected 0 functions, got %d", len(functions))
	}
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(patterns))
	}
	if endpointConfiguredCount != 0 {
		t.Errorf("expected 0 configured endpoints, got %d", endpointConfiguredCount)
	}
}

func TestParseGCPFunctions(t *testing.T) {
	input := `[
		{
			"name": "projects/p/locations/us/functions/my-func",
			"runtime": "python39",
			"httpsTrigger": {"url": "https://..."},
			"ingressSettings": "ALLOW_ALL",
			"environmentVariables": {"DATABASE_URL": "postgres://..."}
		},
		{
			"name": "projects/p/locations/us/functions/internal-func",
			"runtime": "nodejs16",
			"httpsTrigger": {"url": "https://..."},
			"ingressSettings": "ALLOW_INTERNAL_ONLY"
		}
	]`
	functions, patterns, endpointConfiguredCount := parseGCPFunctions(input)
	if len(functions) != 2 {
		t.Fatalf("expected 2 functions, got %d", len(functions))
	}
	if endpointConfiguredCount != 2 {
		t.Errorf("expected 2 configured HTTPS endpoints, got %d", endpointConfiguredCount)
	}
	if len(patterns) == 0 {
		t.Error("expected at least 1 pattern for DATABASE_URL")
	}
}

func TestParseGCPCloudRunServices(t *testing.T) {
	input := `[
		{"metadata": {"name": "web-app"}, "status": {"url": "https://web-app.run.app"}},
		{"metadata": {"name": "internal"}, "status": {"url": ""}}
	]`
	functions, endpointConfiguredCount := parseGCPCloudRunServices(input)
	if len(functions) != 2 {
		t.Fatalf("expected 2 services, got %d", len(functions))
	}
	if endpointConfiguredCount != 1 {
		t.Errorf("expected 1 configured endpoint, got %d", endpointConfiguredCount)
	}
}

func TestParseAzureFunctionApps(t *testing.T) {
	input := `[
		{"name": "my-func-app", "defaultHostName": "my-func-app.azurewebsites.net", "httpsOnly": true, "state": "Running"},
		{"name": "stopped-app", "defaultHostName": "", "httpsOnly": false, "state": "Stopped"}
	]`
	functions := parseAzureFunctionApps(input)
	if len(functions) != 2 {
		t.Fatalf("expected 2 function apps, got %d", len(functions))
	}
	if functions[0].EndpointConfigured == nil || !*functions[0].EndpointConfigured {
		t.Error("expected first app to have endpoint configuration")
	}
	if functions[1].EndpointConfigured == nil || *functions[1].EndpointConfigured {
		t.Error("expected second app to NOT have endpoint configuration")
	}
}

func TestParseAWSLambdaFunctions_InvalidJSON(t *testing.T) {
	functions, patterns, endpointConfiguredCount := parseAWSLambdaFunctions("not json")
	if functions != nil {
		t.Error("expected nil functions for invalid JSON")
	}
	if patterns != nil {
		t.Error("expected nil patterns for invalid JSON")
	}
	if endpointConfiguredCount != 0 {
		t.Errorf("expected 0 configured endpoints for invalid JSON, got %d", endpointConfiguredCount)
	}
}
