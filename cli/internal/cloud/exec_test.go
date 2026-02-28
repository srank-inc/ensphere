package cloud

import (
	"testing"
)

func TestRunCLI_EchoCommand(t *testing.T) {
	result := RunCLI("echo", []string{"test-output"}, 5)
	if result.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d; stderr: %s", result.ExitCode, result.Stderr)
	}
	if result.Stdout != "test-output\n" {
		t.Errorf("expected stdout 'test-output\\n', got %q", result.Stdout)
	}
	if result.ElapsedMs < 0 {
		t.Errorf("expected non-negative elapsed, got %d", result.ElapsedMs)
	}
}

func TestCheckCLIInstalled_Echo(t *testing.T) {
	err := CheckCLIInstalled("echo")
	if err != nil {
		t.Fatalf("expected echo to be installed: %v", err)
	}
}

func TestCheckCLIInstalled_Missing(t *testing.T) {
	err := CheckCLIInstalled("nonexistent-binary-xyz-12345")
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestRunCLI_NonZeroExit(t *testing.T) {
	result := RunCLI("false", nil, 5)
	if result.ExitCode == 0 {
		t.Fatal("expected non-zero exit code from 'false'")
	}
}
