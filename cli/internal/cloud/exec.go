package cloud

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// CLIResult holds the output of a CLI command execution.
type CLIResult struct {
	Command   string `json:"command"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	ElapsedMs int64  `json:"elapsed_ms"`
}

// RunCLI executes a CLI command with timeout and returns structured result.
func RunCLI(name string, args []string, timeoutSec int) CLIResult {
	if timeoutSec < 1 {
		timeoutSec = 30
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start).Milliseconds()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return CLIResult{
		Command:   fmt.Sprintf("%s %s", name, joinArgs(args)),
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		ElapsedMs: elapsed,
	}
}

// CheckCLIInstalled returns error if the CLI binary is not in PATH.
func CheckCLIInstalled(name string) error {
	_, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s not found in PATH: %w", name, err)
	}
	return nil
}

func joinArgs(args []string) string {
	result := ""
	for i, a := range args {
		if i > 0 {
			result += " "
		}
		result += a
	}
	return result
}
