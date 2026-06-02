package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestRunScanPositiveMatchRedactsContextAndLabelsDepth(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.js", `const token = "Authorization: Bearer secret-token";
function render(input) {
  node.innerHTML = input;
}`)

	result, err := RunScan(ScanConfig{Directory: root, Categories: []string{"xss"}, ContextLines: 2})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if result.AnalysisDepth != AnalysisDepthPatternMatch {
		t.Fatalf("expected analysis depth %s, got %s", AnalysisDepthPatternMatch, result.AnalysisDepth)
	}
	if result.TotalMatches == 0 {
		t.Fatal("expected at least one match")
	}
	match := result.Matches[0]
	if match.File != "app.js" || match.Category != "xss" || match.MatchType != "" {
		t.Fatalf("unexpected match: %+v", match)
	}
	if strings.Contains(match.Context, "secret-token") || !strings.Contains(match.Context, "[REDACTED]") {
		t.Fatalf("expected redacted context, got %q", match.Context)
	}
}

func TestRunScanNoMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.js", "console.log('ok')\n")

	result, err := RunScan(ScanConfig{Directory: root, Categories: []string{"xss"}, ContextLines: 2})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if result.TotalMatches != 0 || len(result.Matches) != 0 || len(result.Summary) != 0 {
		t.Fatalf("expected empty result, got %+v", result)
	}
}

func TestRunScanExcludesDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "src/app.js", "node.innerHTML = input\n")
	writeFile(t, root, "ignored/app.js", "node.innerHTML = input\n")

	result, err := RunScan(ScanConfig{
		Directory:    root,
		Categories:   []string{"xss"},
		Excludes:     []string{"ignored/**"},
		ContextLines: 2,
	})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if result.TotalMatches != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", result.TotalMatches, result.Matches)
	}
	if result.Matches[0].File != filepath.Join("src", "app.js") {
		t.Fatalf("expected src/app.js, got %s", result.Matches[0].File)
	}
}

func TestRunScanExtensionOverride(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "template.custom", "node.innerHTML = input\n")

	result, err := RunScan(ScanConfig{
		Directory:    root,
		Categories:   []string{"xss"},
		Extensions:   []string{"custom"},
		ContextLines: 1,
	})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if result.TotalMatches == 0 {
		t.Fatal("expected extension override to scan .custom file")
	}
}

func TestRunScanAbsenceRule(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.tf", `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}`)

	result, err := RunScan(ScanConfig{Directory: root, AbsenceCheck: true, ContextLines: 1})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	found := false
	for _, match := range result.Matches {
		if match.MatchType == "absence" && match.Category == "iac_terraform" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected iac_terraform absence match, got %+v", result.Matches)
	}
}

func TestRunScanSortsMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b.js", "node.innerHTML = input\n")
	writeFile(t, root, "a.js", "node.innerHTML = input\n")

	result, err := RunScan(ScanConfig{Directory: root, Categories: []string{"xss"}, ContextLines: 0})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if len(result.Matches) < 2 {
		t.Fatalf("expected at least two matches, got %+v", result.Matches)
	}
	if result.Matches[0].File > result.Matches[1].File {
		t.Fatalf("matches not sorted: %+v", result.Matches[:2])
	}
}

func TestRunScanContextBounds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.js", "node.innerHTML = input\n")

	if _, err := RunScan(ScanConfig{Directory: root, Categories: []string{"xss"}, ContextLines: -1}); err == nil {
		t.Fatal("expected negative context line error")
	}
	if _, err := RunScan(ScanConfig{Directory: root, Categories: []string{"xss"}, ContextLines: 6}); err == nil {
		t.Fatal("expected too-large context line error")
	}
}
