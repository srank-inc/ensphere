package templates

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestListTemplatesAndNames(t *testing.T) {
	summaries, err := ListTemplates()
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(summaries) == 0 {
		t.Fatal("expected templates")
	}
	names, err := TemplateNames()
	if err != nil {
		t.Fatalf("TemplateNames: %v", err)
	}
	if len(names) != len(summaries) {
		t.Fatalf("names=%d summaries=%d", len(names), len(summaries))
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("template names not sorted: %v", names)
	}
}

func TestGetTemplateInvalid(t *testing.T) {
	if _, err := GetTemplate("missing-template"); err == nil {
		t.Fatal("expected missing template error")
	}
}

func TestMaterializeToWriterAndDir(t *testing.T) {
	names, err := TemplateNames()
	if err != nil {
		t.Fatalf("TemplateNames: %v", err)
	}
	name := names[0]

	var buf bytes.Buffer
	if err := Materialize(name, "", &buf); err != nil {
		t.Fatalf("Materialize writer: %v", err)
	}
	if !strings.Contains(buf.String(), "--- ") {
		t.Fatalf("expected file separators, got %q", buf.String())
	}

	outDir := t.TempDir()
	if err := Materialize(name, outDir, nil); err != nil {
		t.Fatalf("Materialize dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "template.json")); err != nil {
		t.Fatalf("expected template.json materialized: %v", err)
	}
}

func TestMaterializeInvalidDoesNotCreateOutputDir(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "out")
	if err := Materialize("missing-template", outDir, nil); err == nil {
		t.Fatal("expected missing template error")
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("output dir should not be created for invalid template, stat err=%v", err)
	}
}
