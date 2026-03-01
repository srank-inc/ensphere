package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testEntry(probeType, result string) Entry {
	return NewEntry(probeType, "test_technique", "http://test.com", "param", 200, "100ms", result, "test notes")
}

func tempEvidenceFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "evidence.jsonl")
}

func writeEntries(t *testing.T, path string, entries ...Entry) {
	t.Helper()
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for _, e := range entries {
		if err := w.Write(e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestWriteAndReadBack(t *testing.T) {
	path := tempEvidenceFile(t)

	e1 := testEntry("sqli", "baseline")
	e2 := testEntry("xss", "probe")
	e3 := testEntry("cmdi", "baseline")
	writeEntries(t, path, e1, e2, e3)

	entries, _, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].ProbeType != "sqli" {
		t.Fatalf("expected sqli, got %s", entries[0].ProbeType)
	}
	if entries[1].ProbeType != "xss" {
		t.Fatalf("expected xss, got %s", entries[1].ProbeType)
	}
	if entries[2].ProbeType != "cmdi" {
		t.Fatalf("expected cmdi, got %s", entries[2].ProbeType)
	}
}

func TestNextID_EmptyFile(t *testing.T) {
	path := tempEvidenceFile(t)
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("create empty file: %v", err)
	}

	id, err := NextID(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "EVID-001" {
		t.Fatalf("expected EVID-001, got %s", id)
	}
}

func TestNextID_NonexistentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")

	id, err := NextID(path)
	if err != nil {
		t.Fatalf("NextID on nonexistent file should return EVID-001, got error: %v", err)
	}
	if id != "EVID-001" {
		t.Fatalf("expected EVID-001, got %s", id)
	}
}

func TestNextID_ExistingEntries(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path, testEntry("a", "r1"), testEntry("b", "r2"), testEntry("c", "r3"))

	id, err := NextID(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "EVID-004" {
		t.Fatalf("expected EVID-004, got %s", id)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path, testEntry("a", "r1"), testEntry("b", "r2"), testEntry("c", "r3"))

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected Valid chain, got invalid at %s: %s", result.BrokenAt, result.Error)
	}
	if result.EntriesChecked != 3 {
		t.Fatalf("expected 3 entries checked, got %d", result.EntriesChecked)
	}
}

func TestHashChainTamper(t *testing.T) {
	path := tempEvidenceFile(t)

	// Use entries with IDs so BrokenAt is populated
	e1 := testEntry("a", "r1").WithID("EVID-001")
	e2 := testEntry("b", "r2").WithID("EVID-002")
	e3 := testEntry("c", "r3").WithID("EVID-003")
	writeEntries(t, path, e1, e2, e3)

	// Read file, tamper with middle entry's hash, rewrite
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Tamper: modify the hash field of the middle entry
	var entry Entry
	if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	entry.Hash = "tampered_hash_value"
	tampered, _ := json.Marshal(entry)
	lines[1] = string(tampered)

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatal("expected invalid chain after tampering")
	}
	if result.BrokenAt == "" {
		t.Fatal("expected BrokenAt to be populated")
	}
}

func TestHashChainEmpty(t *testing.T) {
	path := tempEvidenceFile(t)
	// Create empty file
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("create empty file: %v", err)
	}

	result, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid chain for empty file")
	}
	if result.EntriesChecked != 0 {
		t.Fatalf("expected 0 entries checked, got %d", result.EntriesChecked)
	}
}

func TestRedactSecrets_JWT(t *testing.T) {
	input := "token=eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiMSJ9.abc123"
	result := RedactSecrets(input)
	if strings.Contains(result, "eyJ") {
		t.Fatalf("expected JWT to be redacted, got %s", result)
	}
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatal("expected [REDACTED] in output")
	}
}

func TestRedactSecrets_Bearer(t *testing.T) {
	input := "Authorization: Bearer mytoken123"
	result := RedactSecrets(input)
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatal("expected [REDACTED] in output")
	}
}

func TestRedactSecrets_QueryParam(t *testing.T) {
	input := "https://api.com?password=secret123&name=foo"
	result := RedactSecrets(input)
	if !strings.Contains(result, "[REDACTED]") {
		t.Fatal("expected [REDACTED] in output")
	}
	if !strings.Contains(result, "name=foo") {
		t.Fatal("expected name=foo to remain unredacted")
	}
}

func TestRedactSecrets_NoSecrets(t *testing.T) {
	input := "https://api.com/path?page=1"
	result := RedactSecrets(input)
	if result != input {
		t.Fatalf("expected unchanged output, got %s", result)
	}
}

func TestComputeHash_Deterministic(t *testing.T) {
	e := testEntry("sqli", "probe")
	hash1 := ComputeHash(e)
	hash2 := ComputeHash(e)
	if hash1 != hash2 {
		t.Fatalf("expected deterministic hash, got %s and %s", hash1, hash2)
	}
}

func TestComputeHash_DifferentEntries(t *testing.T) {
	e1 := testEntry("sqli", "probe")
	e2 := testEntry("xss", "probe")
	hash1 := ComputeHash(e1)
	hash2 := ComputeHash(e2)
	if hash1 == hash2 {
		t.Fatal("expected different hashes for different entries")
	}
}

func TestReadFiltered_ByProbeType(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path,
		testEntry("sqli", "baseline"),
		testEntry("xss", "probe"),
		testEntry("sqli", "probe"),
	)

	entries, err := ReadFiltered(path, EntryFilter{ProbeType: "sqli"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 sqli entries, got %d", len(entries))
	}
	for _, e := range entries {
		if e.ProbeType != "sqli" {
			t.Fatalf("expected ProbeType sqli, got %s", e.ProbeType)
		}
	}
}

func TestReadFiltered_ByResult(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path,
		testEntry("sqli", "baseline"),
		testEntry("xss", "probe"),
		testEntry("cmdi", "probe"),
	)

	entries, err := ReadFiltered(path, EntryFilter{Result: "probe"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 probe entries, got %d", len(entries))
	}
}

func TestCountByResult(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path,
		testEntry("sqli", "baseline"),
		testEntry("xss", "probe"),
		testEntry("cmdi", "baseline"),
		testEntry("lfi", "probe"),
		testEntry("xxe", "probe"),
	)

	counts, err := CountByResult(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if counts["baseline"] != 2 {
		t.Fatalf("expected 2 baseline, got %d", counts["baseline"])
	}
	if counts["probe"] != 3 {
		t.Fatalf("expected 3 probe, got %d", counts["probe"])
	}
}

func TestReadAll_MalformedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")

	ew, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	e1 := Entry{ProbeType: "sqli", Result: "completed", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := ew.Write(e1); err != nil {
		t.Fatal(err)
	}
	e2 := Entry{ProbeType: "xss", Result: "completed", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := ew.Write(e2); err != nil {
		t.Fatal(err)
	}
	if err := ew.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{this is not valid json}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	ew2, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	e3 := Entry{ProbeType: "csrf", Result: "completed", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := ew2.Write(e3); err != nil {
		t.Fatal(err)
	}
	if err := ew2.Close(); err != nil {
		t.Fatal(err)
	}

	entries, skipped, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if skipped != 1 {
		t.Errorf("expected 1 skipped line, got %d", skipped)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 valid entries, got %d", len(entries))
	}
}
