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

func appendRawEvidenceLine(t *testing.T, path string, entry Entry) {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal raw evidence: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open raw evidence file: %v", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write raw evidence line: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close raw evidence file: %v", err)
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
	for i, e := range entries {
		want := "EVID-00" + string(rune('1'+i))
		if e.ID != want {
			t.Fatalf("entry %d expected ID %s, got %s", i, want, e.ID)
		}
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
	writeEntries(t, path, testEntry("a", "baseline"), testEntry("b", "probe"), testEntry("c", "payload"))

	id, err := NextID(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "EVID-004" {
		t.Fatalf("expected EVID-004, got %s", id)
	}
}

func TestNextID_UsesMaxNumericID(t *testing.T) {
	path := tempEvidenceFile(t)
	appendRawEvidenceLine(t, path, testEntry("a", "baseline").WithID("EVID-001"))
	appendRawEvidenceLine(t, path, testEntry("b", "probe").WithID("EVID-010"))
	appendRawEvidenceLine(t, path, testEntry("legacy", "payload"))

	id, err := NextID(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "EVID-011" {
		t.Fatalf("expected EVID-011, got %s", id)
	}
}

func TestWriterAssignsIDAndReturnsWrittenEntry(t *testing.T) {
	path := tempEvidenceFile(t)
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	written, err := w.WriteEntry(testEntry("sqli", "probe"))
	if err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if written.ID != "EVID-001" {
		t.Fatalf("expected assigned ID EVID-001, got %s", written.ID)
	}
	if written.Hash == "" {
		t.Fatal("expected returned entry to include hash")
	}

	entries, _, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if entries[0].ID != written.ID || entries[0].Hash != written.Hash {
		t.Fatalf("written entry mismatch: file=%+v returned=%+v", entries[0], written)
	}
}

func TestWriterContinuesAfterLegacyMissingID(t *testing.T) {
	path := tempEvidenceFile(t)
	e1 := testEntry("a", "baseline").WithID("EVID-010")
	e1.Hash = ComputeHash(e1)
	appendRawEvidenceLine(t, path, e1)
	e2 := testEntry("legacy", "probe")
	e2.PrevHash = e1.Hash
	e2.Hash = ComputeHash(e2)
	appendRawEvidenceLine(t, path, e2)

	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	written, err := w.WriteEntry(testEntry("new", "payload"))
	if err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if written.ID != "EVID-011" {
		t.Fatalf("expected EVID-011, got %s", written.ID)
	}
	if written.PrevHash != e2.Hash {
		t.Fatalf("expected prev_hash %s, got %s", e2.Hash, written.PrevHash)
	}
}

func TestWriterRejectsDuplicateIDs(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path, testEntry("a", "baseline").WithID("EVID-001"))

	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if err := w.Write(testEntry("b", "probe").WithID("EVID-001")); err == nil {
		t.Fatal("expected duplicate ID error")
	}
}

func TestNewWriterRejectsExistingDuplicateIDs(t *testing.T) {
	path := tempEvidenceFile(t)
	appendRawEvidenceLine(t, path, testEntry("a", "baseline").WithID("EVID-001"))
	appendRawEvidenceLine(t, path, testEntry("b", "probe").WithID("EVID-001"))

	if _, err := NewWriter(path); err == nil {
		t.Fatal("expected existing duplicate ID error")
	}
}

func TestWriterRejectsInvalidResult(t *testing.T) {
	path := tempEvidenceFile(t)
	w, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()
	if err := w.Write(testEntry("sqli", "confirmed")); err == nil {
		t.Fatal("expected invalid result error")
	}
}

func TestWriterLockContention(t *testing.T) {
	path := tempEvidenceFile(t)
	w1, err := NewWriter(path)
	if err != nil {
		t.Fatalf("NewWriter w1: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		w2, err := NewWriter(path)
		if err != nil {
			errCh <- err
			return
		}
		errCh <- w2.Close()
	}()

	select {
	case err := <-errCh:
		t.Fatalf("second writer should wait for lock, got early result: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if err := w1.Close(); err != nil {
		t.Fatalf("Close w1: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("second writer after lock release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second writer did not acquire lock after release")
	}
}

func TestHashChainIntegrity(t *testing.T) {
	path := tempEvidenceFile(t)
	writeEntries(t, path, testEntry("a", "baseline"), testEntry("b", "probe"), testEntry("c", "payload"))

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
	e1 := testEntry("a", "baseline").WithID("EVID-001")
	e2 := testEntry("b", "probe").WithID("EVID-002")
	e3 := testEntry("c", "payload").WithID("EVID-003")
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

func TestRedactSecrets_BearerBase64WithPlus(t *testing.T) {
	input := "Authorization: Bearer abc+def/ghi=="
	result := RedactSecrets(input)
	if strings.Contains(result, "def") {
		t.Fatalf("expected full bearer token to be redacted, got %s", result)
	}
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

	e1 := Entry{ProbeType: "sqli", Result: "baseline", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := ew.Write(e1); err != nil {
		t.Fatal(err)
	}
	e2 := Entry{ProbeType: "xss", Result: "probe", Timestamp: time.Now().UTC().Format(time.RFC3339)}
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
	e3 := Entry{ProbeType: "csrf", Result: "payload", Timestamp: time.Now().UTC().Format(time.RFC3339)}
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
