package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func writeSeed(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatalf("write seed %s: %v", name, err)
	}
}

func validSeed(payload string) string {
	return `defaults:
  vuln_type: sqli
  db_engine: postgres
  encoding: raw
  source: test
payloads:
  - technique: blind_time
    injection_surface: query
    evidence_type: timing
    risk: 3
    payload: |-
      ` + payload + `
    placeholders: [SLEEP_SECONDS]
    tags: [test]
`
}

func TestRunSeedgenMinimalFixture(t *testing.T) {
	dir := t.TempDir()
	outDB := filepath.Join(t.TempDir(), "payloads.sqlite")
	writeSeed(t, dir, "sqli.yaml", validSeed("' OR pg_sleep(SLEEP_SECONDS)--"))

	var out bytes.Buffer
	if err := runSeedgen(dir, outDB, &out); err != nil {
		t.Fatalf("runSeedgen: %v", err)
	}
	if !strings.Contains(out.String(), "Done: 1 payloads, 1 tags") {
		t.Fatalf("unexpected output: %s", out.String())
	}

	db, err := sql.Open("sqlite", outDB)
	if err != nil {
		t.Fatalf("open output db: %v", err)
	}
	defer db.Close()

	var vulnType, createdAt, placeholders string
	if err := db.QueryRow("SELECT vuln_type, created_at, placeholders FROM payloads").Scan(&vulnType, &createdAt, &placeholders); err != nil {
		t.Fatalf("query payload: %v", err)
	}
	if vulnType != "sqli" {
		t.Fatalf("expected sqli, got %s", vulnType)
	}
	if createdAt != fixedGeneratedAt {
		t.Fatalf("expected fixed timestamp %s, got %s", fixedGeneratedAt, createdAt)
	}
	if placeholders != `["SLEEP_SECONDS"]` {
		t.Fatalf("unexpected placeholders JSON: %s", placeholders)
	}
}

func TestRunSeedgenRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	outDB := filepath.Join(t.TempDir(), "payloads.sqlite")
	body := validSeed("' OR pg_sleep(SLEEP_SECONDS)--") + `
`
	writeSeed(t, dir, "a.yaml", body)
	writeSeed(t, dir, "b.yaml", body)

	err := runSeedgen(dir, outDB, nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate payload ID") {
		t.Fatalf("expected duplicate payload ID error, got %v", err)
	}
}

func TestRunSeedgenRejectsInvalidRisk(t *testing.T) {
	dir := t.TempDir()
	outDB := filepath.Join(t.TempDir(), "payloads.sqlite")
	writeSeed(t, dir, "bad.yaml", strings.Replace(validSeed("' OR 1=1--"), "risk: 3", "risk: 9", 1))

	err := runSeedgen(dir, outDB, nil)
	if err == nil || !strings.Contains(err.Error(), "risk must be 1-5") {
		t.Fatalf("expected invalid risk error, got %v", err)
	}
}

func TestRunSeedgenRejectsMissingRequiredField(t *testing.T) {
	dir := t.TempDir()
	outDB := filepath.Join(t.TempDir(), "payloads.sqlite")
	writeSeed(t, dir, "bad.yaml", strings.Replace(validSeed("' OR 1=1--"), "    evidence_type: timing\n", "", 1))

	err := runSeedgen(dir, outDB, nil)
	if err == nil || !strings.Contains(err.Error(), "evidence_type required") {
		t.Fatalf("expected missing evidence_type error, got %v", err)
	}
}

func TestRunSeedgenRejectsInvalidEnum(t *testing.T) {
	dir := t.TempDir()
	outDB := filepath.Join(t.TempDir(), "payloads.sqlite")
	writeSeed(t, dir, "bad.yaml", strings.Replace(validSeed("' OR 1=1--"), "technique: blind_time", "technique: nope", 1))

	err := runSeedgen(dir, outDB, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid enum values") {
		t.Fatalf("expected invalid enum error, got %v", err)
	}
}
