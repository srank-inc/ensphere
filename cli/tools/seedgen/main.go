package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"gopkg.in/yaml.v3"

	"github.com/srank/ensphere/internal/enums"
)

const schema = `
CREATE TABLE IF NOT EXISTS payloads (
  id               TEXT PRIMARY KEY,
  vuln_type        TEXT NOT NULL,
  db_engine        TEXT,
  runtime          TEXT,
  technique        TEXT NOT NULL,
  injection_surface TEXT NOT NULL,
  content_type     TEXT,
  encoding         TEXT NOT NULL,
  string_boundary  TEXT,
  evidence_type    TEXT NOT NULL,
  risk             INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 5),
  payload          TEXT NOT NULL,
  placeholders     TEXT NOT NULL DEFAULT '[]',
  notes            TEXT NOT NULL DEFAULT '',
  source           TEXT NOT NULL DEFAULT '',
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payload_tags (
  payload_id TEXT NOT NULL,
  tag        TEXT NOT NULL,
  PRIMARY KEY (payload_id, tag),
  FOREIGN KEY (payload_id) REFERENCES payloads(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_payloads_lookup ON payloads(
  vuln_type, db_engine, runtime, technique,
  injection_surface, content_type, encoding, string_boundary, risk
);
CREATE INDEX IF NOT EXISTS idx_payload_tags_tag ON payload_tags(tag);
`

type SeedFile struct {
	Defaults SeedDefaults  `yaml:"defaults"`
	Payloads []SeedPayload `yaml:"payloads"`
}

type SeedDefaults struct {
	VulnType    string `yaml:"vuln_type"`
	DBEngine    string `yaml:"db_engine"`
	Runtime     string `yaml:"runtime"`
	ContentType string `yaml:"content_type"`
	Encoding    string `yaml:"encoding"`
	Source      string `yaml:"source"`
}

type SeedPayload struct {
	VulnType         string   `yaml:"vuln_type"`
	DBEngine         string   `yaml:"db_engine"`
	Runtime          string   `yaml:"runtime"`
	Technique        string   `yaml:"technique"`
	InjectionSurface string   `yaml:"injection_surface"`
	ContentType      string   `yaml:"content_type"`
	Encoding         string   `yaml:"encoding"`
	StringBoundary   string   `yaml:"string_boundary"`
	EvidenceType     string   `yaml:"evidence_type"`
	Risk             int      `yaml:"risk"`
	Payload          string   `yaml:"payload"`
	Placeholders     []string `yaml:"placeholders"`
	Notes            string   `yaml:"notes"`
	Source           string   `yaml:"source"`
	Tags             []string `yaml:"tags"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: seedgen <seeds-dir> <output.db>\n")
		os.Exit(1)
	}

	seedsDir := os.Args[1]
	outputPath := os.Args[2]

	// Remove existing DB
	os.Remove(outputPath)

	db, err := sql.Open("sqlite", outputPath)
	if err != nil {
		fatal("open db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		fatal("set journal mode: %v", err)
	}

	if _, err := db.Exec(schema); err != nil {
		fatal("create schema: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(seedsDir, "*.yaml"))
	if err != nil {
		fatal("glob seeds: %v", err)
	}
	if len(files) == 0 {
		fatal("no .yaml files found in %s", seedsDir)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	totalPayloads := 0
	totalTags := 0

	tx, err := db.Begin()
	if err != nil {
		fatal("begin tx: %v", err)
	}

	payloadStmt, err := tx.Prepare(`INSERT INTO payloads
		(id, vuln_type, db_engine, runtime, technique, injection_surface, content_type, encoding, string_boundary, evidence_type, risk, payload, placeholders, notes, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		fatal("prepare payload stmt: %v", err)
	}
	defer payloadStmt.Close()

	tagStmt, err := tx.Prepare(`INSERT INTO payload_tags (payload_id, tag) VALUES (?, ?)`)
	if err != nil {
		fatal("prepare tag stmt: %v", err)
	}
	defer tagStmt.Close()

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fatal("read %s: %v", file, err)
		}

		var seed SeedFile
		if err := yaml.Unmarshal(data, &seed); err != nil {
			fatal("parse %s: %v", file, err)
		}

		fmt.Printf("Processing %s (%d payloads)\n", filepath.Base(file), len(seed.Payloads))

		for i, p := range seed.Payloads {
			vulnType := coalesce(p.VulnType, seed.Defaults.VulnType)
			dbEngine := coalesce(p.DBEngine, seed.Defaults.DBEngine)
			runtime := coalesce(p.Runtime, seed.Defaults.Runtime)
			contentType := coalesce(p.ContentType, seed.Defaults.ContentType)
			encoding := coalesce(p.Encoding, seed.Defaults.Encoding)
			source := coalesce(p.Source, seed.Defaults.Source)

			if vulnType == "" {
				fatal("%s: payload %d: vuln_type required", filepath.Base(file), i)
			}
			if p.Technique == "" {
				fatal("%s: payload %d: technique required", filepath.Base(file), i)
			}
			if p.InjectionSurface == "" {
				fatal("%s: payload %d: injection_surface required", filepath.Base(file), i)
			}
			if p.EvidenceType == "" {
				fatal("%s: payload %d: evidence_type required", filepath.Base(file), i)
			}
			if p.Risk < 1 || p.Risk > 5 {
				fatal("%s: payload %d: risk must be 1-5, got %d", filepath.Base(file), i, p.Risk)
			}
			if p.Payload == "" {
				fatal("%s: payload %d: payload required", filepath.Base(file), i)
			}
			if encoding == "" {
				encoding = "raw"
			}

			// Validate enum values at build time
			if err := enums.ValidateSeedPayload(vulnType, dbEngine, runtime, p.Technique, p.InjectionSurface, encoding, p.StringBoundary, p.EvidenceType, filepath.Base(file), i); err != nil {
				fatal("%v", err)
			}

			id := generateID(vulnType, p.Technique, p.InjectionSurface, p.Payload)

			placeholdersJSON, _ := json.Marshal(p.Placeholders)
			if p.Placeholders == nil {
				placeholdersJSON = []byte("[]")
			}

			_, err = payloadStmt.Exec(
				id, vulnType, nullableStr(dbEngine), nullableStr(runtime),
				p.Technique, p.InjectionSurface, nullableStr(contentType),
				encoding, nullableStr(p.StringBoundary), p.EvidenceType,
				p.Risk, p.Payload, string(placeholdersJSON), p.Notes, source,
				now, now,
			)
			if err != nil {
				fatal("%s: payload %d: insert: %v", filepath.Base(file), i, err)
			}
			totalPayloads++

			for _, tag := range p.Tags {
				if _, err := tagStmt.Exec(id, tag); err != nil {
					fatal("%s: payload %d: tag %q: %v", filepath.Base(file), i, tag, err)
				}
				totalTags++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		fatal("commit: %v", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		fatal("switch journal mode: %v", err)
	}

	if _, err := db.Exec("VACUUM"); err != nil {
		fatal("vacuum: %v", err)
	}

	fmt.Printf("\nDone: %d payloads, %d tags → %s\n", totalPayloads, totalTags, outputPath)
}

func generateID(vulnType, technique, surface, payload string) string {
	h := sha256.Sum256([]byte(vulnType + "|" + technique + "|" + surface + "|" + payload))
	return fmt.Sprintf("%x", h[:8])
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "seedgen: "+format+"\n", args...)
	os.Exit(1)
}
