package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/srank/ensphere/internal/enums"
)

const fixedGeneratedAt = "1970-01-01T00:00:00Z"

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

	if err := runSeedgen(os.Args[1], os.Args[2], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "seedgen: %v\n", err)
		os.Exit(1)
	}
}

func runSeedgen(seedsDir, outputPath string, out io.Writer) error {
	if out == nil {
		out = io.Discard
	}

	// Remove existing DB
	if err := os.Remove(outputPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove existing db: %w", err)
	}

	db, err := sql.Open("sqlite", outputPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		return fmt.Errorf("set journal mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA synchronous=OFF"); err != nil {
		return fmt.Errorf("set synchronous mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	files, err := filepath.Glob(filepath.Join(seedsDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("glob seeds: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return fmt.Errorf("no .yaml files found in %s", seedsDir)
	}

	now := fixedGeneratedAt
	totalPayloads := 0
	totalTags := 0
	seenIDs := make(map[string]string)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	payloadStmt, err := tx.Prepare(`INSERT INTO payloads
		(id, vuln_type, db_engine, runtime, technique, injection_surface, content_type, encoding, string_boundary, evidence_type, risk, payload, placeholders, notes, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare payload stmt: %w", err)
	}
	defer payloadStmt.Close()

	tagStmt, err := tx.Prepare(`INSERT INTO payload_tags (payload_id, tag) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare tag stmt: %w", err)
	}
	defer tagStmt.Close()

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}

		var seed SeedFile
		if err := yaml.Unmarshal(data, &seed); err != nil {
			return fmt.Errorf("parse %s: %w", file, err)
		}

		fmt.Fprintf(out, "Processing %s (%d payloads)\n", filepath.Base(file), len(seed.Payloads))

		for i, p := range seed.Payloads {
			sourceRef := fmt.Sprintf("%s: payload %d", filepath.Base(file), i)
			vulnType := coalesce(p.VulnType, seed.Defaults.VulnType)
			dbEngine := coalesce(p.DBEngine, seed.Defaults.DBEngine)
			runtime := coalesce(p.Runtime, seed.Defaults.Runtime)
			contentType := coalesce(p.ContentType, seed.Defaults.ContentType)
			encoding := coalesce(p.Encoding, seed.Defaults.Encoding)
			source := coalesce(p.Source, seed.Defaults.Source)

			if vulnType == "" {
				return fmt.Errorf("%s: vuln_type required", sourceRef)
			}
			if p.Technique == "" {
				return fmt.Errorf("%s: technique required", sourceRef)
			}
			if p.InjectionSurface == "" {
				return fmt.Errorf("%s: injection_surface required", sourceRef)
			}
			if p.EvidenceType == "" {
				return fmt.Errorf("%s: evidence_type required", sourceRef)
			}
			if p.Risk < 1 || p.Risk > 5 {
				return fmt.Errorf("%s: risk must be 1-5, got %d", sourceRef, p.Risk)
			}
			if p.Payload == "" {
				return fmt.Errorf("%s: payload required", sourceRef)
			}
			if encoding == "" {
				encoding = "raw"
			}

			// Validate enum values at build time
			if err := enums.ValidateSeedPayload(vulnType, dbEngine, runtime, p.Technique, p.InjectionSurface, encoding, p.StringBoundary, p.EvidenceType, filepath.Base(file), i); err != nil {
				return err
			}

			id := generateID(vulnType, p.Technique, p.InjectionSurface, p.Payload)
			if previous, ok := seenIDs[id]; ok {
				return fmt.Errorf("%s: duplicate payload ID %s already generated by %s", sourceRef, id, previous)
			}
			seenIDs[id] = sourceRef

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
				return fmt.Errorf("%s: insert: %w", sourceRef, err)
			}
			totalPayloads++

			for _, tag := range p.Tags {
				if _, err := tagStmt.Exec(id, tag); err != nil {
					return fmt.Errorf("%s: tag %q: %w", sourceRef, tag, err)
				}
				totalTags++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true

	if _, err := db.Exec("PRAGMA journal_mode=DELETE"); err != nil {
		return fmt.Errorf("switch journal mode: %w", err)
	}

	if _, err := db.Exec("VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}

	fmt.Fprintf(out, "\nDone: %d payloads, %d tags -> %s\n", totalPayloads, totalTags, outputPath)
	return nil
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
