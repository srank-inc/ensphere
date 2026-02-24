package payloads

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed payloads.sqlite
var embeddedDB embed.FS

// Open extracts the embedded SQLite database to a temp file and opens it read-only.
// The caller must call the returned cleanup function when done.
func Open() (*sql.DB, func(), error) {
	data, err := embeddedDB.ReadFile("payloads.sqlite")
	if err != nil {
		return nil, nil, fmt.Errorf("read embedded db: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "ensphere-db-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp dir: %w", err)
	}

	dbPath := filepath.Join(tmpDir, "payloads.sqlite")
	if err := os.WriteFile(dbPath, data, 0400); err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("write temp db: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?mode=ro&_journal_mode=OFF")
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, nil, fmt.Errorf("open sqlite: %w", err)
	}

	cleanup := func() {
		conn.Close()
		os.RemoveAll(tmpDir)
	}

	return conn, cleanup, nil
}
