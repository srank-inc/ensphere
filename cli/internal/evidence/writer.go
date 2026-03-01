package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Writer appends evidence entries to a JSONL file.
type Writer struct {
	mu       sync.Mutex
	file     *os.File
	enc      *json.Encoder
	lastHash string
}

// NewWriter creates a JSONL writer that appends to the specified file.
// Creates the file if it doesn't exist. Recovers last hash from existing entries
// for chain continuity.
func NewWriter(path string) (*Writer, error) {
	// Read existing entries to recover last hash for chain continuity
	var lastHash string
	if entries, _, err := ReadAll(path); err == nil && len(entries) > 0 {
		lastHash = entries[len(entries)-1].Hash
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	return &Writer{
		file:     f,
		enc:      json.NewEncoder(f),
		lastHash: lastHash,
	}, nil
}

// Write appends an evidence entry as a single JSON line with hash chain.
func (w *Writer) Write(e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	e.PrevHash = w.lastHash
	e.Hash = ComputeHash(e)
	w.lastHash = e.Hash
	return w.enc.Encode(e)
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
