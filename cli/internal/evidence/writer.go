package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Writer appends evidence entries to a JSONL file.
type Writer struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewWriter creates a JSONL writer that appends to the specified file.
// Creates the file if it doesn't exist.
func NewWriter(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	return &Writer{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Write appends an evidence entry as a single JSON line.
func (w *Writer) Write(e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(e)
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
