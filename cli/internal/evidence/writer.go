package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	lockRetryInterval = 50 * time.Millisecond
	lockTimeout       = 5 * time.Second
)

// Writer appends evidence entries to a JSONL file.
type Writer struct {
	mu       sync.Mutex
	file     *os.File
	enc      *json.Encoder
	lastHash string
	nextSeq  int
	ids      map[string]bool
	path     string
	lockPath string
	lockFile *os.File
	closed   bool
}

// NewWriter creates a JSONL writer that appends to the specified file.
// Creates the file if it doesn't exist. Recovers last hash from existing entries
// for chain continuity.
func NewWriter(path string) (*Writer, error) {
	lockPath := path + ".lock"
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		return nil, err
	}

	entries, err := readExistingEntries(path)
	if err != nil {
		_ = releaseLock(lockFile, lockPath)
		return nil, err
	}

	lastHash := ""
	maxID := 0
	ids := make(map[string]bool)
	for _, e := range entries {
		if e.Hash != "" {
			lastHash = e.Hash
		}
		n, ok := parseEvidenceID(e.ID)
		if !ok {
			_ = releaseLock(lockFile, lockPath)
			return nil, fmt.Errorf("invalid evidence ID %q in existing file", e.ID)
		}
		if ids[e.ID] {
			_ = releaseLock(lockFile, lockPath)
			return nil, fmt.Errorf("duplicate evidence ID %q in existing file", e.ID)
		}
		ids[e.ID] = true
		if n > maxID {
			maxID = n
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		_ = releaseLock(lockFile, lockPath)
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	return &Writer{
		file:     f,
		enc:      json.NewEncoder(f),
		lastHash: lastHash,
		nextSeq:  maxID + 1,
		ids:      ids,
		path:     path,
		lockPath: lockPath,
		lockFile: lockFile,
	}, nil
}

// Write appends an evidence entry as a single JSON line with hash chain.
func (w *Writer) Write(e Entry) error {
	_, err := w.WriteEntry(e)
	return err
}

// WriteEntry appends an evidence entry and returns the ID/hash-assigned entry.
func (w *Writer) WriteEntry(e Entry) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return Entry{}, fmt.Errorf("evidence writer for %s is closed", w.path)
	}
	if err := ValidateResult(e.Result); err != nil {
		return Entry{}, err
	}
	autoAssigned := false
	if e.ID == "" {
		e.ID = fmt.Sprintf("EVID-%03d", w.nextSeq)
		autoAssigned = true
	} else {
		if _, ok := parseEvidenceID(e.ID); !ok {
			return Entry{}, fmt.Errorf("invalid evidence ID %q", e.ID)
		}
		if w.ids[e.ID] {
			return Entry{}, fmt.Errorf("duplicate evidence ID %q", e.ID)
		}
	}

	e.PrevHash = w.lastHash
	e.Hash = ComputeHash(e)
	if err := w.enc.Encode(e); err != nil {
		return Entry{}, fmt.Errorf("write evidence entry: %w", err)
	}
	if autoAssigned {
		w.nextSeq++
	}
	w.ids[e.ID] = true
	w.lastHash = e.Hash
	return e, nil
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	fileErr := w.file.Close()
	lockErr := releaseLock(w.lockFile, w.lockPath)
	if fileErr != nil {
		return fileErr
	}
	return lockErr
}

func readExistingEntries(path string) ([]Entry, error) {
	entries, _, err := ReadAll(path)
	if err == nil {
		return entries, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return nil, err
}

func acquireLock(path string) (*os.File, error) {
	deadline := time.Now().Add(lockTimeout)
	var lastErr error
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			return f, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create evidence lock %s: %w", path, err)
		}
		lastErr = err
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("acquire evidence lock %s: timed out after %s: %w", path, lockTimeout, lastErr)
		}
		time.Sleep(lockRetryInterval)
	}
}

func releaseLock(f *os.File, path string) error {
	var closeErr error
	if f != nil {
		closeErr = f.Close()
	}
	removeErr := os.Remove(path)
	if removeErr != nil && !os.IsNotExist(removeErr) {
		if closeErr != nil {
			return fmt.Errorf("close lock: %v; remove lock: %w", closeErr, removeErr)
		}
		return fmt.Errorf("remove evidence lock: %w", removeErr)
	}
	return closeErr
}

func parseEvidenceID(id string) (int, bool) {
	if !strings.HasPrefix(id, "EVID-") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "EVID-"))
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}
