package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	ResultBaseline   = "baseline"
	ResultProbe      = "probe"
	ResultPayload    = "payload"
	ResultControl    = "control"
	ResultCallback   = "callback"
	ResultManualNote = "manual_note"
)

var allowedResults = map[string]bool{
	ResultBaseline:   true,
	ResultProbe:      true,
	ResultPayload:    true,
	ResultControl:    true,
	ResultCallback:   true,
	ResultManualNote: true,
}

// ValidResult reports whether result is an allowed factual evidence stage.
func ValidResult(result string) bool {
	return allowedResults[result]
}

// ValidateResult rejects CLI-owned security judgment labels in evidence Result.
func ValidateResult(result string) error {
	if ValidResult(result) {
		return nil
	}
	return fmt.Errorf("invalid evidence result %q: use one of baseline, probe, payload, control, callback, manual_note", result)
}

// Entry represents a single evidence record written to the JSONL file.
type Entry struct {
	ID             string `json:"id"`                        // EVID-001, EVID-002, etc.
	SessionNumber  int    `json:"session_number,omitempty"`  // Which session generated this
	FindingRef     string `json:"finding_ref,omitempty"`     // VULN-001 cross-reference
	ScreenshotPath string `json:"screenshot_path,omitempty"` // Playwright screenshot ref
	Timestamp      string `json:"timestamp"`
	ProbeType      string `json:"probe_type"`
	Technique      string `json:"technique"`
	URL            string `json:"url"`
	Param          string `json:"param,omitempty"`
	RequestHash    string `json:"request_hash,omitempty"`
	ResponseHash   string `json:"response_hash,omitempty"`
	StatusCode     int    `json:"status_code"`
	Duration       string `json:"duration"`
	Result         string `json:"result"`
	Notes          string `json:"notes,omitempty"`
	PrevHash       string `json:"prev_hash,omitempty"` // Hash of previous entry in chain
	Hash           string `json:"hash,omitempty"`      // SHA256 of this entry (excluding Hash field)
}

// NewEntry creates an Entry with the current timestamp.
func NewEntry(probeType, technique, url, param string, statusCode int, duration string, result, notes string) Entry {
	return Entry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ProbeType:  probeType,
		Technique:  technique,
		URL:        RedactSecrets(url),
		Param:      param,
		StatusCode: statusCode,
		Duration:   duration,
		Result:     result,
		Notes:      RedactSecrets(notes),
	}
}

// WithHashes sets the request and response hashes on the entry.
func (e Entry) WithHashes(reqHash, respHash string) Entry {
	e.RequestHash = reqHash
	e.ResponseHash = respHash
	return e
}

// WithID sets the evidence ID.
func (e Entry) WithID(id string) Entry { e.ID = id; return e }

// WithSession sets the session number.
func (e Entry) WithSession(n int) Entry { e.SessionNumber = n; return e }

// WithFinding sets the finding reference.
func (e Entry) WithFinding(ref string) Entry { e.FindingRef = ref; return e }

// WithScreenshot sets the screenshot path.
func (e Entry) WithScreenshot(path string) Entry { e.ScreenshotPath = path; return e }

// ComputeHash returns the SHA256 hex digest of the entry with its Hash field zeroed.
func ComputeHash(e Entry) string {
	e.Hash = ""
	raw, _ := json.Marshal(e)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
