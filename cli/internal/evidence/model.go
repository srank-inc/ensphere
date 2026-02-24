package evidence

import "time"

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
		Notes:      notes,
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
