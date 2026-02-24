package verify

import (
	"fmt"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// IDORConfig holds configuration for IDOR verification.
type IDORConfig struct {
	URL            string // URL with {id} placeholder
	ID             string // Resource ID to access
	Token          string // Attacker's auth token
	ExpectedStatus int    // Expected denial status (default 403)
	Method         string // HTTP method (default GET)
	ProbeConfig
}

// VerifyIDOR runs the IDOR verification probe.
func VerifyIDOR(cfg IDORConfig) (*VerifyResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	timer := NewTimer()
	throttle := NewThrottle(cfg.ThrottleMs)

	var ew *evidence.Writer
	if cfg.Evidence != "" {
		var err error
		ew, err = evidence.NewWriter(cfg.Evidence)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", err)
		} else {
			defer ew.Close()
		}
	}

	// Replace {id} placeholder with target ID
	targetURL := strings.ReplaceAll(cfg.URL, "{id}", cfg.ID)

	// Build headers with auth token
	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Authorization"] = "Bearer " + cfg.Token

	probeCount := 0

	// Send probe
	throttle.Wait()
	probeCount++
	resp := HTTPProbe(cfg.Method, targetURL, "", headers, cfg.TimeoutSec)
	if resp.Error != nil {
		return nil, fmt.Errorf("idor probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d\n", resp.StatusCode, len(resp.Body))
	writeEvidence(ew, "idor", "idor_uuid", cfg.URL, cfg.ID, resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe",
		fmt.Sprintf("method=%s resource_id=%s", cfg.Method, cfg.ID))

	// Evaluate result
	var status, confidence, evidenceStr string
	containsData := len(resp.Body) > 2

	if resp.StatusCode == 200 && containsData {
		status = "confirmed"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Resource %s accessible with attacker token — status 200 with %d bytes", cfg.ID, len(resp.Body))
	} else if resp.StatusCode == 200 && !containsData {
		status = "potential"
		confidence = "medium"
		evidenceStr = fmt.Sprintf("Status 200 but empty body for resource %s", cfg.ID)
	} else if resp.StatusCode == 403 || resp.StatusCode == 404 {
		status = "safe"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Access denied with status %d for resource %s", resp.StatusCode, cfg.ID)
	} else {
		status = "potential"
		confidence = "low"
		evidenceStr = fmt.Sprintf("Unexpected status %d for resource %s", resp.StatusCode, cfg.ID)
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "idor",
		Technique:  "idor_uuid",
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: IDORDetails{
			StatusCode:     resp.StatusCode,
			ResponseLength: len(resp.Body),
			ContainsData:   containsData,
			ExpectedStatus: cfg.ExpectedStatus,
			ResourceID:     cfg.ID,
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}
