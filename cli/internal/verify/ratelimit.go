package verify

import (
	"fmt"
	"os"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// RateLimitConfig holds configuration for rate limit measurement.
type RateLimitConfig struct {
	URL        string
	Method     string
	Body       string
	Token      string
	BurstCount int // explicitly approved number of sequential requests
	WindowSec  int // time window in seconds (default 10)
	ProbeConfig
}

// VerifyRateLimit runs the rate limit measurement probe.
func VerifyRateLimit(cfg RateLimitConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if cfg.BurstCount < 1 {
		return nil, fmt.Errorf("burst count must be explicitly set to a positive approved value")
	}
	if cfg.WindowSec < 1 {
		cfg.WindowSec = 10
	}

	timer := NewTimer()

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

	headers := make(map[string]string)
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	if cfg.Token != "" {
		headers["Authorization"] = "Bearer " + cfg.Token
	}

	fmt.Fprintf(os.Stderr, "[RATELIMIT] burst=%d window=%ds\n", cfg.BurstCount, cfg.WindowSec)

	deadline := time.Now().Add(time.Duration(cfg.WindowSec) * time.Second)

	var rounds []RoundResult
	statusCodes := make(map[int]int)
	successCount := 0
	throttledCount := 0
	firstThrottleAt := 0
	var minMs, maxMs, totalMs int64
	first := true

	for i := 0; i < cfg.BurstCount; i++ {
		if time.Now().After(deadline) {
			break
		}

		resp := HTTPProbe(cfg.Method, cfg.URL, cfg.Body, headers, cfg.TimeoutSec, cfg.InScope)
		if resp.Error != nil {
			fmt.Fprintf(os.Stderr, "[RATELIMIT %d/%d] error: %v\n", i+1, cfg.BurstCount, resp.Error)
			continue
		}

		round := RoundResult{
			StatusCode: resp.StatusCode,
			ElapsedMs:  resp.ElapsedMs,
			BodyHash:   resp.BodyHash,
			BodyLength: len(resp.Body),
		}
		rounds = append(rounds, round)

		statusCodes[resp.StatusCode]++

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		}

		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			throttledCount++
			if firstThrottleAt == 0 {
				firstThrottleAt = i + 1
			}
		}

		totalMs += resp.ElapsedMs
		if first || resp.ElapsedMs < minMs {
			minMs = resp.ElapsedMs
		}
		if first || resp.ElapsedMs > maxMs {
			maxMs = resp.ElapsedMs
		}
		first = false

		fmt.Fprintf(os.Stderr, "[RATELIMIT %d/%d] status=%d %dms\n", i+1, cfg.BurstCount, resp.StatusCode, resp.ElapsedMs)
		writeEvidence(ew, "rate_limit", "rate_limit_bypass", cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", resp.ElapsedMs), "probe", fmt.Sprintf("request %d/%d", i+1, cfg.BurstCount))
	}

	if len(rounds) == 0 {
		return nil, fmt.Errorf("all rate limit probes failed")
	}

	avgMs := totalMs / int64(len(rounds))

	return &ProbeResult{
		VulnType:   "rate_limit",
		Technique:  "rate_limit_bypass",
		StartedAt:  timer.StartedAt(),
		ProbeCount: len(rounds),
		Duration:   timer.Elapsed(),
		Measurements: RateLimitMeasurements{
			BurstCount:      cfg.BurstCount,
			WindowSec:       cfg.WindowSec,
			SuccessCount:    successCount,
			ThrottledCount:  throttledCount,
			FirstThrottleAt: firstThrottleAt,
			StatusCodes:     statusCodes,
			Rounds:          rounds,
			MinMs:           minMs,
			MaxMs:           maxMs,
			AvgMs:           avgMs,
		},
	}, nil
}
