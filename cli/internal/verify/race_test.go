package verify

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestVerifyRace_ConcurrentBurst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	var count int64
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&count, 1)
		w.WriteHeader(200)
		fmt.Fprintf(w, "request %d", n)
	}))

	cfg := RaceConfig{
		URL:         ts.URL + "/api",
		Method:      "POST",
		Concurrency: 5,
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRace(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.VulnType != "race_condition" {
		t.Fatalf("expected VulnType race_condition, got %s", result.VulnType)
	}

	m, ok := result.Measurements.(RaceMeasurements)
	if !ok {
		t.Fatalf("expected RaceMeasurements, got %T", result.Measurements)
	}
	if m.Concurrency != 5 {
		t.Fatalf("expected Concurrency 5, got %d", m.Concurrency)
	}
	if len(m.Rounds) != 5 {
		t.Fatalf("expected 5 rounds, got %d", len(m.Rounds))
	}
	if m.SuccessCount <= 0 {
		t.Fatalf("expected SuccessCount > 0, got %d", m.SuccessCount)
	}
	if m.UniqueHashes <= 0 {
		t.Fatalf("expected UniqueHashes > 0, got %d", m.UniqueHashes)
	}
	if m.MinMs > m.AvgMs {
		t.Fatalf("expected MinMs <= AvgMs, got %d > %d", m.MinMs, m.AvgMs)
	}
	if m.AvgMs > m.MaxMs {
		t.Fatalf("expected AvgMs <= MaxMs, got %d > %d", m.AvgMs, m.MaxMs)
	}
}
