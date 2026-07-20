package verify

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// SmugglingConfig holds configuration for request smuggling verification.
type SmugglingConfig struct {
	URL       string
	Technique string // cl_te | te_cl | te_te
	ProbeConfig
}

var validSmugglingTechniques = map[string]bool{
	"cl_te": true, "te_cl": true, "te_te": true,
}

// VerifySmuggling runs the request smuggling verification probe.
func VerifySmuggling(cfg SmugglingConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(4, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validSmugglingTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: cl_te, te_cl, te_te", cfg.Technique)}
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

	// Baseline: normal POST request via HTTPProbe
	throttle.Wait()
	probeCount++
	baselineResp := HTTPProbe("POST", cfg.URL, "x=1", cfg.Headers, cfg.TimeoutSec, cfg.InScope)
	if baselineResp.Error != nil {
		return nil, fmt.Errorf("baseline probe: %w", baselineResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[BASELINE] status=%d %dms\n", baselineResp.StatusCode, baselineResp.ElapsedMs)
	writeEvidence(ew, "request_smuggling", cfg.Technique, cfg.URL, "", baselineResp.StatusCode,
		fmt.Sprintf("%dms", baselineResp.ElapsedMs), "baseline", "normal POST request")

	baseline := RoundResult{
		StatusCode: baselineResp.StatusCode,
		ElapsedMs:  baselineResp.ElapsedMs,
		BodyHash:   baselineResp.BodyHash,
		BodyLength: len(baselineResp.Body),
	}

	// Smuggling probes via raw HTTP
	var probeRounds []RoundResult
	for i := 0; i < defaultRounds; i++ {
		throttle.Wait()
		probeCount++

		rawPayload := buildSmugglingPayload(cfg.URL, cfg.Technique, cfg.Headers)
		statusCode, elapsed, err := rawHTTPProbe(cfg.URL, rawPayload, cfg.TimeoutSec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[PROBE %d] error: %v\n", i+1, err)
			continue
		}

		probeRounds = append(probeRounds, RoundResult{
			StatusCode: statusCode,
			ElapsedMs:  elapsed,
		})
		fmt.Fprintf(os.Stderr, "[PROBE %d] status=%d %dms\n", i+1, statusCode, elapsed)
		writeEvidence(ew, "request_smuggling", cfg.Technique, cfg.URL, "", statusCode,
			fmt.Sprintf("%dms", elapsed), "probe", fmt.Sprintf("round %d technique=%s", i+1, cfg.Technique))
	}

	if len(probeRounds) == 0 {
		return nil, fmt.Errorf("all smuggling probes failed")
	}

	probeAvg := avgFromRounds(probeRounds)
	delta := probeAvg - baselineResp.ElapsedMs

	return &ProbeResult{
		VulnType:   "request_smuggling",
		Technique:  cfg.Technique,
		StartedAt:  timer.StartedAt(),
		ProbeCount: probeCount,
		Duration:   timer.Elapsed(),
		Measurements: SmugglingMeasurements{
			Technique:   cfg.Technique,
			Baseline:    baseline,
			ProbeRounds: probeRounds,
			BaselineMs:  baselineResp.ElapsedMs,
			ProbeAvgMs:  probeAvg,
			DeltaMs:     delta,
			PayloadUsed: cfg.Technique,
		},
	}, nil
}

func buildSmugglingPayload(rawURL, technique string, headers map[string]string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse URL %q: %v\n", rawURL, err)
		return ""
	}
	host := parsed.Host
	requestURI := parsed.RequestURI() // includes path + query string
	if requestURI == "" {
		requestURI = "/"
	}

	// Build custom header lines (skip headers managed by the smuggling payload itself)
	var extraHeaders string
	skip := map[string]bool{"host": true, "content-length": true, "transfer-encoding": true}
	for k, v := range headers {
		if !skip[strings.ToLower(k)] {
			extraHeaders += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}

	switch technique {
	case "cl_te":
		// CL says body is short, but TE says chunked
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ\r\n\r\n", requestURI, host, extraHeaders)
	case "te_cl":
		// TE says chunked, CL says body is longer
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n%sTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX", requestURI, host, extraHeaders)
	case "te_te":
		// Obfuscated TE header
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n%sContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n1\r\nZ\r\nQ\r\n\r\n", requestURI, host, extraHeaders)
	default:
		return ""
	}
}

// rawHTTPProbe sends exact bytes over a TCP/TLS connection.
func rawHTTPProbe(rawURL, payload string, timeoutSec int) (int, int64, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0, 0, fmt.Errorf("parse URL: %w", err)
	}

	host := parsed.Host
	useTLS := parsed.Scheme == "https"

	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	timeout := time.Duration(timeoutSec) * time.Second
	start := time.Now()

	var conn net.Conn
	if useTLS {
		hostname := parsed.Hostname()
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", host, &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = net.DialTimeout("tcp", host, timeout)
	}
	if err != nil {
		return 0, 0, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write([]byte(payload))
	if err != nil {
		return 0, 0, fmt.Errorf("write: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return 0, elapsed, fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, elapsed, nil
}
