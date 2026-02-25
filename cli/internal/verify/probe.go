package verify

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProbeResponse holds the result of a single HTTP probe.
type ProbeResponse struct {
	StatusCode   int
	Body         string
	BodyHash     string
	ElapsedMs    int64
	Headers      http.Header
	Error        error
}

// CheckMaxRisk returns a ScopeError if payloadRisk exceeds maxRisk.
func CheckMaxRisk(payloadRisk, maxRisk int) error {
	if maxRisk > 0 && payloadRisk > maxRisk {
		return &ScopeError{Msg: fmt.Sprintf("payload risk %d exceeds max-risk %d", payloadRisk, maxRisk)}
	}
	return nil
}

// HTTPProbe sends an HTTP request and captures timing + response hash.
func HTTPProbe(method, url string, body string, headers map[string]string, timeoutSec int) ProbeResponse {
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("build request: %w", err)}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResponse{ElapsedMs: elapsed, Error: fmt.Errorf("request failed: %w", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ProbeResponse{
			StatusCode: resp.StatusCode,
			ElapsedMs:  elapsed,
			Headers:    resp.Header,
			Error:      fmt.Errorf("read body: %w", err),
		}
	}

	bodyStr := string(respBody)
	hash := fmt.Sprintf("%x", sha256.Sum256(respBody))

	return ProbeResponse{
		StatusCode: resp.StatusCode,
		Body:       bodyStr,
		BodyHash:   hash,
		ElapsedMs:  elapsed,
		Headers:    resp.Header,
	}
}
