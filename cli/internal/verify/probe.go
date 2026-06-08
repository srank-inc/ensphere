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
	StatusCode int
	Body       string
	BodyHash   string
	ElapsedMs  int64
	Headers    http.Header
	Error      error
}

// CheckMaxRisk returns a ScopeError if payloadRisk exceeds maxRisk.
func CheckMaxRisk(payloadRisk, maxRisk int) error {
	if maxRisk > 0 && payloadRisk > maxRisk {
		return &ScopeError{Msg: fmt.Sprintf("payload risk %d exceeds max-risk %d", payloadRisk, maxRisk)}
	}
	return nil
}

// HTTPProbe sends an HTTP request and captures timing + response hash.
func HTTPProbe(method, url string, body string, headers map[string]string, timeoutSec int, inScope ...[]string) ProbeResponse {
	scopePatterns, enforceScope := optionalScope(inScope)
	if enforceScope {
		if err := CheckScope(url, scopePatterns); err != nil {
			return ProbeResponse{Error: err}
		}
	}

	client := scopedHTTPClient(timeoutSec, scopePatterns, enforceScope, true)
	return executeHTTPProbe(client, method, url, body, headers)
}

func executeHTTPProbe(client *http.Client, method, url string, body string, headers map[string]string) ProbeResponse {
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB max
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

// HTTPProbeNoRedirect sends an HTTP request without following redirects.
// Use for probes where the first-hop response status is the security signal
// (auth, authz, IDOR, fileupload verification).
func HTTPProbeNoRedirect(method, url string, body string, headers map[string]string, timeoutSec int, inScope ...[]string) ProbeResponse {
	scopePatterns, enforceScope := optionalScope(inScope)
	if enforceScope {
		if err := CheckScope(url, scopePatterns); err != nil {
			return ProbeResponse{Error: err}
		}
	}
	client := scopedHTTPClient(timeoutSec, scopePatterns, enforceScope, false)
	return executeHTTPProbe(client, method, url, body, headers)
}

func optionalScope(inScope [][]string) ([]string, bool) {
	if len(inScope) == 0 {
		return nil, false
	}
	return inScope[0], true
}

func scopedHTTPClient(timeoutSec int, inScope []string, enforceScope bool, followRedirects bool) *http.Client {
	return scopedHTTPClientWithTransport(timeoutSec, nil, inScope, enforceScope, followRedirects)
}

func scopedHTTPClientWithTransport(timeoutSec int, transport http.RoundTripper, inScope []string, enforceScope bool, followRedirects bool) *http.Client {
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after %d redirects", len(via))
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return &ScopeError{Msg: fmt.Sprintf("redirect target %q uses unsupported scheme %q", req.URL.String(), req.URL.Scheme)}
		}
		if !enforceScope {
			return &ScopeError{Msg: fmt.Sprintf("redirect target %q cannot be scope-validated: no in-scope patterns provided", req.URL.String())}
		}
		if err := CheckScope(req.URL.String(), inScope); err != nil {
			return &ScopeError{Msg: fmt.Sprintf("redirect target %q is out of scope: %v", req.URL.String(), err)}
		}
		return nil
	}
	return client
}
