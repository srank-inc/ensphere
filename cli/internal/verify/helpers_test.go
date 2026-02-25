package verify

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestServer creates an httptest.Server bound to IPv4 127.0.0.1 only.
// We construct the Server struct directly instead of using NewUnstartedServer,
// because NewUnstartedServer calls newLocalListener() internally which can
// panic in IPv6-disabled environments before we get a chance to swap the listener.
func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	ts := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: handler},
	}
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

// baseProbeConfig returns a ProbeConfig suitable for all integration tests.
// InScope covers both 127.0.0.1 and localhost (httptest uses either).
func baseProbeConfig() ProbeConfig {
	return ProbeConfig{
		InScope:    []string{"127.0.0.1", "localhost"},
		MaxRisk:    0, // disabled
		ThrottleMs: 0, // fast
		TimeoutSec: 5,
		Evidence:   "", // skip file
	}
}

// assertScopeErr is a test helper that asserts err is *ScopeError and result is nil.
func assertScopeErr(t *testing.T, result *ProbeResult, err error) {
	t.Helper()
	if result != nil {
		t.Fatal("expected nil result")
	}
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

// delayHandler returns a handler that delays by d when the request body/query
// contains timing-related keywords (sleep, pg_sleep, ping, pickle).
func delayHandler(d time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := r.URL.RawQuery + string(body)
		if strings.Contains(q, "sleep") || strings.Contains(q, "pg_sleep") ||
			strings.Contains(q, "SLEEP") || strings.Contains(q, "ping") ||
			strings.Contains(q, "pickle") {
			time.Sleep(d)
		}
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok param=%s", r.URL.Query().Get("id"))
	}
}

// echoHandler reflects all query params and body in response.
func echoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		fmt.Fprintf(w, "echo: query=%s body=%s", r.URL.RawQuery, string(body))
	}
}

// authGateHandler returns 200 for validToken, 401 otherwise.
func authGateHandler(validToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+validToken {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"status":"authorized","data":"secret"}`)
		} else {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		}
	}
}

// signatureHandler returns body containing the given signature string
// when the request contains LFI/SSRF/XXE-related keywords.
func signatureHandler(signature string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := r.URL.RawQuery + string(body)
		if strings.Contains(q, "etc%2Fpasswd") || strings.Contains(q, "etc/passwd") ||
			strings.Contains(q, "169.254") || strings.Contains(q, "meta-data") ||
			strings.Contains(q, "SYSTEM") || strings.Contains(q, "xxe") {
			w.WriteHeader(200)
			fmt.Fprintf(w, "file content: %s\nmore data here", signature)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, "normal response")
		}
	}
}
