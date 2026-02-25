package verify

import (
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestCheckScope_GlobMatch(t *testing.T) {
	err := CheckScope("http://api.example.com/path", []string{"*.example.com"})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckScope_ExactMatch(t *testing.T) {
	err := CheckScope("http://localhost/path", []string{"localhost"})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckScope_OutOfScope(t *testing.T) {
	err := CheckScope("http://evil.com/path", []string{"*.example.com"})
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

func TestCheckScope_CIDR(t *testing.T) {
	err := CheckScope("http://192.168.1.5/path", []string{"192.168.1.0/24"})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckScope_CIDROutOfRange(t *testing.T) {
	err := CheckScope("http://10.0.0.1/path", []string{"192.168.1.0/24"})
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

func TestCheckScope_EmptyPatterns(t *testing.T) {
	err := CheckScope("http://localhost/", []string{})
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

func TestCheckScope_NoHostname(t *testing.T) {
	err := CheckScope("not-a-url", []string{"*"})
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

func TestCheckMaxRisk_Disabled(t *testing.T) {
	err := CheckMaxRisk(5, 0)
	if err != nil {
		t.Fatalf("expected nil (disabled), got %v", err)
	}
}

func TestCheckMaxRisk_ExactMatch(t *testing.T) {
	err := CheckMaxRisk(3, 3)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCheckMaxRisk_Exceeds(t *testing.T) {
	err := CheckMaxRisk(4, 3)
	var scopeErr *ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("expected *ScopeError, got %T: %v", err, err)
	}
}

func TestCheckMaxRisk_Below(t *testing.T) {
	err := CheckMaxRisk(2, 3)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestHTTPProbe_BasicRoundTrip(t *testing.T) {
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello world"))
	}))

	resp := HTTPProbe("GET", ts.URL+"/test", "", nil, 5)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.BodyHash == "" {
		t.Fatal("expected non-empty BodyHash")
	}
	if resp.ElapsedMs < 0 {
		t.Fatalf("expected ElapsedMs >= 0, got %d", resp.ElapsedMs)
	}
	if resp.Body != "hello world" {
		t.Fatalf("expected body 'hello world', got %q", resp.Body)
	}
}

func TestHTTPProbe_CustomHeaders(t *testing.T) {
	var gotHeader string
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test")
		w.WriteHeader(200)
	}))

	resp := HTTPProbe("GET", ts.URL, "", map[string]string{"X-Test": "ensphere-val"}, 5)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if gotHeader != "ensphere-val" {
		t.Fatalf("expected header 'ensphere-val', got %q", gotHeader)
	}
}

func TestHTTPProbe_PostBody(t *testing.T) {
	var gotBody string
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
	}))

	resp := HTTPProbe("POST", ts.URL, "test-body-data", nil, 5)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if gotBody != "test-body-data" {
		t.Fatalf("expected body 'test-body-data', got %q", gotBody)
	}
}

func TestHTTPProbe_Timeout(t *testing.T) {
	ts := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))

	resp := HTTPProbe("GET", ts.URL, "", nil, 1)
	if resp.Error == nil {
		t.Fatal("expected error for timeout")
	}
	if resp.ElapsedMs <= 0 {
		t.Fatalf("expected ElapsedMs > 0, got %d", resp.ElapsedMs)
	}
}
