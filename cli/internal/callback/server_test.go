package callback

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestCallbackServer_RecordsRequest(t *testing.T) {
	port := freePort(t)
	srv := NewServer(CallbackConfig{Port: port, WaitSec: 5})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan *CallbackResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := srv.Start(ctx)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Send a callback request
	url := fmt.Sprintf("http://127.0.0.1:%d/cb/%s", port, srv.Token())
	resp, err := http.Post(url, "text/plain", strings.NewReader("test-body"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	// Wait for result (server should return after first hit + grace)
	select {
	case result := <-resultCh:
		if result.TotalReceived != 1 {
			t.Errorf("expected 1 callback, got %d", result.TotalReceived)
		}
		if len(result.Callbacks) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(result.Callbacks))
		}
		entry := result.Callbacks[0]
		if entry.Method != "POST" {
			t.Errorf("expected POST, got %s", entry.Method)
		}
		if entry.Path != "/cb/"+srv.Token() {
			t.Errorf("expected path /cb/%s, got %s", srv.Token(), entry.Path)
		}
		if entry.BodyLength != 9 { // len("test-body")
			t.Errorf("expected body length 9, got %d", entry.BodyLength)
		}
		if entry.ID != "CB-001" {
			t.Errorf("expected ID CB-001, got %s", entry.ID)
		}
	case err := <-errCh:
		t.Fatalf("server error: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server result")
	}
}

func TestCallbackServer_WaitTimeout(t *testing.T) {
	port := freePort(t)
	srv := NewServer(CallbackConfig{Port: port, WaitSec: 1})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	result, err := srv.Start(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalReceived != 0 {
		t.Errorf("expected 0 callbacks, got %d", result.TotalReceived)
	}
	if elapsed > 3*time.Second {
		t.Errorf("expected ~1s timeout, took %v", elapsed)
	}
}

func TestCallbackServer_MultipleCallbacks(t *testing.T) {
	port := freePort(t)
	srv := NewServer(CallbackConfig{Port: port, WaitSec: 5})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan *CallbackResult, 1)
	go func() {
		result, _ := srv.Start(ctx)
		resultCh <- result
	}()

	time.Sleep(100 * time.Millisecond)

	// Send 3 requests
	for i := 0; i < 3; i++ {
		url := fmt.Sprintf("http://127.0.0.1:%d/cb/%s", port, srv.Token())
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		resp.Body.Close()
	}

	select {
	case result := <-resultCh:
		if result.TotalReceived != 3 {
			t.Errorf("expected 3 callbacks, got %d", result.TotalReceived)
		}
		// Check sequential IDs
		for i, e := range result.Callbacks {
			expected := fmt.Sprintf("CB-%03d", i+1)
			if e.ID != expected {
				t.Errorf("entry %d: expected ID %s, got %s", i, expected, e.ID)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok := GenerateToken()
		if seen[tok] {
			t.Fatalf("duplicate token at iteration %d: %s", i, tok)
		}
		seen[tok] = true
		if len(tok) != 32 { // 16 bytes = 32 hex chars
			t.Errorf("expected 32 char token, got %d: %s", len(tok), tok)
		}
	}
}

func TestCallbackServer_BodyReadError(t *testing.T) {
	srv := &Server{
		cfg:       CallbackConfig{Port: 0, WaitSec: 5},
		token:     "test-token",
		startedAt: time.Now(),
		firstHit:  make(chan struct{}),
	}

	body := iotest.ErrReader(fmt.Errorf("simulated read error"))
	req := httptest.NewRequest("POST", "/cb/test-token", body)
	w := httptest.NewRecorder()

	srv.handleCallback(w, req)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(srv.entries))
	}

	entry := srv.entries[0]
	if entry.BodyHash != "" {
		t.Errorf("expected empty BodyHash on read error, got %q", entry.BodyHash)
	}
	if entry.BodyLength != 0 {
		t.Errorf("expected 0 BodyLength on read error, got %d", entry.BodyLength)
	}
}
