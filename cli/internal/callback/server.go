package callback

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// CallbackConfig holds configuration for the callback server.
type CallbackConfig struct {
	Port        int
	WaitSec     int    // 0 = run until context cancellation
	ExternalURL string // e.g., ngrok URL
	Evidence    string
}

// CallbackEntry records a single inbound callback request.
type CallbackEntry struct {
	ID         string            `json:"id"`
	ReceivedAt string            `json:"received_at"`
	SourceIP   string            `json:"source_ip"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	BodyHash   string            `json:"body_hash"`
	BodyLength int               `json:"body_length"`
	ElapsedMs  int64             `json:"elapsed_ms"`
}

// CallbackResult is the JSON output of a callback server run.
type CallbackResult struct {
	SchemaVersion int             `json:"schema_version"`
	ListenAddr    string          `json:"listen_addr"`
	ExternalURL   string          `json:"external_url,omitempty"`
	Token         string          `json:"token"`
	StartedAt     string          `json:"started_at"`
	Duration      string          `json:"duration"`
	Callbacks     []CallbackEntry `json:"callbacks"`
	TotalReceived int             `json:"total_received"`
}

// Server is the OOB callback HTTP server.
type Server struct {
	cfg       CallbackConfig
	token     string
	startedAt time.Time
	listener  net.Listener

	mu        sync.Mutex
	entries   []CallbackEntry
	entrySeq  int
	firstHit  chan struct{}
	firstOnce sync.Once
}

// NewServer creates a new callback server with a unique token.
func NewServer(cfg CallbackConfig) *Server {
	return &Server{
		cfg:      cfg,
		token:    GenerateToken(),
		firstHit: make(chan struct{}),
	}
}

// GenerateToken returns a 16-byte hex string.
func GenerateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use time-based token if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Token returns the server's unique token.
func (s *Server) Token() string {
	return s.token
}

// Start runs the callback server until context cancellation or timeout.
func (s *Server) Start(ctx context.Context) (*CallbackResult, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	s.listener = ln
	s.startedAt = time.Now().UTC()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)

	srv := &http.Server{Handler: mux}

	go func() {
		_ = srv.Serve(ln)
	}()

	if s.cfg.WaitSec > 0 {
		// Wait mode: block until first callback + 500ms grace, or timeout
		timeout := time.Duration(s.cfg.WaitSec) * time.Second
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-s.firstHit:
			// Got first callback, wait 500ms grace for additional callbacks
			grace := time.NewTimer(500 * time.Millisecond)
			defer grace.Stop()
			select {
			case <-grace.C:
			case <-ctx.Done():
			}
		case <-timer.C:
		case <-ctx.Done():
		}
	} else {
		// No-wait mode: run until context cancellation
		<-ctx.Done()
	}

	_ = srv.Shutdown(context.Background())

	s.mu.Lock()
	defer s.mu.Unlock()

	return &CallbackResult{
		SchemaVersion: 2,
		ListenAddr:    ln.Addr().String(),
		ExternalURL:   s.cfg.ExternalURL,
		Token:         s.token,
		StartedAt:     s.startedAt.Format(time.RFC3339),
		Duration:      time.Since(s.startedAt).Round(100 * time.Millisecond).String(),
		Callbacks:     s.entries,
		TotalReceived: len(s.entries),
	}, nil
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Only record requests to /cb/<token> path
	if !strings.HasPrefix(r.URL.Path, "/cb/") {
		w.WriteHeader(404)
		return
	}
	pathToken := strings.TrimPrefix(r.URL.Path, "/cb/")
	if pathToken != s.token {
		w.WriteHeader(404)
		return
	}

	body, bodyErr := io.ReadAll(r.Body)
	var bodyHash string
	if bodyErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: callback body read error: %v\n", bodyErr)
	} else {
		h := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(h[:])
	}

	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	s.mu.Lock()
	s.entrySeq++
	entry := CallbackEntry{
		ID:         fmt.Sprintf("CB-%03d", s.entrySeq),
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		SourceIP:   r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
		Headers:    headers,
		BodyHash:   bodyHash,
		BodyLength: len(body),
		ElapsedMs:  time.Since(s.startedAt).Milliseconds(),
	}
	s.entries = append(s.entries, entry)
	s.mu.Unlock()

	s.firstOnce.Do(func() {
		close(s.firstHit)
	})

	w.WriteHeader(200)
	fmt.Fprint(w, "ok")
}
