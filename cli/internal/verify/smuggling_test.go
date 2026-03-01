package verify

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestBuildSmugglingPayload_CLTE(t *testing.T) {
	payload := buildSmugglingPayload("http://example.com/path?q=1", "cl_te", nil)

	if !strings.HasPrefix(payload, "POST /path?q=1 HTTP/1.1\r\n") {
		t.Fatalf("expected payload to start with POST /path?q=1 HTTP/1.1, got prefix: %q", payload[:min(len(payload), 60)])
	}
	if !strings.Contains(payload, "Host: example.com\r\n") {
		t.Fatal("expected Host: example.com header")
	}
	if !strings.Contains(payload, "Content-Length:") {
		t.Fatal("expected Content-Length header")
	}
	if !strings.Contains(payload, "Transfer-Encoding: chunked") {
		t.Fatal("expected Transfer-Encoding: chunked header")
	}
	if strings.Count(payload, "Host:") != 1 {
		t.Fatalf("expected exactly 1 Host header, got %d", strings.Count(payload, "Host:"))
	}
}

func TestBuildSmugglingPayload_TECL(t *testing.T) {
	payload := buildSmugglingPayload("http://example.com/path", "te_cl", nil)

	teIdx := strings.Index(payload, "Transfer-Encoding: chunked")
	clIdx := strings.Index(payload, "Content-Length:")
	if teIdx < 0 || clIdx < 0 {
		t.Fatal("expected both Transfer-Encoding and Content-Length headers")
	}
	if teIdx >= clIdx {
		t.Fatal("expected Transfer-Encoding before Content-Length for te_cl")
	}
}

func TestBuildSmugglingPayload_TETE(t *testing.T) {
	payload := buildSmugglingPayload("http://example.com/path", "te_te", nil)

	count := strings.Count(payload, "Transfer-Encoding")
	if count != 2 {
		t.Fatalf("expected 2 Transfer-Encoding headers, got %d", count)
	}
}

func TestBuildSmugglingPayload_CustomHeaders(t *testing.T) {
	headers := map[string]string{
		"X-Custom": "foo",
		"host":     "should-skip",
	}
	payload := buildSmugglingPayload("http://example.com/path", "cl_te", headers)

	if !strings.Contains(payload, "X-Custom: foo") {
		t.Fatal("expected X-Custom: foo in payload")
	}
	if strings.Count(payload, "Host:") != 1 {
		t.Fatalf("expected exactly 1 Host header (custom 'host' should be skipped), got %d", strings.Count(payload, "Host:"))
	}
	if strings.Count(payload, "Content-Length:") != 1 {
		t.Fatalf("expected exactly 1 Content-Length, got %d", strings.Count(payload, "Content-Length:"))
	}
}

func TestBuildSmugglingPayload_InvalidTechnique(t *testing.T) {
	payload := buildSmugglingPayload("http://example.com/path", "invalid", nil)
	if payload != "" {
		t.Fatalf("expected empty string for invalid technique, got %q", payload)
	}
}

func TestRawHTTPProbe_LocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read request (at least first line)
		reader := bufio.NewReader(conn)
		reader.ReadString('\n') // read request line

		// Write minimal HTTP response
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}()

	rawPayload := "GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
	statusCode, elapsed, err := rawHTTPProbe("http://"+listener.Addr().String()+"/test", rawPayload, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if statusCode != 200 {
		t.Fatalf("expected status 200, got %d", statusCode)
	}
	if elapsed < 0 {
		t.Fatalf("expected elapsed >= 0, got %d", elapsed)
	}
}

