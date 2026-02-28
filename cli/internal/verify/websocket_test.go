package verify

import (
	"testing"
)

func TestComputeWSAccept(t *testing.T) {
	// Verify: SHA-1(key + GUID) base64-encoded
	// echo -n "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-5E5AB5DC85B8" | shasum -a 1 | xxd -r -p | base64
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "hwqcGW2OcQ1GlXli6GyQ2JWVCrQ="

	got := computeWSAccept(key)
	if got != expected {
		t.Fatalf("computeWSAccept(%q) = %q, want %q", key, got, expected)
	}
}

func TestGenerateWSKey(t *testing.T) {
	key := generateWSKey()
	if key == "" {
		t.Fatal("generateWSKey() returned empty string")
	}

	// Base64-encoded 16 bytes = 24 chars
	if len(key) != 24 {
		t.Fatalf("expected 24-char base64 key, got %d chars: %q", len(key), key)
	}

	// Two calls should produce different keys
	key2 := generateWSKey()
	if key == key2 {
		t.Fatal("generateWSKey() returned identical keys on consecutive calls")
	}
}

func TestParseHTTPStatus(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"HTTP/1.1 101 Switching Protocols\r\n", 101},
		{"HTTP/1.1 200 OK\r\n", 200},
		{"HTTP/1.1 403 Forbidden\r\n", 403},
		{"HTTP/1.0 404 Not Found\r\n", 404},
		{"garbage", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := parseHTTPStatus(tt.line)
		if got != tt.want {
			t.Errorf("parseHTTPStatus(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}
