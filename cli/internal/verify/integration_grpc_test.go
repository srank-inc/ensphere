package verify

import (
	"fmt"
	"net"
	"testing"
)

func TestGRPC_Plaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// TCP listener that accepts HTTP/2 preface and responds with SETTINGS
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the HTTP/2 preface (24 bytes) + SETTINGS frame (9 bytes)
		buf := make([]byte, 64)
		conn.Read(buf)

		// Respond with empty SETTINGS frame
		// length=0, type=0x04(SETTINGS), flags=0, stream=0
		settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
		conn.Write(settings)
	}()

	addr := listener.Addr().String()

	result, err := VerifyGRPC(GRPCConfig{
		URL:       fmt.Sprintf("http://%s", addr),
		Technique: "grpc_plaintext",
		ProbeConfig: ProbeConfig{
			InScope:    []string{"127.0.0.1"},
			MaxRisk:    0,
			ThrottleMs: 0,
			TimeoutSec: 5,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.VulnType != "grpc" {
		t.Fatalf("expected vuln_type grpc, got %s", result.VulnType)
	}

	m, ok := result.Measurements.(GRPCMeasurements)
	if !ok {
		t.Fatal("expected GRPCMeasurements")
	}
	if !m.PlaintextAccepted {
		t.Fatal("expected plaintext to be accepted")
	}
	if m.ElapsedMs < 0 {
		t.Fatalf("expected elapsed >= 0, got %d", m.ElapsedMs)
	}
}

func TestGRPC_Reflection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// For reflection, we need an HTTP/2 server. Since we can't easily mock full HTTP/2
	// without external deps, we test that the probe completes without error against
	// a server that refuses the connection (reflection_enabled=false).
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Close listener immediately so connection is refused
	listener.Close()

	addr := listener.Addr().String()

	result, err := VerifyGRPC(GRPCConfig{
		URL:       fmt.Sprintf("http://%s", addr),
		Technique: "grpc_reflection",
		ProbeConfig: ProbeConfig{
			InScope:    []string{"127.0.0.1"},
			MaxRisk:    0,
			ThrottleMs: 0,
			TimeoutSec: 2,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(GRPCMeasurements)
	if !ok {
		t.Fatal("expected GRPCMeasurements")
	}
	if m.ReflectionEnabled {
		t.Fatal("expected reflection to not be enabled on closed port")
	}
}
