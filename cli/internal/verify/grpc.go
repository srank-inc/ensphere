package verify

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// GRPCConfig holds configuration for gRPC verification.
type GRPCConfig struct {
	URL       string
	Technique string // grpc_reflection | grpc_plaintext
	ProbeConfig
}

var validGRPCTechniques = map[string]bool{
	"grpc_reflection": true, "grpc_plaintext": true,
}

// Pre-serialized gRPC reflection request body:
// gRPC frame: [compressed=0x00][length=0x00000003] + protobuf ServerReflectionRequest{list_services:"*"}
// Protobuf: field 3 (string) = tag 0x1a, length 1, value 0x2a ("*")
var grpcReflectionBody = []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x1a, 0x01, 0x2a}

// HTTP/2 connection preface + empty SETTINGS frame (pre-concatenated).
var http2ClientPrelude = append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)

// VerifyGRPC runs the gRPC security verification probe.
func VerifyGRPC(cfg GRPCConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	if err := CheckMaxRisk(2, cfg.MaxRisk); err != nil {
		return nil, err
	}

	if !validGRPCTechniques[cfg.Technique] {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: grpc_reflection, grpc_plaintext", cfg.Technique)}
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

	switch cfg.Technique {
	case "grpc_reflection":
		return grpcReflection(cfg, timer, throttle, ew, &probeCount)
	case "grpc_plaintext":
		return grpcPlaintext(cfg, timer, throttle, ew, &probeCount)
	default:
		return nil, fmt.Errorf("unsupported technique %q", cfg.Technique)
	}
}

func grpcReflection(cfg GRPCConfig, timer *Timer, throttle *Throttle, ew *evidence.Writer, probeCount *int) (*ProbeResult, error) {
	reflectionEnabled := false
	var servicesFound []string

	// Try both v1alpha and v1 reflection endpoints
	endpoints := []string{
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	}

	var lastElapsed int64

	for _, endpoint := range endpoints {
		throttle.Wait()
		*probeCount++

		reqURL := strings.TrimRight(cfg.URL, "/") + endpoint
		start := time.Now()

		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
		}

		req, err := http.NewRequest("POST", reqURL, bytes.NewReader(grpcReflectionBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")

		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		lastElapsed = time.Since(start).Milliseconds()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[REFLECTION %s] error: %v\n", endpoint, err)
			writeEvidence(ew, "grpc", cfg.Technique, cfg.URL, "", 0,
				fmt.Sprintf("%dms", lastElapsed), "probe", fmt.Sprintf("reflection probe %s: error", endpoint))
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		ct := resp.Header.Get("Content-Type")
		grpcStatus := resp.Header.Get("Grpc-Status")

		fmt.Fprintf(os.Stderr, "[REFLECTION %s] status=%d content-type=%s grpc-status=%s %dms\n",
			endpoint, resp.StatusCode, ct, grpcStatus, lastElapsed)
		writeEvidence(ew, "grpc", cfg.Technique, cfg.URL, "", resp.StatusCode,
			fmt.Sprintf("%dms", lastElapsed), "probe", fmt.Sprintf("reflection probe %s", endpoint))

		if resp.StatusCode == 200 && strings.HasPrefix(ct, "application/grpc") {
			// Check if gRPC status indicates UNIMPLEMENTED (code 12)
			if grpcStatus == "12" {
				continue
			}
			reflectionEnabled = true
			servicesFound = extractServiceNames(body)
			break
		}
	}

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "grpc",
		Technique:     cfg.Technique,
		StartedAt:     timer.StartedAt(),
		ProbeCount:    *probeCount,
		Duration:      timer.Elapsed(),
		Measurements: GRPCMeasurements{
			Technique:         cfg.Technique,
			ReflectionEnabled: reflectionEnabled,
			ServicesFound:     servicesFound,
			ElapsedMs:         lastElapsed,
		},
	}, nil
}

func grpcPlaintext(cfg GRPCConfig, timer *Timer, throttle *Throttle, ew *evidence.Writer, probeCount *int) (*ProbeResult, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	plaintextAccepted := false
	tlsAccepted := false
	var totalElapsed int64

	// Test 1: Plaintext HTTP/2
	throttle.Wait()
	*probeCount++
	start := time.Now()

	conn, err := net.DialTimeout("tcp", host, timeout)
	plaintextElapsed := time.Since(start).Milliseconds()
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, writeErr := conn.Write(http2ClientPrelude)
		if writeErr == nil {
			buf := make([]byte, 64)
			n, readErr := conn.Read(buf)
			if readErr == nil && n >= 4 && buf[3] == 0x04 {
				plaintextAccepted = true
			}
		}
		conn.Close()
	}
	totalElapsed = plaintextElapsed
	fmt.Fprintf(os.Stderr, "[PLAINTEXT] accepted=%v %dms\n", plaintextAccepted, plaintextElapsed)
	writeEvidence(ew, "grpc", cfg.Technique, cfg.URL, "", 0,
		fmt.Sprintf("%dms", plaintextElapsed), "probe", fmt.Sprintf("plaintext h2 preface: accepted=%v", plaintextAccepted))

	// Test 2: TLS HTTP/2
	throttle.Wait()
	*probeCount++
	start = time.Now()

	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", host, &tls.Config{
		ServerName:         parsed.Hostname(),
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})
	tlsElapsed := time.Since(start).Milliseconds()
	if err == nil {
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			_ = tlsConn.SetDeadline(time.Now().Add(timeout))
			_, writeErr := tlsConn.Write(http2ClientPrelude)
			if writeErr == nil {
				buf := make([]byte, 64)
				n, readErr := tlsConn.Read(buf)
				if readErr == nil && n >= 4 && buf[3] == 0x04 {
					tlsAccepted = true
				}
			}
		}
		tlsConn.Close()
	}
	totalElapsed = tlsElapsed
	fmt.Fprintf(os.Stderr, "[TLS] accepted=%v %dms\n", tlsAccepted, tlsElapsed)
	writeEvidence(ew, "grpc", cfg.Technique, cfg.URL, "", 0,
		fmt.Sprintf("%dms", tlsElapsed), "probe", fmt.Sprintf("TLS h2 preface: accepted=%v", tlsAccepted))

	tlsRequired := tlsAccepted && !plaintextAccepted

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "grpc",
		Technique:     cfg.Technique,
		StartedAt:     timer.StartedAt(),
		ProbeCount:    *probeCount,
		Duration:      timer.Elapsed(),
		Measurements: GRPCMeasurements{
			Technique:         cfg.Technique,
			PlaintextAccepted: plaintextAccepted,
			TLSAccepted:       tlsAccepted,
			TLSRequired:       tlsRequired,
			ElapsedMs:         totalElapsed,
		},
	}, nil
}

// extractServiceNames does a simple scan for service name strings in a gRPC response body.
// Looks for length-prefixed strings containing "." (likely fully-qualified service names).
func extractServiceNames(body []byte) []string {
	if len(body) < 5 {
		return nil
	}

	// Skip 5-byte gRPC frame header
	data := body
	if len(data) > 5 {
		data = data[5:]
	}

	var services []string
	seen := make(map[string]bool)

	for i := 0; i < len(data)-1; i++ {
		// Look for protobuf string field patterns: tag byte followed by length byte
		if data[i] == 0x0a || data[i] == 0x12 || data[i] == 0x1a || data[i] == 0x22 {
			length := int(data[i+1])
			if length > 0 && length < 200 && i+2+length <= len(data) {
				candidate := string(data[i+2 : i+2+length])
				if strings.Contains(candidate, ".") && isPrintable(candidate) && !seen[candidate] {
					seen[candidate] = true
					services = append(services, candidate)
				}
			}
		}
	}

	return services
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
