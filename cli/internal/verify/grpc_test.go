package verify

import (
	"testing"
)

func TestExtractServiceNames(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		wantLen  int
		wantName string // at least one expected service name
	}{
		{
			name:    "empty",
			body:    nil,
			wantLen: 0,
		},
		{
			name:    "too short",
			body:    []byte{0x00, 0x01},
			wantLen: 0,
		},
		{
			name: "mock reflection response with service name",
			// 5-byte gRPC frame header + protobuf with a string field containing "grpc.reflection.v1alpha.ServerReflection"
			body: func() []byte {
				service := "grpc.reflection.v1alpha.ServerReflection"
				// gRPC frame header (5 bytes): compressed=0, length = len(protobuf)
				protoLen := 2 + len(service) // tag + length + string
				frameLen := protoLen
				frame := []byte{0x00, 0x00, 0x00, 0x00, byte(frameLen)}
				// Protobuf: tag 0x0a (field 1, wire type 2), length, string
				proto := []byte{0x0a, byte(len(service))}
				proto = append(proto, []byte(service)...)
				return append(frame, proto...)
			}(),
			wantLen:  1,
			wantName: "grpc.reflection.v1alpha.ServerReflection",
		},
		{
			name: "no dotted names",
			body: func() []byte {
				s := "nodots"
				frame := []byte{0x00, 0x00, 0x00, 0x00, byte(2 + len(s))}
				proto := []byte{0x0a, byte(len(s))}
				proto = append(proto, []byte(s)...)
				return append(frame, proto...)
			}(),
			wantLen: 0, // "nodots" has no "." so it's filtered out
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractServiceNames(tt.body)
			if len(got) != tt.wantLen {
				t.Fatalf("extractServiceNames() returned %d services, want %d: %v", len(got), tt.wantLen, got)
			}
			if tt.wantName != "" {
				found := false
				for _, s := range got {
					if s == tt.wantName {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("expected service name %q in %v", tt.wantName, got)
				}
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"hello.world", true},
		{"grpc.reflection.v1", true},
		{"", true},
		{"has\x00null", false},
		{"has\nnewline", false},
		{string([]byte{0x01}), false},
	}
	for _, tt := range tests {
		got := isPrintable(tt.input)
		if got != tt.want {
			t.Errorf("isPrintable(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
