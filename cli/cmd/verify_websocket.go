package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	wsURL       string
	wsTechnique string
	wsPayload   string
	wsHeaders   []string
	wsInScope   []string
	wsMaxRisk   int
	wsThrottle  int
	wsTimeout   int
	wsEvidence  string
)

var verifyWebSocketCmd = &cobra.Command{
	Use:   "websocket",
	Short: "Verify WebSocket security",
	Long: `Verify WebSocket security via raw TCP handshake and frame analysis.

Techniques:
  ws_injection    Send payload via WebSocket text frame after upgrade
  ws_hijack       Attempt upgrade with evil origin
  ws_origin_check Three sub-probes: no origin, null origin, evil origin

Examples:
  ensphere verify websocket --url "ws://target/ws" --technique ws_injection --payload "<script>alert(1)</script>" --in-scope "*.target.com"
  ensphere verify websocket --url "ws://target/ws" --technique ws_origin_check --in-scope "*.target.com"`,
	RunE: runVerifyWebSocket,
}

func init() {
	verifyWebSocketCmd.Flags().StringVar(&wsURL, "url", "", "Target WebSocket URL (required)")
	verifyWebSocketCmd.Flags().StringVar(&wsTechnique, "technique", "", "Technique: ws_injection, ws_hijack, ws_origin_check (required)")
	verifyWebSocketCmd.Flags().StringVar(&wsPayload, "payload", "", "Payload to send as WebSocket text frame")
	verifyWebSocketCmd.Flags().StringSliceVar(&wsHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyWebSocketCmd.Flags().StringSliceVar(&wsInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyWebSocketCmd.Flags().IntVar(&wsMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyWebSocketCmd.Flags().IntVar(&wsThrottle, "throttle", 500, "Milliseconds between probes")
	verifyWebSocketCmd.Flags().IntVar(&wsTimeout, "timeout", 10, "Request timeout in seconds")
	verifyWebSocketCmd.Flags().StringVar(&wsEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyWebSocketCmd.MarkFlagRequired("url")
	_ = verifyWebSocketCmd.MarkFlagRequired("technique")
	_ = verifyWebSocketCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyWebSocketCmd)
}

func runVerifyWebSocket(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range wsHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.WebSocketConfig{
		URL:       wsURL,
		Technique: wsTechnique,
		Payload:   wsPayload,
		ProbeConfig: verify.ProbeConfig{
			InScope:    wsInScope,
			MaxRisk:    wsMaxRisk,
			ThrottleMs: wsThrottle,
			TimeoutSec: wsTimeout,
			Headers:    headers,
			Evidence:   wsEvidence,
		},
	}

	result, err := verify.VerifyWebSocket(cfg)
	if err != nil {
		var scopeErr *verify.ScopeError
		if errors.As(err, &scopeErr) {
			fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
		os.Exit(3)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
