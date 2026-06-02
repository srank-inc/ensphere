package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/srank/ensphere/internal/verify"
)

var errUsage = errors.New("usage error")
var osExit = os.Exit

func parseHeaders(raw []string) (map[string]string, error) {
	headers := make(map[string]string)
	for _, h := range raw {
		key, value, ok := strings.Cut(h, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("%w: malformed --header %q (expected key:value)", errUsage, h)
		}
		headers[key] = value
	}
	return headers, nil
}

func mustParseHeaders(raw []string) map[string]string {
	headers, err := parseHeaders(raw)
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
		return nil
	}
	return headers
}

func encodeJSON(out interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func exitForVerifyError(err error) int {
	var scopeErr *verify.ScopeError
	if errors.As(err, &scopeErr) || errors.Is(err, errUsage) {
		return 2
	}
	return 3
}

func runVerify(fn func() (*verify.ProbeResult, error)) error {
	result, err := fn()
	if err != nil {
		writeVerifyError(err)
		osExit(exitForVerifyError(err))
	}
	if err := encodeJSON(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		osExit(3)
	}
	return nil
}

func writeVerifyError(err error) {
	var scopeErr *verify.ScopeError
	switch {
	case errors.As(err, &scopeErr):
		fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
	case errors.Is(err, errUsage):
		fmt.Fprintf(os.Stderr, "usage error: %s\n", err)
	default:
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
	}
}
