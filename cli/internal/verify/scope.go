package verify

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// ScopeError indicates a scope or usage violation (exit code 2).
type ScopeError struct {
	Msg string
}

func (e *ScopeError) Error() string { return e.Msg }

// CheckScope validates that a URL's hostname matches at least one in-scope pattern.
// Patterns use glob syntax (e.g., "*.example.com", "localhost") or CIDR notation (e.g., "192.168.1.0/24").
func CheckScope(rawURL string, inScopePatterns []string) error {
	if len(inScopePatterns) == 0 {
		return &ScopeError{Msg: "no in-scope patterns provided — refusing to probe"}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &ScopeError{Msg: fmt.Sprintf("invalid URL %q: %v", rawURL, err)}
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return &ScopeError{Msg: fmt.Sprintf("URL %q has no hostname", rawURL)}
	}

	for _, pattern := range inScopePatterns {
		pattern = strings.TrimSpace(pattern)

		// Try CIDR match (e.g., "192.168.1.0/24")
		if _, ipNet, err := net.ParseCIDR(pattern); err == nil {
			if ip := net.ParseIP(hostname); ip != nil && ipNet.Contains(ip) {
				return nil
			}
			continue
		}

		// Fall back to glob match (e.g., "*.example.com")
		matched, err := filepath.Match(pattern, hostname)
		if err != nil {
			continue
		}
		if matched {
			return nil
		}
	}

	return &ScopeError{Msg: fmt.Sprintf("URL hostname %q is not in scope (patterns: %s)", hostname, strings.Join(inScopePatterns, ", "))}
}

// CheckCloudScope validates cloud resource identifiers against in-scope patterns.
// Format: "aws://ACCOUNT_ID", "gcp://PROJECT_ID", "azure://SUBSCRIPTION_ID"
func CheckCloudScope(provider, resourceID string, inScopePatterns []string) error {
	if len(inScopePatterns) == 0 {
		return &ScopeError{Msg: "no in-scope patterns provided"}
	}
	prefix := provider + "://"
	for _, p := range inScopePatterns {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, prefix) {
			scopeID := strings.TrimPrefix(p, prefix)
			if scopeID == resourceID || scopeID == "*" {
				return nil
			}
			if matched, _ := filepath.Match(scopeID, resourceID); matched {
				return nil
			}
		}
	}
	return &ScopeError{Msg: fmt.Sprintf("resource %s://%s not in scope", provider, resourceID)}
}
