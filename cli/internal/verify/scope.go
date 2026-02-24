package verify

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// CheckScope validates that a URL's hostname matches at least one in-scope pattern.
// Patterns use glob syntax (e.g., "*.example.com", "localhost").
func CheckScope(rawURL string, inScopePatterns []string) error {
	if len(inScopePatterns) == 0 {
		return fmt.Errorf("no in-scope patterns provided — refusing to probe")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL %q has no hostname", rawURL)
	}

	for _, pattern := range inScopePatterns {
		pattern = strings.TrimSpace(pattern)
		matched, err := filepath.Match(pattern, hostname)
		if err != nil {
			continue
		}
		if matched {
			return nil
		}
	}

	return fmt.Errorf("URL hostname %q is not in scope (patterns: %s)", hostname, strings.Join(inScopePatterns, ", "))
}
