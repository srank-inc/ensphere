package evidence

import "regexp"

var redactionPatterns = []*regexp.Regexp{
	// JWTs (eyJ followed by base64 characters)
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),

	// Bearer tokens in headers or values
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9_\-.]+`),

	// Sensitive query parameters: password=, secret=, token=, key=, apikey=, api_key=, api-key=
	regexp.MustCompile(`(?i)(password|secret|token|key|apikey|api_key|api-key)=[^&\s]+`),
}

// RedactSecrets replaces sensitive values in a string with [REDACTED].
func RedactSecrets(s string) string {
	for _, re := range redactionPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
