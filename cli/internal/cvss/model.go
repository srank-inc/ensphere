package cvss

// CvssOutput is the JSON output for the cvss command.
type CvssOutput struct {
	VectorString string            `json:"vector_string"`
	BaseScore    float64           `json:"base_score"`
	Severity     string            `json:"severity"`
	Metrics      map[string]string `json:"metrics"`
}

// SeverityRating returns the severity label for a CVSS score.
func SeverityRating(score float64) string {
	switch {
	case score == 0.0:
		return "None"
	case score <= 3.9:
		return "Low"
	case score <= 6.9:
		return "Medium"
	case score <= 8.9:
		return "High"
	default:
		return "Critical"
	}
}
