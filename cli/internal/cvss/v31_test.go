package cvss

import (
	"testing"
)

func TestCalculateV31(t *testing.T) {
	tests := []struct {
		name     string
		av       string
		ac       string
		pr       string
		ui       string
		s        string
		c        string
		i        string
		a        string
		score    float64
		severity string
	}{
		{
			name:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical",
			av:       "N", ac: "L", pr: "N", ui: "N", s: "U",
			c: "H", i: "H", a: "H",
			score:    9.8,
			severity: "Critical",
		},
		{
			name:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium",
			av:       "N", ac: "L", pr: "N", ui: "R", s: "C",
			c: "L", i: "L", a: "N",
			score:    6.1,
			severity: "Medium",
		},
		{
			name:     "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N = 5.5 Medium",
			av:       "L", ac: "L", pr: "N", ui: "R", s: "U",
			c: "H", i: "N", a: "N",
			score:    5.5,
			severity: "Medium",
		},
		{
			name:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 Critical",
			av:       "N", ac: "L", pr: "N", ui: "N", s: "C",
			c: "H", i: "H", a: "H",
			score:    10.0,
			severity: "Critical",
		},
		{
			name:     "CVSS:3.1/AV:P/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N = 0.0 None (ISS=0)",
			av:       "P", ac: "H", pr: "N", ui: "R", s: "U",
			c: "N", i: "N", a: "N",
			score:    0.0,
			severity: "None",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateV31(tt.av, tt.ac, tt.pr, tt.ui, tt.s, tt.c, tt.i, tt.a)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.BaseScore != tt.score {
				t.Errorf("score = %v, want %v", result.BaseScore, tt.score)
			}
			if result.Severity != tt.severity {
				t.Errorf("severity = %q, want %q", result.Severity, tt.severity)
			}
			if result.Version != "3.1" {
				t.Errorf("version = %q, want %q", result.Version, "3.1")
			}
		})
	}
}

func TestCalculateV31_InvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		av   string
		ac   string
		pr   string
		ui   string
		s    string
		c    string
		i    string
		a    string
	}{
		{name: "invalid AV", av: "X", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "H"},
		{name: "invalid AC", av: "N", ac: "X", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "H"},
		{name: "invalid PR", av: "N", ac: "L", pr: "X", ui: "N", s: "U", c: "H", i: "H", a: "H"},
		{name: "invalid UI", av: "N", ac: "L", pr: "N", ui: "X", s: "U", c: "H", i: "H", a: "H"},
		{name: "invalid S", av: "N", ac: "L", pr: "N", ui: "N", s: "X", c: "H", i: "H", a: "H"},
		{name: "invalid C", av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "X", i: "H", a: "H"},
		{name: "invalid I", av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "X", a: "H"},
		{name: "invalid A", av: "N", ac: "L", pr: "N", ui: "N", s: "U", c: "H", i: "H", a: "X"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CalculateV31(tt.av, tt.ac, tt.pr, tt.ui, tt.s, tt.c, tt.i, tt.a)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestSeverityRating(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.0, "None"},
		{0.1, "Low"},
		{3.9, "Low"},
		{4.0, "Medium"},
		{6.9, "Medium"},
		{7.0, "High"},
		{8.9, "High"},
		{9.0, "Critical"},
		{10.0, "Critical"},
	}

	for _, tt := range tests {
		got := SeverityRating(tt.score)
		if got != tt.expected {
			t.Errorf("SeverityRating(%v) = %q, want %q", tt.score, got, tt.expected)
		}
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{4.0, 4.0},
		{4.02, 4.1},
		{4.1, 4.1},
		{4.10001, 4.2},
		{0.0, 0.0},
	}

	for _, tt := range tests {
		got := roundUp(tt.input)
		if got != tt.expected {
			t.Errorf("roundUp(%v) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
