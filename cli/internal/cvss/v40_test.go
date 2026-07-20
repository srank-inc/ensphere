package cvss

import (
	"testing"
)

func TestCalculateV40(t *testing.T) {
	tests := []struct {
		name     string
		av       string
		ac       string
		at       string
		pr       string
		ui       string
		vc       string
		vi       string
		va       string
		sc       string
		si       string
		sa       string
		score    float64
		severity string
	}{
		{
			name: "Max severity: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H = 10.0",
			av:   "N", ac: "L", at: "N", pr: "N", ui: "N",
			vc: "H", vi: "H", va: "H",
			sc: "H", si: "H", sa: "H",
			score:    10.0,
			severity: "Critical",
		},
		{
			name: "Zero impact: AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N = 0.0",
			av:   "P", ac: "H", at: "P", pr: "H", ui: "A",
			vc: "N", vi: "N", va: "N",
			sc: "N", si: "N", sa: "N",
			score:    0.0,
			severity: "None",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateV40(tt.av, tt.ac, tt.at, tt.pr, tt.ui,
				tt.vc, tt.vi, tt.va, tt.sc, tt.si, tt.sa)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.BaseScore != tt.score {
				t.Errorf("score = %v, want %v", result.BaseScore, tt.score)
			}
			if result.Severity != tt.severity {
				t.Errorf("severity = %q, want %q", result.Severity, tt.severity)
			}
		})
	}
}

func TestCalculateV40_MacroVectorLookup(t *testing.T) {
	// AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N
	// EQ1: AV=N,PR=N,UI=N → 0
	// EQ2: AC=L,AT=N → 0
	// EQ3: VC=H,VI=L → not(H and H) but (H or L or N) → 1
	// EQ4: SC=H,SI=L → not(H and H) but (H or L or N) → 1
	// EQ5: default 0
	// EQ6: VC=H → 0
	// MacroVector: "001100"
	result, err := CalculateV40("N", "L", "N", "N", "N", "H", "L", "N", "H", "L", "N")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The lookup for "001100" is 9.3; interpolation may adjust slightly.
	if result.BaseScore < 8.0 || result.BaseScore > 10.0 {
		t.Errorf("expected score near 9.3 for MV 001100, got %v", result.BaseScore)
	}
}

func TestCalculateV40_VectorString(t *testing.T) {
	result, err := CalculateV40("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
	if result.VectorString != expected {
		t.Errorf("vector = %q, want %q", result.VectorString, expected)
	}
}

func TestCalculateV40_InvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		av   string
		ac   string
		at   string
		pr   string
		ui   string
		vc   string
		vi   string
		va   string
		sc   string
		si   string
		sa   string
	}{
		{name: "invalid AV", av: "X", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid AC", av: "N", ac: "X", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid AT", av: "N", ac: "L", at: "X", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid PR", av: "N", ac: "L", at: "N", pr: "X", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid UI", av: "N", ac: "L", at: "N", pr: "N", ui: "X", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid VC", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "X", vi: "H", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid VI", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "X", va: "H", sc: "H", si: "H", sa: "H"},
		{name: "invalid VA", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "X", sc: "H", si: "H", sa: "H"},
		{name: "invalid SC", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "X", si: "H", sa: "H"},
		{name: "invalid SI", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "X", sa: "H"},
		{name: "invalid SA", av: "N", ac: "L", at: "N", pr: "N", ui: "N", vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "X"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CalculateV40(tt.av, tt.ac, tt.at, tt.pr, tt.ui,
				tt.vc, tt.vi, tt.va, tt.sc, tt.si, tt.sa)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestBuildMacroVector(t *testing.T) {
	tests := []struct {
		name string
		av   string
		ac   string
		at   string
		pr   string
		ui   string
		vc   string
		vi   string
		va   string
		sc   string
		si   string
		sa   string
		want string
	}{
		{
			name: "all highest severity",
			av:   "N", ac: "L", at: "N", pr: "N", ui: "N",
			vc: "H", vi: "H", va: "H", sc: "H", si: "H", sa: "H",
			want: "000000",
		},
		{
			name: "all lowest severity",
			av:   "P", ac: "H", at: "P", pr: "H", ui: "A",
			vc: "N", vi: "N", va: "N", sc: "N", si: "N", sa: "N",
			want: "212201",
		},
		{
			name: "mixed EQ levels",
			av:   "A", ac: "L", at: "N", pr: "N", ui: "N",
			vc: "H", vi: "L", va: "N", sc: "N", si: "H", sa: "N",
			want: "101100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMacroVector(tt.av, tt.ac, tt.at, tt.pr, tt.ui,
				tt.vc, tt.vi, tt.va, tt.sc, tt.si, tt.sa)
			if got != tt.want {
				t.Errorf("buildMacroVector() = %q, want %q", got, tt.want)
			}
		})
	}
}
