package cvss

import (
	"fmt"
	"math"
)

// roundUp rounds val up to the nearest tenth (0.1).
// For example: 4.02 -> 4.1, 4.0 -> 4.0, 4.10001 -> 4.2.
func roundUp(val float64) float64 {
	return math.Ceil(val*10) / 10.0
}

// CalculateV31 computes a CVSS v3.1 base score from the eight base metrics.
//
// Parameters are single-letter abbreviation values:
//
//	av: Attack Vector (N, A, L, P)
//	ac: Attack Complexity (L, H)
//	pr: Privileges Required (N, L, H)
//	ui: User Interaction (N, R)
//	s:  Scope (U, C)
//	c:  Confidentiality Impact (H, L, N)
//	i:  Integrity Impact (H, L, N)
//	a:  Availability Impact (H, L, N)
func CalculateV31(av, ac, pr, ui, s, c, i, a string) (*CvssOutput, error) {
	// --- validate inputs ---
	avWeights := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acWeights := map[string]float64{"L": 0.77, "H": 0.44}
	prWeightsUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightsChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	uiWeights := map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeights := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	scopeValues := map[string]bool{"U": true, "C": true}

	avW, ok := avWeights[av]
	if !ok {
		return nil, fmt.Errorf("invalid Attack Vector (AV): %q, expected N/A/L/P", av)
	}
	acW, ok := acWeights[ac]
	if !ok {
		return nil, fmt.Errorf("invalid Attack Complexity (AC): %q, expected L/H", ac)
	}
	if !scopeValues[s] {
		return nil, fmt.Errorf("invalid Scope (S): %q, expected U/C", s)
	}

	var prW float64
	if s == "U" {
		prW, ok = prWeightsUnchanged[pr]
	} else {
		prW, ok = prWeightsChanged[pr]
	}
	if !ok {
		return nil, fmt.Errorf("invalid Privileges Required (PR): %q, expected N/L/H", pr)
	}

	uiW, ok := uiWeights[ui]
	if !ok {
		return nil, fmt.Errorf("invalid User Interaction (UI): %q, expected N/R", ui)
	}

	cW, ok := ciaWeights[c]
	if !ok {
		return nil, fmt.Errorf("invalid Confidentiality (C): %q, expected H/L/N", c)
	}
	iW, ok := ciaWeights[i]
	if !ok {
		return nil, fmt.Errorf("invalid Integrity (I): %q, expected H/L/N", i)
	}
	aW, ok := ciaWeights[a]
	if !ok {
		return nil, fmt.Errorf("invalid Availability (A): %q, expected H/L/N", a)
	}

	// --- compute ISS ---
	iss := 1.0 - ((1.0 - cW) * (1.0 - iW) * (1.0 - aW))

	var baseScore float64

	if iss <= 0 {
		baseScore = 0.0
	} else {
		// Exploitability sub-score
		exploitability := 8.22 * avW * acW * prW * uiW

		var impact float64
		if s == "U" {
			impact = 6.42 * iss
			baseScore = roundUp(math.Min(impact+exploitability, 10.0))
		} else {
			// Scope Changed
			impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss*0.9731-0.02, 13)
			baseScore = roundUp(math.Min(1.08*(impact+exploitability), 10.0))
		}
	}

	vector := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		av, ac, pr, ui, s, c, i, a)

	return &CvssOutput{
		Version:      "3.1",
		VectorString: vector,
		BaseScore:    baseScore,
		Severity:     SeverityRating(baseScore),
		Metrics: map[string]string{
			"AV": av,
			"AC": ac,
			"PR": pr,
			"UI": ui,
			"S":  s,
			"C":  c,
			"I":  i,
			"A":  a,
		},
	}, nil
}
