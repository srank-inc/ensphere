package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/cvss"
)

var (
	cvssVersion string
	cvssAV      string
	cvssAC      string
	cvssPR      string
	cvssUI      string
	cvssS       string
	cvssC       string
	cvssI       string
	cvssA       string
	cvssAT      string
	cvssVC      string
	cvssVI      string
	cvssVA      string
	cvssSC      string
	cvssSI      string
	cvssSA      string
)

var cvssCmd = &cobra.Command{
	Use:   "cvss",
	Short: "Calculate CVSS base scores",
	Long: `Calculate CVSS base scores from metric values.

Supports CVSS v3.1 and v4.0. Outputs JSON with the vector string, numeric
score, and severity rating.

Examples:
  # CVSS v3.1
  ensphere cvss --version 3.1 --av N --ac L --pr N --ui N --s U --c H --i H --a H

  # CVSS v4.0
  ensphere cvss --version 4.0 --av N --ac L --at N --pr N --ui N \
    --vc H --vi H --va H --sc H --si H --sa H`,
	RunE: runCvss,
}

func init() {
	cvssCmd.Flags().StringVar(&cvssVersion, "version", "", "CVSS version: 3.1 or 4.0 (required)")
	cvssCmd.Flags().StringVar(&cvssAV, "av", "", "Attack Vector (N/A/L/P)")
	cvssCmd.Flags().StringVar(&cvssAC, "ac", "", "Attack Complexity (L/H)")
	cvssCmd.Flags().StringVar(&cvssPR, "pr", "", "Privileges Required (N/L/H)")
	cvssCmd.Flags().StringVar(&cvssUI, "ui", "", "User Interaction")
	cvssCmd.Flags().StringVar(&cvssS, "s", "", "Scope (U/C) [v3.1 only]")
	cvssCmd.Flags().StringVar(&cvssC, "c", "", "Confidentiality (H/L/N) [v3.1 only]")
	cvssCmd.Flags().StringVar(&cvssI, "i", "", "Integrity (H/L/N) [v3.1 only]")
	cvssCmd.Flags().StringVar(&cvssA, "a", "", "Availability (H/L/N) [v3.1 only]")
	cvssCmd.Flags().StringVar(&cvssAT, "at", "", "Attack Requirements (N/P) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssVC, "vc", "", "Vulnerable Confidentiality (H/L/N) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssVI, "vi", "", "Vulnerable Integrity (H/L/N) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssVA, "va", "", "Vulnerable Availability (H/L/N) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssSC, "sc", "", "Subsequent Confidentiality (H/L/N) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssSI, "si", "", "Subsequent Integrity (H/L/N) [v4.0 only]")
	cvssCmd.Flags().StringVar(&cvssSA, "sa", "", "Subsequent Availability (H/L/N) [v4.0 only]")

	rootCmd.AddCommand(cvssCmd)
}

func runCvss(cmd *cobra.Command, args []string) error {
	version := strings.TrimSpace(cvssVersion)
	if version == "" {
		return fmt.Errorf("--version is required (3.1 or 4.0)")
	}

	var result *cvss.CvssOutput
	var err error

	switch version {
	case "3.1":
		if err := requireFlags("v3.1", map[string]string{
			"--av": cvssAV, "--ac": cvssAC, "--pr": cvssPR, "--ui": cvssUI,
			"--s": cvssS, "--c": cvssC, "--i": cvssI, "--a": cvssA,
		}); err != nil {
			return err
		}
		result, err = cvss.CalculateV31(
			strings.ToUpper(cvssAV), strings.ToUpper(cvssAC),
			strings.ToUpper(cvssPR), strings.ToUpper(cvssUI),
			strings.ToUpper(cvssS),
			strings.ToUpper(cvssC), strings.ToUpper(cvssI), strings.ToUpper(cvssA),
		)

	case "4.0":
		if err := requireFlags("v4.0", map[string]string{
			"--av": cvssAV, "--ac": cvssAC, "--at": cvssAT,
			"--pr": cvssPR, "--ui": cvssUI,
			"--vc": cvssVC, "--vi": cvssVI, "--va": cvssVA,
			"--sc": cvssSC, "--si": cvssSI, "--sa": cvssSA,
		}); err != nil {
			return err
		}
		result, err = cvss.CalculateV40(
			strings.ToUpper(cvssAV), strings.ToUpper(cvssAC), strings.ToUpper(cvssAT),
			strings.ToUpper(cvssPR), strings.ToUpper(cvssUI),
			strings.ToUpper(cvssVC), strings.ToUpper(cvssVI), strings.ToUpper(cvssVA),
			strings.ToUpper(cvssSC), strings.ToUpper(cvssSI), strings.ToUpper(cvssSA),
		)

	default:
		return fmt.Errorf("unsupported CVSS version: %q (use 3.1 or 4.0)", version)
	}

	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// requireFlags checks that every flag in the map has a non-empty value.
func requireFlags(label string, flags map[string]string) error {
	var missing []string
	for name, val := range flags {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s requires flags: %s", label, strings.Join(missing, ", "))
	}
	return nil
}
