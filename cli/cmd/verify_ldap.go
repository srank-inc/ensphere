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
	ldapURL       string
	ldapParam     string
	ldapTechnique string
	ldapMethod    string
	ldapHeaders   []string
	ldapInScope   []string
	ldapMaxRisk   int
	ldapThrottle  int
	ldapTimeout   int
	ldapEvidence  string
)

var verifyLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "Verify LDAP injection vulnerability",
	Long: `Verify LDAP injection with filter injection, blind boolean, or blind error probes.

Techniques:
  ldap_filter_injection  Inject LDAP filter metacharacters and compare responses (default)
  ldap_blind_boolean     Inject true/false LDAP conditions and compare body hashes
  ldap_blind_error       Inject malformed filter (unbalanced parens) and detect error signatures

Examples:
  ensphere verify ldap --url "http://target/search" --param uid --in-scope "*.target.com"
  ensphere verify ldap --url "http://target/search" --param uid --technique ldap_blind_boolean --in-scope "*.target.com"
  ensphere verify ldap --url "http://target/login" --param username --technique ldap_blind_error --method POST --in-scope "*.target.com"`,
	RunE: runVerifyLDAP,
}

func init() {
	verifyLDAPCmd.Flags().StringVar(&ldapURL, "url", "", "Target URL (required)")
	verifyLDAPCmd.Flags().StringVar(&ldapParam, "param", "", "Parameter/field name (required)")
	verifyLDAPCmd.Flags().StringVar(&ldapTechnique, "technique", "ldap_filter_injection", "Technique: ldap_filter_injection, ldap_blind_boolean, ldap_blind_error")
	verifyLDAPCmd.Flags().StringVar(&ldapMethod, "method", "GET", "HTTP method")
	verifyLDAPCmd.Flags().StringSliceVar(&ldapHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyLDAPCmd.Flags().StringSliceVar(&ldapInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyLDAPCmd.Flags().IntVar(&ldapMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyLDAPCmd.Flags().IntVar(&ldapThrottle, "throttle", 500, "Milliseconds between probes")
	verifyLDAPCmd.Flags().IntVar(&ldapTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyLDAPCmd.Flags().StringVar(&ldapEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyLDAPCmd.MarkFlagRequired("url")
	_ = verifyLDAPCmd.MarkFlagRequired("param")
	_ = verifyLDAPCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyLDAPCmd)
}

func runVerifyLDAP(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range ldapHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.LDAPConfig{
		URL:       ldapURL,
		Param:     ldapParam,
		Technique: ldapTechnique,
		Method:    ldapMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    ldapInScope,
			MaxRisk:    ldapMaxRisk,
			ThrottleMs: ldapThrottle,
			TimeoutSec: ldapTimeout,
			Headers:    headers,
			Evidence:   ldapEvidence,
		},
	}

	result, err := verify.VerifyLDAP(cfg)
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
