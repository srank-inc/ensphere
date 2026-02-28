package cmd

import (
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vulnerabilities with targeted probes",
	Long: `Run targeted verification probes against specific vulnerability types.

Available subcommands:
  sqli            Verify SQL injection (blind_time, blind_boolean, error_based)
  xss             Verify reflected cross-site scripting
  idor            Verify insecure direct object reference
  ssrf            Verify server-side request forgery
  auth            Verify authentication bypass
  rls             Verify Supabase RLS tenant isolation
  cmdi            Verify command injection
  lfi             Verify local file inclusion
  ssti            Verify server-side template injection
  xxe             Verify XML external entity injection
  deserialization Verify insecure deserialization
  csrf            Verify cross-site request forgery
  nosql           Verify NoSQL injection
  jwt             Verify JWT manipulation
  cors            Verify CORS misconfiguration
  protopollution  Verify prototype pollution
  graphql         Verify GraphQL abuse
  race            Verify race condition
  smuggling       Verify request smuggling
  cachepoisoning  Verify cache poisoning
  redirect        Verify open redirect
  csvinjection    Verify CSV injection
  authz           Verify authorization bypass
  clickjacking    Verify clickjacking protection (X-Frame-Options, CSP frame-ancestors)
  headerinjection Verify CRLF header injection
  websocket       Verify WebSocket security
  grpc            Verify gRPC security`,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
