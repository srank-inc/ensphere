# Ensphere Test Reference

## Commands

```bash
make test                                          # go vet + go test ./...
cd cli && go test -short ./...                     # fast: contracts + core + evidence + drift (~258 tests, ~4s)
cd cli && go test ./...                            # full: everything including integration (~309 tests, ~11s)
cd cli && go test -race ./internal/verify/         # race detector on verify package
cd cli && go test -race -short ./internal/verify/  # race detector, fast path only
```

## Test File Inventory

| File | Package | Purpose |
|------|---------|---------|
| `verify/helpers_test.go` | verify | Shared test utilities (newTestServer, baseProbeConfig, assertScopeErr, handler factories) |
| `verify/probe_test.go` | verify | Core infrastructure (CheckScope, CheckMaxRisk, HTTPProbe) |
| `verify/contracts_test.go` | verify | Safety gate contracts for all 33 probes (scope, max-risk, technique validation) |
| `verify/integration_injection_test.go` | verify | Integration: sqli, xss, cmdi, lfi, ssti, xxe, nosql, deserialization, csvinjection, ldap, xpath, fileupload |
| `verify/integration_auth_test.go` | verify | Integration: auth, authz, rls, jwt, cors, csrf, idor, massassignment, countJSONRows |
| `verify/integration_infra_test.go` | verify | Integration: ssrf, redirect, protopollution, graphql, cachepoisoning |
| `verify/smuggling_test.go` | verify | Smuggling: buildSmugglingPayload + rawHTTPProbe |
| `verify/race_test.go` | verify | Race: concurrent burst verification |
| `verify/websocket_test.go` | verify | WebSocket: computeWSAccept, generateWSKey, parseHTTPStatus |
| `verify/grpc_test.go` | verify | gRPC: extractServiceNames, isPrintable |
| `verify/integration_websocket_test.go` | verify | Integration: WebSocket upgrade, origin check, hijack, malformed-101 rejection |
| `verify/integration_grpc_test.go` | verify | Integration: gRPC plaintext detection, reflection probe |
| `verify/ratelimit_test.go` | verify | Integration: sequential burst, no throttling, window expiry |
| `verify/propertyauthz_test.go` | verify | Integration: field difference, identical responses, watch fields, non-JSON |
| `evidence/evidence_test.go` | evidence | Hash chain integrity, redaction, read/write/filter, NextID (empty/missing/existing), malformed line handling |
| `payloads/drift_test.go` | payloads | Docs drift guard (payload count + vuln type canary values) |
| `cloud/parser_test.go` | cloud | Prowler/Trivy parser + vuln type mapping |
| `cloud/compute_test.go` | cloud | AWS/GCP/Azure compute parse functions |
| `cloud/logging_test.go` | cloud | CloudTrail/GCP sinks/Azure diagnostics parse functions |
| `cloud/secrets_test.go` | cloud | Secrets Manager/Secret Manager/Key Vault parse functions |
| `openapi/parser_test.go` | openapi | OpenAPI v3 JSON/YAML parsing, auth detection, parameter merge, HTTP error handling |
| `callback/server_test.go` | callback | OOB callback server: request recording, timeout, multiple callbacks, token uniqueness, body read error |

## Conventions

- Integration tests skip with `testing.Short()` — use `-short` for fast CI
- Assertions are **relational** (e.g., `PayloadAvgMs > BaselineAvgMs`), never exact values or message strings
- No `t.Parallel()` in timing-sensitive or raw-TCP tests
- Use `newTestServer(t, handler)` for all test HTTP servers (IPv4-only, auto-cleanup); never use `httptest.NewServer` directly
- Use `t.Cleanup()` for net.Listener, temp files
- Drift test canary values (1206 payloads, 27 DB vuln types) must be updated alongside docs when payloads change
