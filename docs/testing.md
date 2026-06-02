# Ensphere Test Reference

## Commands

```bash
make test                                          # go vet + go test ./...
make smoke                                         # build + basic CLI command checks
make verify-generated                              # regenerate payload/checklist embeds and fail on drift
cd cli && go test -short ./...                     # fast: contracts + core + evidence + drift
cd cli && go test ./...                            # full: everything including integration
cd cli && go test -race ./internal/verify/         # race detector on verify package
cd cli && go test -race -short ./internal/verify/  # race detector, fast path only
```

## CI Gates

GitHub Actions runs on every push and on pull requests. The workflow uses `go-version-file: cli/go.mod`, so CI fails clearly if the declared Go toolchain is unavailable. The required gates are:

- `cd cli && go vet ./...`
- `cd cli && go test ./...`
- `cd cli && go test -race -short ./internal/verify/`
- `make smoke`
- `make verify-generated`

## Generated Artifacts

`make seeds` compiles `assets/seeds/*.yaml` into the embedded SQLite payload database. `make checklists` deletes and recopies `cli/internal/checklist/data/` from `skills/checklists/` so removed source checklists cannot leave stale embeds. `make verify-generated` runs both generators, confirms known generated assets are tracked, and then checks for Git drift in `cli/internal/payloads/payloads.sqlite` and `cli/internal/checklist/data`.

The payload DB uses a fixed generated timestamp for deterministic rebuilds. If payload counts change, update the canary tests and docs together.

## Local Artifacts

Expected local artifacts from builds and smoke runs include `bin/`, `cli/ensphere`, `cli/.gocache/`, `evidence.jsonl`, `evidence.jsonl.lock`, and `ensphere-pentest/`. These are ignored. Committed embedded assets such as `cli/internal/payloads/payloads.sqlite` and `cli/internal/checklist/data/` remain visible to Git and CI.

## JSON Contracts

CLI JSON tests assert parsed semantics rather than pretty formatting. Breaking output changes require an intentional schema version bump where the command exposes `schema_version`. Verify outputs must remain measurement-only and must not add exact JSON fields named `status`, `confidence`, `confirmed`, `safe`, or `potential`.

## Test File Inventory

| File | Package | Purpose |
|------|---------|---------|
| `cmd/helpers_test.go` | cmd | Command helper behavior: header parsing and verify exit-code mapping |
| `cmd/subprocess_test.go` | cmd | Subprocess CLI contract tests for help, JSON output, evidence, scope failure, and malformed headers |
| `verify/helpers_test.go` | verify | Shared test utilities (newTestServer, baseProbeConfig, assertScopeErr, handler factories) |
| `verify/probe_test.go` | verify | Core infrastructure (CheckScope, CheckMaxRisk, HTTPProbe) |
| `verify/sqli_test.go` | verify | SQLi DB engine normalization and DB-specific payload selection |
| `verify/contracts_test.go` | verify | Safety gate contracts for all 33 probes (scope, max-risk, technique validation, forbidden judgment JSON tags) |
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
| `evidence/evidence_test.go` | evidence | Hash chain integrity, redaction, write-time IDs, lock contention, duplicate IDs, read/write/filter, NextID, malformed line handling |
| `payloads/drift_test.go` | payloads | Docs drift guard (payload count + vuln type canary values) |
| `scan/scanner_test.go` | scan | Regex pattern-match scanner: matches, no matches, excludes, absence rules, extension overrides, sorting, redaction |
| `sinks/query_test.go` | sinks | Embedded sink loader, invalid category, and regex compile validation |
| `templates/templates_test.go` | templates | Template listing, invalid lookup, materialization to writer and temp dir |
| `checklist/list_test.go` | checklist | Embedded checklist listing, invalid lookup, markdown title and checkbox parsing |
| `compliance/query_test.go` | compliance | Mapping list, valid lookup, invalid vuln type, no-mapping behavior |
| `tools/seedgen/main_test.go` | seedgen | Fixture-based deterministic seed compilation and invalid seed errors |
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
