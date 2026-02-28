# Ensphere Development Guide

## Design Principle

> **Ensphere produces verifiable facts. The AI produces all security judgments.**

Everything that ships as part of Ensphere — Go code, Python templates, YAML seeds, all tooling — is a **measurement and execution engine**. Given the same inputs, it produces the same outputs every time. Ensphere never classifies, interprets, or judges findings.

**Ensphere is allowed to:** execute HTTP requests, measure timing, hash responses, compare raw values, count rows, validate scope, redact secrets, calculate CVSS from fixed inputs, map to compliance frameworks. All deterministic.

**Ensphere must NOT:** assign status (confirmed/potential/safe), assign confidence (high/medium/low), apply thresholds ("delta > 500ms = SQLi"), decide exploitability, or make any statement that requires interpretation or context. Those are heuristics, not facts — they belong to the AI.

**The AI (Claude / agent)** consumes Ensphere's raw measurements and applies context, reasoning, multi-step correlation, framework knowledge, and security expertise to classify findings, assign confidence, chain attack paths, and write reports.

This separation means: no hallucinated probes (Ensphere owns execution), no fake determinism (Ensphere never pretends to be certain about judgments), and maximum intelligence where it matters (the AI reasons with full context instead of crude thresholds).

## Architecture

Go CLI binary (`ensphere`) + Claude Code skill files (`skills/`). CLI commands and business logic live in `cli/`. Skill methodology and checklists live in `skills/`.

| Path | Purpose |
|------|---------|
| `cli/cmd/` | Cobra command files (one per command) |
| `cli/internal/` | Business logic packages |
| `cli/internal/verify/` | Verification probe logic |
| `cli/internal/evidence/` | JSONL evidence writer/reader |
| `cli/internal/payloads/` | SQLite DB + query logic |
| `cli/internal/templates/` | Pre-built Python 3 exploit scripts |
| `cli/internal/checklist/` | Framework-specific security checklists |
| `cli/internal/compliance/` | Compliance framework mappings |
| `cli/internal/cvss/` | CVSS v3.1/v4.0 scoring engine |
| `cli/internal/scan/` | Static sink pattern scanner |
| `cli/internal/sinks/` | Sink pattern database |
| `cli/internal/enums/` | Enum validation maps |
| `cli/tools/seedgen/` | YAML → SQLite compiler |
| `assets/seeds/` | YAML payload seed files |
| `skills/` | Claude Code skill files |
| `skills/methodology/` | Session methodology (01-08) |
| `skills/checklists/` | Security checklists |
| `skills/shared/` | Evidence standards and proof-level definitions |

## Build

```bash
make build        # YAML seeds → SQLite → Go binary (bin/ensphere)
make seeds        # only recompile seed database
make test         # go vet + go test
make install      # copy binary to /usr/local/bin
make install-all  # install binary + skill files
make clean        # remove build artifacts
```

## Testing

```bash
make test                                          # go vet + go test ./...
cd cli && go test -short ./...                     # fast: contracts + core + evidence + drift (~94 tests, ~3s)
cd cli && go test ./...                            # full: everything including integration (~123 tests, ~5s)
cd cli && go test -race ./internal/verify/         # race detector on verify package
cd cli && go test -race -short ./internal/verify/  # race detector, fast path only
```

Test files are organized by concern:

| File | Package | Purpose |
|------|---------|---------|
| `verify/helpers_test.go` | verify | Shared test utilities (newTestServer, baseProbeConfig, assertScopeErr, handler factories) |
| `verify/probe_test.go` | verify | Core infrastructure (CheckScope, CheckMaxRisk, HTTPProbe) |
| `verify/contracts_test.go` | verify | Safety gate contracts for all 23 probes (scope, max-risk, technique validation) |
| `verify/integration_injection_test.go` | verify | Integration: sqli, xss, cmdi, lfi, ssti, xxe, nosql, deserialization, csvinjection |
| `verify/integration_auth_test.go` | verify | Integration: auth, authz, rls, jwt, cors, csrf, idor |
| `verify/integration_infra_test.go` | verify | Integration: ssrf, redirect, protopollution, graphql, cachepoisoning |
| `verify/smuggling_test.go` | verify | Smuggling: buildSmugglingPayload + rawHTTPProbe |
| `verify/race_test.go` | verify | Race: concurrent burst verification |
| `evidence/evidence_test.go` | evidence | Hash chain integrity, redaction, read/write/filter, NextID (empty/missing/existing) |
| `payloads/drift_test.go` | payloads | Docs drift guard (payload count + vuln type canary values) |

**Test conventions:**
- Integration tests skip with `testing.Short()` — use `-short` for fast CI
- Assertions are **relational** (e.g., `PayloadAvgMs > BaselineAvgMs`), never exact values or message strings
- No `t.Parallel()` in timing-sensitive or raw-TCP tests
- Use `newTestServer(t, handler)` for all test HTTP servers (IPv4-only, auto-cleanup); never use `httptest.NewServer` directly
- Use `t.Cleanup()` for net.Listener, temp files
- Drift test canary values (1059 payloads, 21 vuln types) must be updated alongside docs when payloads change

## Conventions

- **Commands**: One file per command in `cli/cmd/`. Register with parent in `init()`.
- **Logic**: All business logic in `cli/internal/<package>/`. Commands only parse flags, build config, call logic, encode JSON output.
- **JSON output**: `json.NewEncoder(os.Stdout).SetIndent("", "  ")` for all structured output.
- **Errors**: `fmt.Errorf("context: %w", err)` for wrapping.

## Adding Payloads

1. Edit or create YAML in `assets/seeds/`
2. Follow format: `defaults:` section + `payloads:` array
3. All enum values validated at build time (`make build`)
4. Valid enums defined in `cli/internal/enums/enums.go`

## Adding Commands

1. Create `cli/cmd/<name>.go` with Cobra command
2. Create `cli/internal/<package>/` for business logic
3. Register command with parent in `init()`
4. Follow patterns in existing commands (e.g., `verify_sqli.go`)

## What NOT To Do

- Don't modify `payloads.sqlite` directly — it's generated from YAML
- Don't add Go dependencies without clear need
- Don't put business logic in `cli/cmd/` files
- Don't skip `--in-scope` validation on verify commands (all verify commands require it)
