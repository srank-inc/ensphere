# Development Guide

## Core Principle

Ensphere is an evidence-first, agent-guided assessment system built around a
measurement and execution engine. The CLI and generated assets produce
deterministic facts. The AI or human analyst produces security judgments.

Allowed in code:

- Execute HTTP requests
- Measure timing and sizes
- Hash requests and responses
- Compare raw values
- Count rows and matches
- Validate scope
- Redact secrets
- Calculate CVSS from fixed user-supplied metrics
- Map to compliance frameworks

Not allowed in code:

- Assign vulnerability status
- Assign confidence
- Decide exploitability
- Treat thresholds as proof
- Declare a finding confirmed, potential, or safe

## Repository Layout

| Path | Purpose |
|------|---------|
| `cli/cmd/` | Cobra command files |
| `cli/internal/` | Business logic packages |
| `cli/internal/verify/` | Verification probe logic |
| `cli/internal/evidence/` | JSONL evidence writer and reader |
| `cli/internal/payloads/` | Embedded SQLite payload database and query logic |
| `cli/internal/runner/` | Workspace runner, assessment-plan drafting, report/final gates, Session 10 handoff |
| `cli/internal/templates/` | Embedded Python 3 measurement templates |
| `cli/internal/checklist/` | Embedded checklist loader |
| `cli/internal/compliance/` | Compliance mappings |
| `cli/internal/cvss/` | CVSS v4.0 calculator |
| `cli/internal/scan/` | Regex-based sink scanner |
| `cli/internal/sinks/` | Sink pattern database |
| `cli/internal/callback/` | OOB callback HTTP listener |
| `cli/internal/cloud/` | Cloud probes and parser logic |
| `cli/internal/openapi/` | OpenAPI parser |
| `cli/internal/enums/` | Shared enum validation maps |
| `cli/tools/seedgen/` | YAML to SQLite payload compiler |
| `assets/seeds/` | Payload YAML sources |
| `skills/` | Agent methodology and checklists |
| `docs/` | Product and engineering documentation |

## Build

```bash
make build
make seeds
make checklists
make install
make install-all
make clean
```

`payloads.sqlite` is generated from YAML seeds but intentionally tracked so CI can detect drift. Do not edit it directly.

## Testing

```bash
make test
make smoke
make verify-generated
cd cli && go test -short ./...
cd cli && go test ./...
cd cli && go test -race -short ./internal/verify/
```

See [testing.md](testing.md) for the full test inventory and generated-artifact workflow.

## Command Rules

- Keep one Cobra command file per command under `cli/cmd/`.
- Keep business logic in `cli/internal/<package>/`.
- Commands should parse flags, build config, call internal logic, and encode output.
- Structured output should use indented JSON.
- Verify commands must validate `--in-scope` before network execution.
- Header parsing must reject malformed `--header` values as usage errors.

## Adding Payloads

1. Edit or create YAML under `assets/seeds/`.
2. Follow the `defaults:` plus `payloads:` format.
3. Run `make verify-generated`.
4. Commit YAML changes and regenerated embedded assets together.

Valid enum values are defined in `cli/internal/enums/enums.go`.

## Adding Commands

1. Create `cli/cmd/<name>.go`.
2. Create or extend `cli/internal/<package>/`.
3. Register the command with its parent in `init()`.
4. Add subprocess or focused package tests.
5. Update [cli-reference.md](cli-reference.md) when the public contract changes.

## Documentation Rules

- Keep README human-facing and concise.
- Keep [../index.md](../index.md), [index.md](index.md), and folder-local
  indexes current when adding or retiring major docs, plans, runbooks, seeds,
  checklists, benchmark protocols, or runbooks.
- Put CLI details in [cli-reference.md](cli-reference.md).
- Put agent workflow and runner semantics in [agent-workflow.md](agent-workflow.md), [../skills/shared/workflow-contract.md](../skills/shared/workflow-contract.md), and `skills/`.
- Update [testing.md](testing.md) when test inventory, gates, or drift checks change.
