# Ensphere Project Index

Last updated: 2026-07-18

Use this file as the fast orientation layer for AI agents and contributors. It
points to the durable project rules, active plans, generated assets, and
folder-local indexes.

## Start Here

| Need | File |
|------|------|
| Human-facing overview and quick start | [README.md](README.md) |
| Agent/developer operating rules | [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) |
| Full documentation map | [docs/index.md](docs/index.md) |
| CLI command reference | [docs/cli-reference.md](docs/cli-reference.md) |
| Agent assessment workflow | [docs/agent-workflow.md](docs/agent-workflow.md) |
| Installed skill entry point | [skills/SKILL.md](skills/SKILL.md) |
| Current Go CLI specification | [ENSPHERE-GO-SPEC.md](ENSPHERE-GO-SPEC.md) |

## Current Direction

Ensphere is an evidence-first, agent-guided application security assessment
system. The Go CLI remains a deterministic
measurement engine: Ensphere produces verifiable facts; the AI or human analyst
produces security judgments.

The active direction is a broad, adaptive, complete assessment in Sessions
01–09. Session 10 optionally accepts human-authorized impact validation for
explicitly selected findings, and Session 11 attaches those outcomes without
overwriting the Session 09 judgment. External tools are source-provided leads
that must preserve provenance and stay separate from Ensphere-owned
measurements.

Commercial-model specifications are intentionally absent from the current
project docs. If that ever changes, write a new model from scratch.

## Repository Map

| Path | Purpose |
|------|---------|
| [cli/cmd/](cli/cmd/) | Cobra command layer. Keep commands thin. |
| [cli/internal/](cli/internal/) | Deterministic business logic packages. |
| [cli/internal/runner/](cli/internal/runner/) | Agent workspace runner, plan/report/final gates, Session 10 handoff. |
| [assets/seeds/](assets/seeds/) | YAML payload source data compiled into embedded SQLite. |
| [skills/](skills/) | Agent skill, methodology, checklists, and shared contracts. |
| [skills/evaluation/](skills/evaluation/) | Blind ground-truth benchmark protocol, manifest, and reviewer template. |
| [docs/](docs/) | Engineering docs, workflow docs, and testing. |
| [templates/](templates/) | Workspace configuration template. |

## Folder Indexes

| Area | Index |
|------|-------|
| Documentation | [docs/index.md](docs/index.md) |
| Assessment methodology | [skills/methodology/index.md](skills/methodology/index.md) |
| Shared workflow contracts | [skills/shared/index.md](skills/shared/index.md) |
| Framework checklists | [skills/checklists/index.md](skills/checklists/index.md) |
| Payload seeds | [assets/seeds/index.md](assets/seeds/index.md) |
| Config templates | [templates/index.md](templates/index.md) |

## Dependency Surface

| Dependency | Source of truth | Notes |
|------------|-----------------|-------|
| Go toolchain | [cli/go.mod](cli/go.mod) | CI uses the Go version file. |
| Go modules | [cli/go.mod](cli/go.mod) and [cli/go.sum](cli/go.sum) | Run `cd cli && go get -u all && go mod tidy` for dependency refreshes. |
| Python | Embedded template shebangs | Templates are Python 3 stdlib-only; there is no Python package lock. |
| Generated payload DB | [assets/seeds/](assets/seeds/) -> [cli/internal/payloads/payloads.sqlite](cli/internal/payloads/payloads.sqlite) | Regenerate with `make seeds` or `make build`. |
| Generated checklist data | [skills/checklists/](skills/checklists/) -> [cli/internal/checklist/data/](cli/internal/checklist/data/) | Regenerate with `make checklists` or `make build`. |

## Verification Commands

```bash
cd cli && go test ./...
make build
make smoke
make verify-generated
```
