<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

# Ensphere

Ensphere is an evidence-first autonomous application security assessment system for AI agents and human analysts. It combines a deterministic Go CLI, an agent workspace runner, curated payload data, scoped measurement probes, hash-chained evidence, optional exploit planning, source sink discovery, cloud checks, compliance mapping, and portable methodology files.

The project is built around a strict product boundary:

> Ensphere produces verifiable facts. The AI or human analyst produces all security judgments.

Ensphere can send requests, measure timing, hash responses, count rows, validate scope, redact secrets, calculate CVSS from supplied metrics, and map findings to compliance frameworks. It does not decide whether a vulnerability is confirmed, exploitable, high-confidence, or safe. Those conclusions belong in the analyst report.

## What It Provides

| Capability | Purpose |
|------------|---------|
| Curated payload database | 1206 payloads across 27 vulnerability types, generated from YAML seeds into embedded SQLite |
| Native measurement probes | 33 scoped probes for SQLi, XSS, SSRF, auth, authz, cloud, API, and protocol issues |
| Evidence logging | JSONL evidence with write-time `EVID-XXX` IDs, hash-chain integrity, redaction, and cross-process locking |
| Exploit templates | Python 3 stdlib-only templates for reproducible proof-of-concept work |
| Static sink discovery | Regex-based source sink candidates labeled as `analysis_depth: "pattern_match"` |
| Cloud parsing and probes | Provider CLI-based checks plus Prowler and Trivy result ingestion |
| Compliance mapping | OWASP, PCI-DSS, SOC 2, ISO 27001, and OWASP API Security mappings |
| Runner and report gates | Workspace initialization, deterministic session planning, next-action prompts, report readiness gates, Session 10 handoff, and Session 11 final-registry derivation |
| Agent methodology | Portable skill files and adaptive 01-11 assessment workflow for Codex, Claude Code, and other agent surfaces |
| External ingestion roadmap | Nmap, Nuclei, SARIF, ZAP/Burp, SQLMap, and similar tools are planned as source-provided leads, not Ensphere-owned judgments |

The canonical workflow separates assessment from exploitation: Sessions 01-09
produce a broad evidence-backed assessment, Session 10 optionally proves
selected findings by exploitation, and Session 11 regenerates an
exploit-verified final report.

## Quick Start

```bash
git clone https://github.com/srank-com-my/ensphere.git
cd ensphere
make build
./bin/ensphere --help
```

Install the binary globally when you want `ensphere` available from any project:

```bash
make install
```

Install both the binary and AI-agent skill files:

```bash
make install-all
```

Initialize an agent workspace:

```bash
ensphere run init \
  --target "https://staging.example.com" \
  --source yes \
  --target-type api_backend \
  --in-scope staging.example.com

ensphere run plan
ensphere run next
ensphere run report
# Optional after Session 09 is DONE and exploitation is explicitly enabled:
# ensphere run exploit --finding VULN-001
# Optional after Session 10 writes exploit outcomes:
# ensphere run final
```

The runner writes `ensphere-pentest/next-action.md` and
`ensphere-pentest/agent-prompt.md` for Codex, Claude Code, or another subscribed
AI agent surface. `run init` refuses to overwrite an initialized workspace; use
`run status` or `run next` to resume. `run plan` writes a deterministic draft
`assessment-plan.yaml` from config and keeps the Session 01.5 mirror in sync;
Session 01.5 should review and update it after Recon evidence. `run report`
writes the Session 09 readiness gate and checks assessment-plan validity,
terminal session states, session reports, evidence hash chains, and finding
registry contracts. `run exploit` requires Session 09 to be marked `DONE`,
validates selected IDs against the Session 09 finding registry, and writes the
Session 10 handoff with the exploit policy; the runner does not execute
exploitation by itself. `run final` derives the Session 11 finding registry from
Session 10 outcomes without modifying Session 09 evidence or registry
artifacts.

## Requirements

- Go 1.26.4 or newer
- macOS, Linux, or another Go-supported platform
- Optional: Codex, Claude Code, or another subscribed AI agent surface for agent-guided assessments
- Optional: Playwright MCP for browser-driven testing
- Optional: cloud provider CLIs for cloud probes (`aws`, `gcloud`, `az`)

## CLI Examples

Query payloads:

```bash
ensphere payloads sqli --db postgres --technique blind_time
ensphere payloads ssrf --max-risk 2 --limit 5
```

Run scoped verification probes:

```bash
ensphere verify sqli \
  --url "https://target.example/search?id=1" \
  --param id \
  --technique blind_time \
  --in-scope target.example \
  --evidence ./evidence.jsonl
```

Inspect and verify evidence:

```bash
ensphere evidence query --file ./evidence.jsonl --summary
ensphere evidence verify --file ./evidence.jsonl
```

Scan source for sink candidates:

```bash
ensphere scan ./src --category sqli,xss --context-lines 1
```

See the full command reference in [docs/cli-reference.md](docs/cli-reference.md).

## Safety Model

All verify commands require explicit `--in-scope` validation before network execution. Probes also support throttling, timeout controls, and max-risk gates. Scope failures return exit code `2`; runtime failures return exit code `3`.

Verify output is JSON schema v2 and measurement-only:

```json
{
  "schema_version": 2,
  "vuln_type": "sqli",
  "technique": "blind_time",
  "probe_count": 3,
  "measurements": {}
}
```

There is intentionally no CLI-owned `status`, `confidence`, `confirmed`, `safe`, or `potential` field.

## Architecture

```text
assets/seeds/        YAML payload seeds
cli/cmd/             Cobra command layer
cli/internal/        Deterministic business logic
cli/tools/seedgen/   YAML to SQLite generator
skills/              Agent methodology and checklists
docs/                Product, development, testing, and operational references
```

The command layer parses flags and emits JSON. Business logic lives under `cli/internal/`. Generated assets are tracked where CI can verify them.

## Quality Gates

The repository includes GitHub Actions CI for every push and pull request. The local equivalents are:

```bash
make test
make smoke
make verify-generated
cd cli && go test -race -short ./internal/verify/
```

`make verify-generated` rebuilds embedded payload and checklist assets, then fails if generated data drifts from source files.

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/cli-reference.md](docs/cli-reference.md) | Full CLI command reference and output contracts |
| [docs/agent-workflow.md](docs/agent-workflow.md) | AI-agent assessment workflow |
| [docs/development.md](docs/development.md) | Architecture, build, testing, and contribution rules |
| [docs/testing.md](docs/testing.md) | Test inventory, CI gates, and generated drift checks |
| [docs/dogfood/README.md](docs/dogfood/README.md) | Local dogfood runbooks |
| [docs/ensphere-autonomous-pentest-expansion-plan.html](docs/ensphere-autonomous-pentest-expansion-plan.html) | Active evidence-first autonomy roadmap |

## Distribution

Ensphere is proprietary software. No license is granted unless provided separately in a written agreement with the project owner.
