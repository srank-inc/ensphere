<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

# Ensphere

Ensphere is a deterministic security automation toolkit for authorized application and cloud assessments. It combines a Go CLI, curated payload data, verification probes, evidence logging, exploit templates, source sink discovery, compliance mapping, and AI-agent methodology files.

The project is built around a strict product boundary:

> Ensphere produces verifiable facts. The AI or human analyst produces all security judgments.

Ensphere can send requests, measure timing, hash responses, count rows, validate scope, redact secrets, calculate CVSS from supplied metrics, and map findings to compliance frameworks. It does not decide whether a vulnerability is confirmed, exploitable, high-confidence, or safe. Those conclusions belong in the analyst report.

## What It Provides

| Capability | Purpose |
|------------|---------|
| Curated payload database | 1206 payloads across 27 vulnerability types, generated from YAML seeds into embedded SQLite |
| Verification probes | 33 scoped measurement probes for SQLi, XSS, SSRF, auth, authz, cloud, API, and protocol issues |
| Evidence logging | JSONL evidence with write-time `EVID-XXX` IDs, hash-chain integrity, redaction, and cross-process locking |
| Exploit templates | Python 3 stdlib-only templates for reproducible proof-of-concept work |
| Static sink discovery | Regex-based source sink candidates labeled as `analysis_depth: "pattern_match"` |
| Cloud parsing and probes | Provider CLI-based checks plus Prowler and Trivy result ingestion |
| Compliance mapping | OWASP, PCI-DSS, SOC 2, ISO 27001, and OWASP API Security mappings |
| Agent methodology | Portable skill files and assessment runbooks for Claude Code and Codex |

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

## Requirements

- Go 1.26.3 or newer
- macOS, Linux, or another Go-supported platform
- Optional: Claude Code or Codex for agent-guided assessments
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
| [docs/agent-workflow.md](docs/agent-workflow.md) | Claude Code and Codex assessment workflow |
| [docs/development.md](docs/development.md) | Architecture, build, testing, and contribution rules |
| [docs/testing.md](docs/testing.md) | Test inventory, CI gates, and generated drift checks |
| [docs/dogfood/README.md](docs/dogfood/README.md) | Local dogfood runbooks |

## Distribution

Ensphere is proprietary software. No license is granted unless provided separately in a written agreement with the project owner.
