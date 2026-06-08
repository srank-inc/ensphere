# Ensphere Documentation Index

Last updated: 2026-06-08

This directory is the system of record for project documentation. `CLAUDE.md`,
`AGENTS.md`, and the root [../index.md](../index.md) point here for durable
docs.

## Active Direction

Ensphere is a local, evidence-first autonomous application security assessment
workflow. The shipped system is centered on a deterministic CLI, portable agent
methodology, workspace runner gates, and factual evidence. External scanner
ingestion is a roadmap track unless a specific importer is documented in the CLI
reference.

## Core Docs

| Doc | Purpose | When to Read |
|-----|---------|--------------|
| [../index.md](../index.md) | Project-wide index and dependency surface | First orientation pass |
| [cli-reference.md](cli-reference.md) | Full CLI command reference and output contracts | Running or integrating Ensphere CLI commands |
| [agent-workflow.md](agent-workflow.md) | AI-agent assessment workflow | Running agent-guided assessments |
| [development.md](development.md) | Architecture, build, testing, contribution, and generated-file rules | Changing code or generated assets |
| [testing.md](testing.md) | Test file inventory, conventions, drift guard details | Writing/debugging tests |
| [../skills/shared/workflow-contract.md](../skills/shared/workflow-contract.md) | Session decisions, coverage labels, evidence categories, agent contract, report honesty rules | Implementing or auditing autonomous workflow behavior |
| [../skills/shared/evidence-standards.md](../skills/shared/evidence-standards.md) | Evidence logging, proof levels, and report honesty rules | Writing session reports or evidence artifacts |

## Plans

| Plan | Status | Use |
|------|--------|-----|
| [ensphere-autonomous-pentest-expansion-plan.html](ensphere-autonomous-pentest-expansion-plan.html) | Active roadmap | Evidence-first autonomy, optional exploitation, runner gates, benchmark plan |
| [../ENSPHERE-FULL-KALI-COVERAGE.md](../ENSPHERE-FULL-KALI-COVERAGE.md) | External tool integration strategy | Kali-style tools as source-provided leads and optional Session 10 inputs |
| [production-grade-hardening-plan.html](production-grade-hardening-plan.html) | Reference plan | Production hardening acceptance criteria and historical implementation context |

## Folder Indexes

| Folder | Index | Purpose |
|--------|-------|---------|
| [dogfood/](dogfood/) | [dogfood/index.md](dogfood/index.md) | Local vulnerable targets and sample report regeneration rules |
| [../skills/methodology/](../skills/methodology/) | [../skills/methodology/index.md](../skills/methodology/index.md) | Session 01-11 methodology map |
| [../skills/shared/](../skills/shared/) | [../skills/shared/index.md](../skills/shared/index.md) | Evidence categories, coverage labels, and agent/Ensphere contract |
| [../skills/checklists/](../skills/checklists/) | [../skills/checklists/index.md](../skills/checklists/index.md) | Framework-specific checklist inventory |
| [../assets/seeds/](../assets/seeds/) | [../assets/seeds/index.md](../assets/seeds/index.md) | Payload seed inventory |
| [../templates/](../templates/) | [../templates/index.md](../templates/index.md) | Workspace config template inventory |
| [../sample-reports/](../sample-reports/) | [../sample-reports/index.md](../sample-reports/index.md) | Evidence-backed sample reports |

## Removed Docs

The old commercial-model Markdown files were removed intentionally. Do not treat
commercial planning as an active roadmap unless a new plan is written.
