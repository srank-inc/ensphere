# Ensphere Documentation Index

Last updated: 2026-07-18

This directory is the system of record for project documentation. `CLAUDE.md`,
`AGENTS.md`, and the root [../index.md](../index.md) point here for durable
docs.

## Active Direction

Ensphere is a local, evidence-first, agent-guided application security
assessment workflow. The shipped system centers on a deterministic CLI, portable agent
methodology, workspace runner gates, and factual evidence. External scanner
ingestion is a roadmap track unless a specific importer is documented in the CLI
reference.

## Core Docs

| Doc | Purpose | When to Read |
|-----|---------|--------------|
| [../index.md](../index.md) | Project-wide index and dependency surface | First orientation pass |
| [../ENSPHERE-GO-SPEC.md](../ENSPHERE-GO-SPEC.md) | Current Go CLI implementation contract and conformance notes | Implementing or auditing CLI behavior |
| [cli-reference.md](cli-reference.md) | Full CLI command reference and output contracts | Running or integrating Ensphere CLI commands |
| [agent-workflow.md](agent-workflow.md) | AI-agent assessment workflow | Running agent-guided assessments |
| [development.md](development.md) | Architecture, build, testing, contribution, and generated-file rules | Changing code or generated assets |
| [testing.md](testing.md) | Test file inventory, conventions, drift guard details | Writing/debugging tests |
| [../skills/shared/workflow-contract.md](../skills/shared/workflow-contract.md) | Session lifecycle, decisions, coverage, safety, human-operation boundary, and reporting contract | Implementing or auditing workflow behavior |
| [../skills/shared/evidence-standards.md](../skills/shared/evidence-standards.md) | Provenance, evidence strength, finding status, controlled validation, and report honesty | Writing session reports or evidence artifacts |

## Folder Indexes

| Folder | Index | Purpose |
|--------|-------|---------|
| [../skills/evaluation/](../skills/evaluation/) | [../skills/evaluation/README.md](../skills/evaluation/README.md) | Blind ground-truth methodology evaluation protocol |
| [../skills/methodology/](../skills/methodology/) | [../skills/methodology/index.md](../skills/methodology/index.md) | Session 01-11 methodology map |
| [../skills/shared/](../skills/shared/) | [../skills/shared/index.md](../skills/shared/index.md) | Evidence categories, coverage labels, and agent/Ensphere contract |
| [../skills/checklists/](../skills/checklists/) | [../skills/checklists/index.md](../skills/checklists/index.md) | Framework-specific checklist inventory |
| [../assets/seeds/](../assets/seeds/) | [../assets/seeds/index.md](../assets/seeds/index.md) | Payload seed inventory |
| [../templates/](../templates/) | [../templates/index.md](../templates/index.md) | Workspace config template inventory |

## Removed Docs

The old commercial-model Markdown files were removed intentionally. Do not treat
commercial planning as an active roadmap unless a new plan is written.
