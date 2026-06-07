# Shared Workflow Index

Last updated: 2026-06-07

These files define the cross-session contracts used by the CLI runner, skill
methodology, reports, and future autonomous workflows.

| File | Purpose | Read When |
|------|---------|-----------|
| [workflow-contract.md](workflow-contract.md) | Session decisions, applicability values, coverage labels, evidence categories, agent contract, report honesty rules | Implementing runner behavior, writing session plans, auditing reports |
| [evidence-standards.md](evidence-standards.md) | Evidence row rules, proof levels, escalation ladder, reproducibility, report honesty | Writing evidence, findings, and reports |

## Key Contract

Ensphere measures facts. The AI or human analyst interprets them.

Ensphere may execute requests, validate scope, hash outputs, compare raw values,
calculate CVSS from supplied metrics, map compliance controls, and verify path
safety. Ensphere must not classify vulnerabilities, assign confidence, decide
exploitability, or imply coverage that did not happen.

## Evidence Categories

Use the shared category names consistently:

| Category | Meaning |
|----------|---------|
| `imported_lead` | Source-provided scanner or external tool lead; not Ensphere-confirmed. |
| `ensphere_measurement` | Deterministic CLI measurement or generated evidence. |
| `agent_judgment` | AI or human interpretation backed by evidence. |
| `exploit_attempt` | Session 10 factual attempt record. |
| `exploit_result` | Session 10/11 outcome backed by proof evidence. |

## Coverage Labels

Use `full`, `partial`, `blocked`, `source_only`, `black_box_only`,
`client_only`, and `cloud_only` exactly as defined in
[workflow-contract.md](workflow-contract.md).
