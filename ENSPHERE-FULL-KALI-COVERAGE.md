# Ensphere External Tool and Kali Integration Strategy

Last updated: 2026-06-08

This document supersedes the older framing that Ensphere should expand into a
default post-exploitation platform. The active direction is now the one
defined in [docs/ensphere-autonomous-pentest-expansion-plan.html](docs/ensphere-autonomous-pentest-expansion-plan.html):
evidence-first autonomous application security assessment, broad coverage by
default, and optional prove-by-exploitation only when explicitly enabled.

## Current Position

Ensphere is not a general post-exploitation platform by default. Its current
product center is:

- A deterministic Go CLI for scoped measurements.
- A portable AI-agent methodology for authorized application, API, cloud,
  Kubernetes, and IaC assessment.
- A workspace runner that creates handoff files, validates plans, blocks uncited
  reports, prepares selected Session 10 findings, and derives Session 11 final
  registries.
- A factual evidence model with hash chains, redaction, transcript paths, and
  report gates.

External tools can strengthen coverage, but they must not replace the native
measurement boundary. Their output is imported as source-provided leads or
transcripts. The AI agent or human analyst decides relevance, severity,
confidence, exploitability, and attack-path meaning in reports.

## Non-Negotiables

- No CLI-owned vulnerability `status`, `confidence`, `confirmed`, `safe`, or
  `potential` fields in measurement output.
- No scanner severity laundering: imported severity stays source-provided until
  corroborated by native Ensphere evidence or explicit manual proof.
- No broad exploitation by inference. Session 10 requires explicit enablement,
  selected finding IDs, risk limits, approval gates, writable evidence paths,
  and cleanup expectations.
- No hidden evidence. Every report finding must cite an evidence ID, transcript,
  import reference, artifact, or explicitly labeled manual note.
- No out-of-scope probing. External tools must receive the same scope discipline
  as native verify commands.

## What Is Shipped Today

| Area | Current Support | Evidence Boundary |
|------|-----------------|-------------------|
| Native probes | 33 scoped measurement families across injection, auth, authz, SSRF, XSS, API, protocol, rate-limit, and file-upload classes | Ensphere measurements only |
| Payloads | 1206 YAML-seeded payloads across 27 vulnerability types, compiled into embedded SQLite | Payload selection facts |
| Evidence | JSONL writer/reader/verifier with `EVID-XXX` IDs, hash-chain integrity, redaction, and cross-process locking | Factual ledger |
| Runner | `run init`, `plan`, `status`, `next`, `report`, `exploit`, and `final` | Workspace and gate facts |
| Cloud | Provider CLI probes plus Prowler and Trivy parser support | Native cloud facts and source-provided parser facts |
| OpenAPI | OpenAPI v3 parser | API inventory facts |
| Source review | Sink pattern scanner and framework checklists | Pattern-match leads |
| Templates | 13 Python 3 stdlib-only exploit templates | Optional Session 10 scaffolding |

## Roadmap: External Tool Ingestion

Track 5 of the expansion plan adds importers for common security tools. These
importers should normalize output into the same workspace/evidence model while
preserving source provenance.

| Tool Class | First Importer Value | Required Boundary |
|------------|----------------------|-------------------|
| Nmap | Host, port, service, version, NSE script output | Inventory or lead only; no vulnerability status |
| Nuclei | Template ID, matched URL, extracted values, source severity | Source severity only |
| SARIF | Static analysis rule ID, file path, region, message | Source-provided SAST lead |
| ZAP/Burp | Alert, request, response, evidence snippet, scanner confidence | Scanner lead requiring review or native corroboration |
| SQLMap | Target, parameter, DBMS, technique, transcript path | Tool-provided proof only when transcripted and scoped |

Importer output should record:

- `source_tool`
- `source_file`
- source rule, template, plugin, or finding ID
- source severity and confidence when provided
- raw matched evidence or transcript path
- parser status and parse errors
- workspace-relative artifact paths

## Kali-Style Tools

Kali, Parrot, or a custom security workstation can be useful execution
environments, but they are not required for the default Ensphere workflow.
When Kali-style tools are used, they should be handled as scoped tools that
produce transcripts or importable artifacts.

Good fit:

- Nmap for inventory.
- Nuclei for template-driven leads.
- SQLMap for explicitly scoped SQL injection proof in Session 10.
- ZAP or Burp exports for HTTP scanner leads.
- Trivy and Prowler for cloud, container, and IaC evidence.
- `kubectl`, cloud CLIs, and provider audit tools when those assets are in
  scope.

Not default:

- Credential dumping.
- Persistence.
- C2 implants.
- Lateral movement.
- Domain compromise workflows.
- Unbounded password spraying or brute force.
- Destructive post-exploitation.

Those activities may belong in a future separately scoped expansion pack, but
they are not part of the current evidence-first application assessment product.

## Session Mapping

| Session | External Tool Role |
|---------|--------------------|
| 01 Recon | Inventory imports such as Nmap or crawler outputs may support target classification. |
| 01.5 Plan | Imported inventory can inform run, skip, limited, blocked, and not-applicable decisions. |
| 02-08 Assessment | External outputs create leads; native probes, transcripts, or manual notes provide corroborating evidence. |
| 09 Report | Scanner leads are labeled source-provided unless corroborated. |
| 10 Exploitation | External exploit tools may run only for selected Session 09 finding IDs and approved risk limits. |
| 11 Final Report | Outcomes from Session 10 can update finding buckets without rewriting Session 09 evidence. |

Session 10 details belong in
[skills/methodology/10-exploitation.md](skills/methodology/10-exploitation.md).
Use its playbook model for web/app, cloud/container, network service,
credential, host privilege, identity, and chained-impact proof. Do not recreate
the old infrastructure workflow as a mandatory sequence.

## Safe Usage Rules

External tool execution must be reproducible and auditable:

1. Record the exact command, version, scope, input file, and output path.
2. Save raw output under `ensphere-pentest/` using workspace-relative paths.
3. Import or cite the output with source provenance intact.
4. Redact secrets before publication.
5. Keep scanner results separate from native Ensphere measurements.
6. Stop or mark the session blocked if evidence capture fails.

## Product Implication

The right product direction is not "wrap every Kali tool." The right direction
is to make external tools first-class evidence sources while preserving the
native measurement core. Ensphere should give an AI agent disciplined hands:
scope, payloads, measurements, evidence, import provenance, report gates, and
explicit exploitation approval.

## Acceptance Criteria

External-tool integration is complete enough when:

- Importers preserve source provenance and source-provided severity.
- Imported leads can be cited in finding registries without becoming factual CLI
  judgments.
- Session 09 report gates reject uncited or unsafe artifact paths.
- Session 10 refuses broad exploitation and accepts only selected, registry-backed
  finding IDs.
- Sample reports show imported leads, native measurements, skipped sessions, and
  optional exploitation outcomes separately.
