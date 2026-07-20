# Ensphere External Tool Integration Plan

Last reviewed: 2026-07-18
Status: Active roadmap

## Verdict

Ensphere should ingest evidence from external security tools; it should not try
to become a wrapper around every tool in a security distribution.

The useful product is a common provenance contract: external output enters the
workspace as a source-provided lead, keeps its original claims intact, and can
be cited or corroborated without becoming an Ensphere judgment. This plan
covers parsing existing artifacts. It does not authorize or automate tool
execution.

The active methodology remains [skills/SKILL.md](skills/SKILL.md), with the
responsibility boundary defined by
[skills/shared/workflow-contract.md](skills/shared/workflow-contract.md).

## Product Boundary

| Evidence source | What Ensphere may record | Who interprets it |
|-----------------|--------------------------|-------------------|
| Native Ensphere probe | Requests, responses, timing, hashes, callbacks, counts, and configuration values | AI or human analyst |
| External tool artifact | Tool identity, version, rule, source severity/confidence, matched data, parser state, and raw artifact reference | AI or human analyst |
| Source review | Cited file, line, pattern match, configuration, and data-flow facts | AI or human analyst |
| Optional impact validation | Human-authorized plan, transcript, artifacts, outcome, executor, and cleanup evidence | Human names a human or AI executor; analyst interprets and reports |

An importer must never emit Ensphere-owned vulnerability status, confidence,
severity, exploitability, or business impact. Source severity and confidence
remain explicitly source-provided.

## Shipped Baseline

Ensphere currently provides:

- native, scoped measurement commands for 33 vulnerability families;
- 1,206 payload records across 27 payload-backed vulnerability types;
- JSONL evidence with write-time IDs, redaction, locking, and hash-chain
  verification;
- Prowler and Trivy parsers under the cloud command surface;
- source sink candidates, framework checklists, and an OpenAPI parser;
- Session 09 report gates and optional human-authorized Sessions 10–11.

Prowler and Trivy are existing format-specific parsers and the migration
starting point. They do not yet satisfy the common provenance and parser-state
contract proposed below.

## Common Import Contract

Every importer should produce a collection of source-provided leads with these
fields:

```yaml
source:
  tool: nuclei
  version: "[captured version]"
  artifact: "imports/nuclei.jsonl"
  captured_at: "[timestamp]"
  scope_reference: "config.md#scope"
parser:
  name: "ensphere-nuclei"
  state: complete
  errors: []
leads:
  - source_id: "[template or result id]"
    rule_id: "[rule or template id]"
    source_severity: "[verbatim source value]"
    source_confidence: "[verbatim source value, if supplied]"
    asset: "[normalized in-scope asset]"
    location: "[endpoint, port, file, or resource]"
    observed_data: "[lossless redacted observation]"
    raw_reference: "imports/nuclei.jsonl#[stable locator]"
```

Required behavior:

1. Parse local, explicitly supplied artifacts; do not launch the source tool.
2. Preserve unknown fields or retain a raw reference so parsing is not lossy.
3. Reject unsafe workspace paths and record partial parsing rather than hiding
   errors.
4. Preserve the source tool's exact severity and confidence vocabulary.
5. Deduplicate only exact source identities; leave semantic deduplication to the
   analyst.
6. Never turn a lead into a finding automatically.

## Priority Order

### 1. Establish the shared importer package

Create one internal model and validation path for provenance, parse state,
artifact references, source claims, and lead identity. Migrate Prowler and Trivy
to it without changing their meaning.

Acceptance:

- malformed or partial artifacts produce explicit parser issues;
- raw artifacts remain citable inside the workspace;
- source severity cannot appear as analyst-assigned severity;
- importer output contains no finding judgment fields.

### 2. Add SARIF

SARIF is the best first general importer because it gives Ensphere broad static
analysis coverage through one documented interchange format.

Capture rule ID, tool component, file URI, region, message, level, fingerprints,
and result properties. Treat every result as a source-review lead until the
analyst verifies reachability and security meaning.

### 3. Add Nuclei and Nmap

- **Nuclei:** preserve template ID, matcher/extractor output, matched asset,
  source severity, and raw result reference.
- **Nmap:** preserve host, port, protocol, service, version claim, script ID,
  script output, and scan scope. Service/version detection is inventory, not a
  vulnerability conclusion.

### 4. Add ZAP and Burp exports

Support stable export formats rather than live proxy control. Preserve alert
identity, request/response references, scanner confidence, evidence excerpts,
and affected locations. Authentication and macro state remain limitations
unless captured in the source artifact.

### 5. Prove report integration

Add fixtures showing imported-only leads, corroborated findings, duplicate
source results, parser failures, and redacted artifacts. Session 09 must display
source provenance and coverage limitations without laundering scanner claims.

## Tools That Do Not Belong in the Default Import Roadmap

Credential dumping, persistence, command-and-control, lateral movement,
password spraying, destructive post-exploitation, and denial-of-service
workflows are outside Ensphere's application-assessment product boundary.

SQLMap or another impact-oriented tool may appear only as an artifact from an
exactly authorized Session 10 plan. Ensphere may ingest its transcript. An AI
may launch it only when the human authorization names the AI as executor and
the exact command, target, environment, limits, stop conditions, and cleanup
are within that plan.

## Session Mapping

| Session | Imported artifact role |
|---------|------------------------|
| 01 Recon | Add inventory facts and candidate surfaces. |
| 01.5 Plan | Support applicability and coverage decisions. |
| 02–08 Assessment | Create leads that require analyst review or corroboration. |
| 09 Report | Cite source-provided leads with provenance and limitations. |
| 10 Human-authorized validation | Accept executor-produced artifacts only for explicitly selected findings and an exactly authorized plan. |
| 11 Validation-aware report | Attach the selected outcomes without changing Session 09 statuses. |

## Non-Goals

- Owning installation or lifecycle management for external tools.
- Reproducing a security distribution's command catalog.
- Running scanners automatically because a target technology was detected.
- Treating scanner agreement as proof.
- Converting external severity into Ensphere severity.
- Expanding scope through discovered hosts, URLs, accounts, or cloud resources.
- Giving an AI agent default, inferred, or open-ended impact-validation authority.

## Completion Criteria

This roadmap is complete when:

- all importers use the common provenance and parser-state contract;
- Prowler, Trivy, SARIF, Nuclei, Nmap, and stable ZAP/Burp exports have fixture
  coverage;
- report gates validate citations and workspace paths for imported artifacts;
- reports distinguish imported leads, Ensphere measurements, source review,
  analyst judgments, and human- or agent-executed validation evidence;
- parser failures and unsupported source fields remain visible;
- no importer executes its source tool or assigns a security conclusion;
- dogfood reports demonstrate imported-only, corroborated, contradicted, and
  untested leads.

## Decision Rule

Add an importer when it improves evidence coverage across multiple target
types and can preserve provenance without inventing meaning. Do not add one
merely because the source tool is popular.
