# Ensphere Go CLI — Current Technical Specification

Last verified against the repository: 2026-07-18
Status: Normative current contract plus explicit implementation conformance notes

## System Boundary

The Go CLI is Ensphere's deterministic measurement, evidence, and workspace
layer. It may execute explicitly scoped operations and record what happened. It
must not decide whether a vulnerability is confirmed, assign confidence or
severity, infer exploitability, or write business-impact judgments.

“Deterministic” describes the CLI's rules and transformations. A live target can
return different observations as its state changes; Ensphere records those
differences rather than forcing a threshold-based conclusion.

| Responsibility | Go CLI | AI or human analyst |
|----------------|--------|---------------------|
| Scope | Parse and enforce configured assets | Decide whether authorization and coverage are sufficient |
| Measurement | Send bounded requests and record raw observations | Define claims and interpret baseline/probe/control evidence |
| Evidence | Assign IDs, redact, hash-chain, validate, and query | Decide what evidence supports or contradicts a finding |
| Source/imports | Preserve available pattern matches and format-specific parsed source fields | Corroborate, deduplicate semantically, classify, and prioritize |
| Reporting | Validate required files, fields, citations, safe paths, and integrity | Write statuses, confidence, severity, impact, priority, and remediation |
| Optional Session 10 | Validate enablement, selected IDs, handoff gates, outcomes, authorization citations, executor provenance, and cleanup records | Analyst writes the plan; a human authorizes it and names a human or AI executor; analyst reports the outcome |

### Current conformance

The current contract removes the known deterministic-layer P0 violations:
cloud probes preserve provider settings and permission actions without
Ensphere-owned exposure or escalation judgments; embedded Python template
metadata lists raw observation fields rather than success thresholds; and the
Session 10/11 gates require exact-plan authorization evidence, executor
provenance, cleanup, and status-preserving derivation.

## Shipped Components

### Payload database

The canonical payload sources are `assets/seeds/*.yaml`. The seed compiler
validates enum values and generates the tracked embedded SQLite database at
`cli/internal/payloads/payloads.sqlite`.

Current canary values:

- 1,206 payload records;
- 27 payload-backed vulnerability types;
- context filters for engine, runtime, technique, surface, content type,
  encoding, boundary, tag, and maximum risk.

Payload selection is deterministic input selection, not a security finding.

### Native measurement probes

The `ensphere verify` command exposes 33 scoped measurement families:

```text
sqli xss idor ssrf auth rls cmdi lfi ssti xxe deserialization
csrf nosql jwt cors protopollution graphql race smuggling
cachepoisoning redirect csvinjection authz clickjacking
headerinjection websocket grpc ratelimit propertyauthz ldap xpath
fileupload massassignment
```

Verify output contains operation metadata and raw measurements. Exact output
shape varies by probe, but it must not contain CLI-owned fields named `status`,
`confidence`, `confirmed`, `safe`, or `potential`.

All verify commands validate `--in-scope` before network execution. Probe
families apply their own risk, technique, timeout, throttle, and bounded-action
validation.

### Evidence ledger

Evidence is JSONL. The writer:

- assigns canonical `EVID-XXX` IDs at write time;
- rejects missing, malformed, or duplicate IDs when continuing an existing
  ledger;
- serializes concurrent writers with a lock file;
- redacts supported secret forms;
- records `prev_hash` and `hash` for tamper-evident verification.

The factual `result` vocabulary is:

```text
baseline probe payload control callback manual_note
```

Finding judgments belong in reports and finding registries, not evidence rows.

### Workspace runner

`ensphere run` manages files under `ensphere-pentest/` and emits JSON summaries.
It does not run the AI.

| Command | Current behavior |
|---------|------------------|
| `run init` | Create the workspace, configuration, progress, and session directories. |
| `run plan` | Draft or strictly validate the assessment plan and Session 01.5 mirror. |
| `run status` | Read progress and expose the next eligible session. |
| `run next` | Write the next-action and agent-prompt handoff files. |
| `run report` | Enforce Session 09 plan, terminal-state, report, evidence, registry, citation, and safe-path gates. |
| `run validate-impact` | Prepare a human-authorized Session 10 handoff for explicitly selected Session 09 finding IDs. The command does not autonomously start the plan. |
| `run impact-ready` | Validate the exact strict plan and SHA-256-bound human authorization before any Session 10 action; execute nothing. |
| `run final` | Validate Session 10 outcomes and derive the Session 11 registry without changing Session 09 statuses. |

Runner YAML is a single current contract. Decoding is strict: unknown fields and
additional YAML documents are rejected. There is no schema-version field or
migration path.

Finding registries contain report-layer judgments such as status, confidence,
evidence strength, severity, priority, CVSS v4.0, impact, remediation, coverage,
and citations. The runner validates these values and their evidence contracts;
it does not originate them.

### Optional human-authorized impact validation

Session 10 is disabled by default. `run validate-impact` requires Session 09 to
be marked `DONE`, requires the complete `run report` gate to pass, validates
exact registry IDs, and writes a human-authorized handoff.

The generated handoff always states:

```yaml
human_authorization_required: true
authorization_record_required: true
environment_acknowledgement_required: true
permitted_executors: [human, agent]
validation_plan_required: true
cleanup_required: true
cleanup_evidence_required: true
```

For each selected finding, the analyst writes a bounded plan and pauses. A
separate human authorization record identifies the exact plan revision and
SHA-256, executor, environment, actions, and limits. The executor may be
`human` or `agent`; a changed plan hash requires new authorization. Before any
action, `run impact-ready` must deterministically validate the strict YAML plan,
authorization, current hash, and authorization/readiness timestamp order with
`ready: true`. Session 11
accepts an outcome only when the authorization hash matches the current plan,
the structured execution record stays inside its action/time/environment
bounds, the pre-execution attestation predates execution, cited Session 10
evidence IDs resolve through a valid hash chain, executor-specific evidence is
present, and cleanup evidence is complete.
The CLI validates the authorization artifact but does not authenticate the
human identity behind a chat or external instruction; that provenance remains
an analyst/agent evidence obligation.

Session 11 copies the Session 09 registry into a derived registry and attaches
`impact_validation_outcome_status`, outcome evidence, and cleanup state to selected
findings. The merge preserves every base finding status.

### Source and external-tool evidence

`ensphere scan` and `ensphere sinks` produce pattern-match candidates. They do
not establish reachability or exploitability.

The cloud package currently has format-specific Prowler and Trivy parsers. They
do not yet implement the complete provenance/parser-state contract. Future work
must preserve provenance and source claims, expose parser errors, and never
assign an Ensphere finding judgment.

### Supporting deterministic resources

- 13 framework/cloud checklists are authored under `skills/checklists/` and
  copied into the binary at build time.
- 13 Python 3 standard-library measurement templates are embedded under
  `cli/internal/templates/data/`. Their metadata lists observation fields, not
  success conditions. Their presence does not authorize execution.
- Compliance mappings cover OWASP, PCI DSS, SOC 2, ISO 27001, and OWASP API
  Security categories. A mapping is context, not certification.
- The CVSS command calculates CVSS v4.0 from user- or analyst-supplied metrics.
  The CLI does not choose those metrics.
- The OpenAPI package parses OpenAPI v3 JSON/YAML into inventory facts.
- The callback listener records bounded out-of-band observations; a callback is
  evidence, not an automatic finding.

## Code Organization

```text
cli/cmd/                 Cobra parsing and JSON output
cli/internal/verify/     scoped measurement implementations
cli/internal/evidence/   JSONL ledger, redaction, locking, integrity
cli/internal/runner/     workspace, planning, report, and optional handoff gates
cli/internal/payloads/   embedded SQLite query layer
cli/internal/cloud/      cloud measurements and Prowler/Trivy parsing
cli/internal/scan/       pattern-match source candidates
cli/internal/sinks/      embedded sink patterns
cli/internal/openapi/    OpenAPI parsing
cli/internal/cvss/       CVSS v4.0 calculation
cli/internal/templates/  embedded measurement templates
cli/internal/checklist/  embedded checklists
cli/internal/compliance/ compliance mappings
cli/internal/callback/   out-of-band observation listener
cli/internal/enums/      canonical enum validation
cli/tools/seedgen/       deterministic YAML-to-SQLite compiler
```

Command files parse flags and call business logic under `cli/internal/`.
Structured command output uses indented JSON. Errors wrap their lower-level
cause with context.

## Generated Assets

```bash
make seeds       # YAML payload sources -> embedded SQLite
make checklists  # skill checklists -> embedded checklist data
make build       # regenerate assets and compile bin/ensphere
```

Generated payload and checklist assets are tracked. `make verify-generated`
regenerates both and fails on drift, including stale files left by a deleted
source checklist.

The SQLite tables are `payloads` and `payload_tags`. Query ordering is stable:
specific nullable-field matches rank ahead of generic fallbacks, followed by
risk and payload ID.

## Current Safety Contract

- Explicit scope validation precedes every verify request.
- The default maximum risk is 3. Most verify families use a fixed probe-family
  risk; SQLi also selects payload records by risk.
- Default inter-probe throttle is 500 ms where the probe uses standard
  throttling.
- Rate-limit testing requires an explicit bounded burst count.
- The methodology requires exact authorization, limits, rollback, and cleanup
  evidence for higher-risk or state-changing work. Verify commands enforce
  scope and command-specific gates but do not read the workspace session plan.
- Path-bearing transcript, artifact, and cleanup-evidence fields are checked
  for safe workspace-relative paths by report/final gates.
- Automatic redaction covers JWTs, bearer tokens, and supported sensitive query
  parameters. The methodology still requires manual secret and personal-data
  review before publication.
- Optional impact validation is disabled by default and executes only after a
  human authorizes the exact plan revision and names its human or AI executor.

Verify-related exit behavior is:

```text
0  probes completed and JSON was emitted
1  Cobra validation errors such as a missing required flag
2  scope errors and command errors explicitly mapped as usage failures
3  runtime or probe failure
```

An exit code of 0 means the measurement operation completed; it is not a
security conclusion.

## Validation and CI

The required repository gates are:

```bash
make test
make smoke
make verify-generated
cd cli && go test -race -short ./internal/verify/
```

GitHub Actions runs the equivalent vet, full test, verify race, smoke, and
generated-drift gates on pushes and pull requests. Current tests cover command
contracts, all 33 verify safety contracts, representative integrations,
evidence integrity, runner/report/final gates, import parsers, generated assets,
and supporting packages.

## Change Rules

1. Treat the current public contract as the only supported contract; do not add
   migration readers, aliases, or retired fields without a new product decision.
2. Keep security judgment out of CLI measurement output.
3. Add or change business logic under `cli/internal/`, not command files.
4. Add focused tests for every public contract or safety-boundary change.
5. Update this specification from the implementation in the same change.
6. Update payload count canaries and docs together when seed data changes.
7. Keep roadmap work in the product, hardening, or external-tool plans; do not
   describe planned behavior as shipped here.
