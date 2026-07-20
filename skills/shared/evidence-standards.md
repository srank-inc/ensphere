# Evidence Standards

Read this with [workflow-contract.md](workflow-contract.md). Ensphere records
facts. The analyst—human or AI—turns those facts into findings.

## Evidence Record

Every material observation must be attributable to one of these categories:

| Category | What it records |
|----------|-----------------|
| `imported_lead` | A scanner or external tool result, retaining the source tool, rule, source severity, raw reference, and parse status. |
| `ensphere_measurement` | A deterministic Ensphere request, response, timing, hash, callback, count, or configuration measurement. |
| `source_review` | A cited file, line, data-flow trace, configuration value, or implementation fact. |
| `manual_observation` | A reproducible observation captured in a transcript or artifact. |
| `human_authorization` | Human authorization for an exact plan revision, executor, environment, actions, and limits. |
| `human_execution` | A human-executed optional Session 10 action and its raw observations. |
| `agent_execution` | An AI-agent-executed optional Session 10 action and its raw observations. |
| `agent_judgment` | A cited analytical conclusion: status, confidence, severity, impact, priority, or remediation. |
| `impact_validation_attempt` | An optional Session 10 executor-run action and its observed response. |
| `impact_validation_result` | An optional Session 10 outcome judgment backed by attempt evidence. |

These categories are not values for the JSONL `result` field. Evidence rows use
only factual stages such as `baseline`, `probe`, `payload`, `control`,
`callback`, or `manual_note`.

For every cited artifact preserve:

- evidence ID or workspace-relative path;
- producer and collection time;
- target, endpoint, input, and identity/role context;
- exact request, command, source location, or observation procedure;
- raw result or a lossless redacted representation;
- hash-chain or integrity state where available;
- redactions and known collection limitations.

Imported severity and confidence always remain source-provided until the
analyst independently assesses them.

## Evidence Strength

Evidence strength describes support for a claim, not finding severity.

| Value | Use when |
|-------|----------|
| `direct` | The claimed behavior or policy violation was observed with an appropriate baseline and control, or is unambiguous in source/configuration. |
| `corroborated` | Independent evidence types support the same claim and material alternatives were checked. |
| `indicative` | A relevant signal exists, but a material alternative explanation or missing input remains. |
| `insufficient` | The available evidence cannot support the claim. Preserve it as a lead, limitation, or `not_tested` record. |

Do not promote timing, status-code, response-size, reflection, or scanner output
to `direct` merely because it is repeatable. The measurement must distinguish
the security claim from plausible alternatives.

## Finding Status

Status records the analyst's conclusion about the narrow claim:

| Status | Meaning |
|--------|---------|
| `confirmed` | Evidence directly or through strong corroboration demonstrates the weakness in scope. |
| `likely` | Evidence supports the weakness, but one material uncertainty remains. |
| `informational` | A factual condition worth reporting without asserting an exploitable weakness. |
| `not_supported` | Controlled checks contradict the candidate or support an effective control for the tested case. |
| `not_tested` | The claim could not be evaluated because it was outside scope, blocked, inapplicable, or missing required input. |

Keep these dimensions separate:

- **Confidence**: `high`, `medium`, or `low`—certainty in the status.
- **Severity**: consequence and exploit conditions if the finding is real.
- **Priority**: remediation order after business context, reachability,
  exposure, and compensating controls are considered.
- **Optional validation outcome**: Session 10 result. It never replaces the
  Session 09 status.

`confirmed` normally requires `direct` or `corroborated` evidence. A `likely`
finding may use `indicative` evidence only when the uncertainty and required
validation are explicit. Do not report `insufficient` evidence as a weakness.

## Controlled Validation Cycle

Use this cycle for each candidate in Sessions 02–08:

1. State one narrow, falsifiable claim.
2. Capture a normal baseline using the same endpoint, identity, state, and
   relevant transport conditions.
3. Apply the smallest safe probe that distinguishes the claim.
4. Run a negative or positive control suited to the mechanism.
5. Repeat or interleave only enough trials to address noise or state drift.
6. Compare raw observations; list plausible alternative explanations.
7. Resolve the candidate as `confirmed`, `likely`, `not_supported`, or
   `not_tested`, with evidence strength and confidence.
8. Stop when the narrow claim is resolved.

Do not require arbitrary bypass counts, fixed request counts, or
manual-to-automated escalation. Additional variants must test a named parser,
normalization, state, or control hypothesis. Never broaden scope or increase
impact solely to obtain a more dramatic proof.

## Reproducibility

For a reportable finding include:

- affected asset and exact location;
- prerequisites, identity, role, and state;
- safe reproduction steps and exact non-secret inputs;
- baseline, probe, and control observations;
- expected versus observed behavior;
- evidence citations and artifact integrity state;
- environmental or temporal dependencies;
- cleanup/reversion steps when state changed.

Use placeholders such as `[SESSION_TOKEN]` and `[TEST_OBJECT_ID]`; never publish
live secrets or personal data. Transcript, artifact, and cleanup references
must remain inside the assessment workspace and must not use absolute paths,
URLs, `~`, backslashes, or parent traversal.

## Honest Negative Conclusions

- Say what was tested, against which assets and roles, and with which controls.
- Use `not_supported` for the tested claim; do not write "safe", "secure", or
  "no vulnerabilities" as a broad conclusion.
- Use `not_tested` when required access, roles, data, regions, protocols, or
  environment stability were absent.
- A missing signal is not affirmative proof that a surface is absent.
- Skipped, blocked, partial, source-only, black-box-only, client-only, and
  cloud-only coverage must be visible in both the session report and final
  report.
- Hash-chain, parser, transcript, or artifact failures are report limitations.

## Optional Session 10 Evidence

Session 10 is disabled by default and explicitly selected. The AI prepares the
bounded plan and pauses. A human must authorize that exact revision and name
either the human or AI as executor before any action runs. A separate strict
authorization file records the plan path, revision, SHA-256, human authorizer,
timestamp, executor, environment acknowledgement, exact actions, and
action/time/risk limits. The outcome cites that file and records timestamps,
performed actions, action count, stop-condition state, rollback, and cleanup.
The pre-execution `run impact-ready` JSON is retained in the transcript.

An outcome such as `objective_achieved`, `objective_not_achieved`,
`blocked_by_control`, `blocked_by_constraint`, or `inconclusive` is a separate
validation result. A contradictory result may
trigger an analyst reassessment, but the runner must never overwrite the
Session 09 status automatically.
