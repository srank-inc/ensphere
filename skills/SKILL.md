---
name: ensphere
description: Evidence-first methodology for authorized software security assessments. Use when starting or resuming an Ensphere assessment, planning category coverage, validating candidates with deterministic measurements, producing the Session 09 report, or running optional human-authorized Sessions 10–11.
---

# Ensphere

Ensphere is an evidence-first assessment workflow for software the user is
authorized to assess.

> Ensphere produces verifiable facts. The analyst produces all security
> judgments.

Read [shared/workflow-contract.md](shared/workflow-contract.md) and
[shared/evidence-standards.md](shared/evidence-standards.md) before running a
session. Their scope, evidence, controlled-validation, stop, and reporting rules
override examples in category files.

## Start or Resume

When the user says `ensphere` or names a session:

1. Locate `ensphere-pentest/config.md` and `progress.md`.
2. If the workspace is absent, collect the first-run inputs below and initialize
   it. Never assume authorization from repository access alone.
3. Read `ensphere run status` output, the assessment plan, the selected
   session's methodology, the prior session report, and any checkpoint.
4. Confirm the selected target when the workspace contains multiple deployable
   applications or backends. Do not silently assess every repository.
5. State the active mode and material limits:
   - `WHITE_BOX`: source/configuration plus an authorized live target;
   - `BLACK_BOX`: authorized live target without source;
   - `SOURCE_ONLY`: source/configuration without a live target.
6. Resume the recorded candidate and coverage state. Do not repeat completed
   probes merely because the conversation context changed.
7. Follow the session lifecycle in the shared workflow contract.

Ask for user direction when authorization, target identity, environment, or a
material boundary cannot be established safely. Missing optional context is a
coverage limitation, not permission to broaden testing.

## First-Run Inputs

Initialize with `ensphere run init` when available, or create equivalent
workspace configuration containing:

- selected target URL or artifact and target type;
- source availability and path;
- explicitly in-scope and out-of-scope assets;
- test environment and stability constraints;
- supplied test identities, roles, tenants, and owned/synthetic data;
- prohibited actions and request/action limits;
- cloud accounts/projects/subscriptions/clusters, if applicable;
- authorization attestation;
- optional Session 10 disabled by default.

Never place real secrets in reports, prompts, command history examples, or
published artifacts.

## Session Map

Read only the methodology needed for the current session and directly linked
provider appendix.

| Session | Methodology | Outcome |
|---------|-------------|---------|
| 01 | [Recon](methodology/01-recon.md) | Target profile and provenance-backed attack-surface inventory. |
| 01.5 | [Session plan](methodology/01.5-session-plan.md) | Evidence-backed applicability and coverage plan. |
| 02 | [Injection](methodology/02-injection.md) | Injection candidate resolution. |
| 03 | [Authentication](methodology/03-auth.md) | Authentication and session-control candidate resolution. |
| 04 | [Authorization](methodology/04-authz.md) | Object, function, and workflow authorization candidate resolution. |
| 05 | [XSS](methodology/05-xss.md) | Render-context and client execution candidate resolution. |
| 06 | [SSRF](methodology/06-ssrf.md) | Outbound-fetch policy candidate resolution. |
| 07 | [Cloud](methodology/07-cloud.md) | Read-only cloud, Kubernetes, and IaC assessment. |
| 08 | [API](methodology/08-api.md) | API-specific control candidate resolution. |
| 09 | [Assessment report](methodology/09-report.md) | Complete decision-ready report and finding registry. |
| 10 | [Human-authorized impact validation](methodology/10-impact-validation.md) | Optional outcomes for an explicitly selected subset. |
| 11 | [Validation-aware report](methodology/11-final-report.md) | Optional derived report that preserves Session 09 judgments. |

Sessions 01, 01.5, and 09 always run. Sessions 02–08 follow the evidence-backed
applicability plan. Sessions 10–11 are not part of normal completion.

## Standard Session Artifacts

Each session directory should contain, as applicable:

- `plan.md`: scope, limits, coverage matrix, candidates, and controls;
- `evidence.jsonl`: deterministic factual measurements;
- `transcripts/` or `artifacts/`: workspace-relative supporting material;
- `checkpoint.md`: resumable position and remaining candidates;
- `report.md`: coverage, findings, tested defenses, limitations, and evidence
  index.

Update `progress.md` only after the report is written. Use `DONE`, `SKIPPED`,
`BLOCKED`, or `NOT_APPLICABLE`; these are workflow states, not security
conclusions.

## Checkpoints

Before a long operation or context boundary, record:

- current phase and coverage-matrix position;
- completed candidate IDs and their resolution;
- remaining candidates and why they matter;
- evidence paths and latest hash-chain state;
- target identity/role/state needed to resume;
- request/action counters and stop conditions.

Delete the checkpoint only after the session report and progress update are
complete.

## Tool Use

Use Ensphere as the deterministic measurement layer. Consult `ensphere help`
and subcommand help for current CLI syntax instead of relying on duplicated
command catalogs in this skill.

- `ensphere scan`, sink patterns, and source citations create candidates; they
  do not confirm vulnerabilities.
- payload queries select controlled inputs; a payload's presence in the corpus
  does not make it appropriate for the current scope.
- verify commands record measurements. Read raw baseline/probe/control output
  and apply the evidence standard; never inherit a conclusion from a threshold.
- external scanners remain source-provided leads until corroborated.
- calculate CVSS v4.0 only after the analyst fixes the metric inputs.
- if a CLI example conflicts with the approved scope or shared stop rules, do
  not run it.

## End Protocol

1. Resolve every planned candidate or record why it remains `not_tested`.
2. Reconcile the coverage matrix with actual work.
3. Verify cited evidence paths and evidence-chain state.
4. Write the session report using the category methodology.
5. Mark the session terminal and prepare only the next applicable session.
6. Tell the user the result, material limitations, and next session.

Do not automatically continue across sessions.

After Session 09, the assessment is complete. Do not offer, enter, or execute
Session 10 unless the human explicitly enables it and selects finding IDs with
`ensphere run validate-impact`. For every selected finding, prepare the exact
bounded plan and pause. A human must then authorize that plan revision and name
its executor. Serialize that approval in the strict authorization record and
require `ensphere run impact-ready` to return `ready: true` before any action.
The executor may be the human or the AI agent. Never treat broad assessment
authorization as authorization for Session 10.

Session 11 runs only when the human explicitly requests `ensphere run final`
after valid Session 10 outcomes exist. `run next` must not offer or start it. It
attaches optional validation results without overwriting the Session 09 finding
status or evidence.

Methodology changes are evaluated with the blind, ground-truth protocol in
[evaluation/README.md](evaluation/README.md). Do not consult benchmark answers
during an assessment or present benchmark branding as evidence.

## Non-Negotiable Report Rules

- No uncited finding.
- No broad "safe" or "secure" claim from bounded testing.
- No scanner severity presented as Ensphere severity.
- No attack path presented as observed unless every edge has evidence.
- No compliance certification language from an assessment mapping.
- No universal remediation deadline detached from business context.
- No impact-validation outcome used as the base finding status.
- No implication that optional Session 10 covered findings it did not select.
