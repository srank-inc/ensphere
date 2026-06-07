# Ensphere Workflow Contract

This file is the shared contract for autonomous Ensphere assessments. It keeps
the skill workflow aligned with the product boundary:

> Ensphere produces verifiable facts. The AI or human analyst produces all
> security judgments.

## Native Measurement Core

Ensphere must not be reduced to only a skill plus external tool ingestion.
External tools create leads and coverage, but Ensphere's native probes, payload
corpus, scope validation, evidence writer, callback capture, redaction, and
replayable measurements are the verification layer.

The agent can reason with tool output, but reports become defensible only when
claims cite Ensphere evidence, transcripts, imported leads, or explicitly
labeled manual notes.

## Session Decisions

Use these values in `assessment-plan.yaml` when deciding whether a session
should run.

| Decision | Meaning | Required Record |
|----------|---------|-----------------|
| `run` | Session applies and should execute. | Evidence-backed reason and expected inputs. |
| `skip` | Session does not apply to this target. | Skipped-session report with evidence and limitations. |
| `force` | Human explicitly overrides auto-skip. | Override reason and special scope constraints. |
| `limited` | Session can run only against part of the intended surface. | Coverage limits, missing inputs, and safe alternate checks. |
| `blocked` | Relevant surface exists but cannot execute safely or meaningfully. | Blocking condition, required user input, and residual coverage gap. |
| `uncertain` | Recon did not prove presence or absence of surface. | Default to run unless human accepts skip risk. |
| `not_applicable` | Normal network pentest workflow is not valid for the target type. | Target classification report and recommended alternate mode. |

## Execution States

Use these values in `progress.md` to describe work execution state.

| State | Meaning |
|-------|---------|
| `PENDING` | Not started. |
| `IN_PROGRESS` | Currently running or resumable from checkpoint. |
| `DONE` | Completed and report written. |
| `SKIPPED` | Deliberately skipped with report and reason. |
| `BLOCKED` | Relevant but could not continue without missing input or unsafe action. |
| `NOT_APPLICABLE` | Target type makes this session invalid. |

## Coverage Labels

Every session report and final report coverage table should use one of these
labels.

| Label | Meaning | Report Requirement |
|-------|---------|--------------------|
| `full` | Required inputs were available and the planned session surface was tested. | State covered categories and cite evidence. |
| `partial` | Some relevant surface was tested, but scope, credentials, data, or stability limited coverage. | Name the missing coverage and avoid broad assurance language. |
| `blocked` | Relevant surface exists, but testing could not execute safely or meaningfully. | Record the blocker and required input. |
| `source_only` | Source review occurred without a live executable target. | Call it source review, not dynamic pentest proof. |
| `black_box_only` | Live behavioral testing occurred without source code. | Reference endpoints and transcripts, not file paths. |
| `client_only` | Primary artifact is a mobile, desktop, browser extension, or static client without a supplied backend. | Report client exposure facts and backend testing limitations. |
| `cloud_only` | Target is cloud, Kubernetes, or IaC without an app HTTP surface. | Run cloud checks and state app sessions were not applicable. |

## Evidence Categories

Use these categories when building finding registries and report appendices.
They are not replacements for factual evidence `result` stages.

| Category | Lives In | Meaning | Judgment Boundary |
|----------|----------|---------|-------------------|
| `imported_lead` | Evidence ledger or importer output. | Factual scanner or external tool output: matched URL, template ID, source severity, transcript, or parsed artifact. | Lead only. Source severity is not Ensphere-confirmed severity. |
| `ensphere_measurement` | Evidence ledger. | Native Ensphere probe, payload selection, response measurement, callback receipt, hash, or parser result. | Measurement only. No vulnerability status or confidence. |
| `agent_judgment` | Finding registry, report, or analyst notes. | AI or human classification, confidence, severity, exploitability, business impact, and remediation priority. | Must cite evidence. Never stored as factual CLI measurement. |
| `exploit_attempt` | Session 10 evidence and transcripts. | Planned exploit command, request sequence, expected proof, stop condition, and observed response. | Attempt record only until impact evidence exists. |
| `exploit_result` | Session 10 report and Session 11 final report. | Exploit outcome bucket derived from attempts, artifacts, callbacks, screenshots, or transcript proof. | Report judgment backed by exploit evidence. |

## Finding Buckets

Finding buckets are report judgments, never CLI measurement fields.

| Bucket | Use When |
|--------|----------|
| `EXPLOITED` | Session 10 or category evidence reaches impact proof: data extracted, unauthorized action completed, JavaScript executed, internal service reached, or equivalent proof. |
| `STRONG_EVIDENCE_NOT_EXPLOITED` | Evidence supports a real issue, but exploit proof was disabled, not selected, or not required for the assessment. |
| `BLOCKED_BY_SECURITY` | A security control prevented exploitation after systematic bypass attempts. |
| `BLOCKED_BY_OPERATIONAL_CONSTRAINT` | Missing account, missing test data, unstable service, unavailable callback, or authorization boundary prevented proof. |
| `FALSE_POSITIVE` | Systematic testing showed the suspected weakness is not exploitable in scope. |
| `NOT_TESTED` | The surface was outside scope, skipped, blocked, or unavailable. |

## Agent Contract

| Area | Ensphere Must Measure | Agent May Decide |
|------|-----------------------|------------------|
| Scope and target | Configured hosts, in-scope checks, discovered endpoints, target type, and coverage labels. | Whether coverage is sufficient for a conclusion, or whether to ask for more inputs. |
| Probing | Exact payload, request, response metadata, timing, hashes, callbacks, and artifacts. | Whether measurements support a finding, false positive, blocked state, or further testing. |
| External tools | Source tool, source file, source rule ID, source severity, raw matched evidence, and parser status. | Whether a tool lead is relevant, exploitable, duplicate, or worth native verification. |
| Reporting | Evidence IDs, transcript paths, skipped-session reports, hash verification status, and redaction state. | Severity, confidence, business impact, attack path, remediation priority, and final narrative. |
| Exploitation | Selected finding IDs, exploit attempts, observed responses, cleanup actions, and resulting artifacts. | Whether proof satisfies exploited, blocked, strong-evidence, or false-positive report buckets. |

## External Tool Trust Model

Imported scanner output is never an Ensphere-confirmed finding by itself.

Importers must preserve:
- Source tool
- Source file
- Source rule or template ID
- Source severity and confidence, when provided
- Raw matched evidence or transcript reference
- Parser status and parse errors

Reports may cite imported leads, but they must label source severity as
source-provided until corroborated by native Ensphere measurements or manual
proof.

## Report Honesty Rules

- No uncited finding: every finding needs an evidence ID, transcript path,
  import reference, or explicitly labeled manual note.
- Report paths must be workspace-relative: transcript, artifact, and cleanup
  references must not be absolute paths, URLs, parent-directory traversal, or
  anything outside `ensphere-pentest/`.
- No implied coverage: skipped, blocked, partial, source-only, black-box-only,
  client-only, and cloud-only coverage must be visible in the executive summary
  and appendix.
- No exploit wording unless Session 10 proves it: use strong evidence,
  suspected, blocked, or not selected when exploit proof did not run or did not
  succeed.
- No scanner laundering: imported scanner severity remains source-provided
  until the agent cites corroborating Ensphere evidence or manual proof.
- No silent evidence failure: hash-chain or transcript failures are report
  limitations, not internal details to hide.
