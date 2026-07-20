# Session 10: Optional Human-Authorized Impact Validation

## Purpose and Default

Session 10 is an optional validation lane for a human-selected subset of
Session 09 findings. Sessions 01–09 are a complete assessment. Session 10 is
disabled by default, never starts by inference, and is not required to finish
the assessment.

A human or an AI agent may execute a Session 10 plan. In both cases, a human
must first authorize the exact plan revision, executor, target environment,
actions, and limits. A clear human instruction to execute those exact actions
counts as authorization; a general request to assess, continue, investigate,
or improve confidence does not. Before execution, serialize the clear
instruction into the strict authorization file described below; chat wording
alone is not an executable artifact.

## Refusal and Pause Rule

When Session 10 has been explicitly enabled and selected or the human has
explicitly invoked its workflow, any absent or ambiguous gate blocks execution.
Record that missing gate in `10-impact-validation/report.md`, mark Session 10
`BLOCKED`, and leave the Session 09 report unchanged. Use `SKIPPED` only when
the human explicitly declines or cancels the optional session. When Session 10
was never enabled or invoked, stop at Session 09 without creating Session 10
artifacts or changing its state.

After a plan is written or changed, pause for authorization. Any material
change to an action, payload, executor, environment, request limit, risk limit,
stop condition, rollback, or cleanup procedure creates a new revision and
invalidates authorization for the prior revision.

## Required Gates

| Gate | Required evidence |
|------|-------------------|
| Session 09 complete | Session 09 is `DONE`; its registry and report pass `ensphere run report`. |
| Explicit enablement | The current `assessment-plan.yaml` has `impact_validation.enabled: true`. The init/config flag feeds plan generation but never overrides an existing plan. Absence or ambiguity means disabled. |
| Exact selection | `ensphere run validate-impact --finding ...` writes IDs that resolve against the Session 09 registry. No wildcard or inferred candidates. |
| Environment acknowledgement | A human identifies the authorized environment and confirms it is suitable for the exact actions. |
| Per-finding plan | Narrow objective, executor, prerequisites, exact action sequence, expected evidence, limits, stop conditions, rollback, and cleanup evidence. |
| Human authorization | The record identifies the plan revision, finding ID, executor, exact actions, limits, environment, authorizer, and timestamp. |
| Evidence readiness | Workspace-relative authorization, transcript, artifact, and cleanup paths are defined; secret and PII redaction is defined. |

## Phase 1: Write the Exact Plan

For each selected finding and proposed executor, write the strict
`10-impact-validation/plans/{ID}-{executor}.yaml` contract:

```yaml
finding_id: VULN-001
objective: "Observe whether the authorized identity can read the non-sensitive canary"
session09_evidence_ids: [EVID-021, EVID-024]
executor: agent
environment: "owned local test environment"
identity: "test-user-a"
role: "member"
actions:
  - id: action-1
    action_type: non_sensitive_canary_read
    target: "https://local.example.test/api/canary/123"
    operation: "GET /api/canary/123 with test-user-a authorization"
    risk: 2
    expected_observations:
      - status code
      - response hash
max_actions: 1
max_duration_minutes: 5
max_risk: 2
stop_conditions:
  - unexpected state change
rollback_steps:
  - no state change expected; stop if this assumption is false
cleanup_verification:
  - verify canary state is unchanged
transcript_path: 10-impact-validation/transcripts/VULN-001.md
artifact_directory: 10-impact-validation/artifacts
cleanup_evidence_path: 10-impact-validation/cleanup.md#VULN-001
```

Use the smallest action capable of answering the stated objective. Do not add
generic bypass lists, lateral movement, persistence, unrelated credentials,
sensitive-data extraction, or resource changes. An action outside the
selection or plan is not authorized. `risk` is the bounded operation safety
class used by the handoff, not finding severity, exploitability, or confidence.

## Phase 1.5: Record Exact Human Authorization

Hash the completed plan bytes with SHA-256. After the human approves that exact
hash and names the executor, write
`10-impact-validation/authorizations/{ID}-{executor}.yaml`:

```yaml
finding_id: VULN-001
plan_path: 10-impact-validation/plans/VULN-001-agent.yaml
plan_revision: rev-1
plan_sha256: sha256:[64 lowercase hexadecimal characters]
authorized_by: "[human identity]"
authorized_at: "2026-07-18T10:00:00Z"
executor: agent
environment: "owned local test environment"
environment_acknowledged: true
authorized_action_ids:
  - action-1
max_actions: 1
max_duration_minutes: 5
max_risk: 2
```

The authorization record is separate from the plan so writing the approval
does not change the approved plan bytes. Ensphere can validate record
consistency and plan binding; it cannot authenticate who typed a chat message.
The agent must create this record only from an actual human instruction and
must preserve the task/message reference in the transcript.

## Phase 1.75: Pass the Pre-Execution Gate

Before either executor performs any action, run:

```bash
ensphere run impact-ready \
  --finding VULN-001 \
  --authorization 10-impact-validation/authorizations/VULN-001-agent.yaml
```

Proceed only when the JSON contains `"ready": true`. This command executes no
target action. It validates Session 09 readiness, selection, the strict current
handoff, unknown fields, plan SHA-256, ordered action IDs, action types, exact
target/operation, executor, environment, identity/role, risk/action/time limits,
stop conditions, rollback, cleanup, and evidence paths. Save its output in the
transcript. On success it also writes a readiness attestation under
`10-impact-validation/readiness/`; the outcome must cite it. Any later plan or
authorization change invalidates that readiness; run it again after fresh
human authorization. The recorded readiness time must be at or after
`authorization.authorized_at` and at or before execution starts.

## Phase 2: Execute Only the Authorized Revision

The named executor performs only the authorized actions and records:

- finding ID and plan revision/hash;
- executor identity (`human` or `agent`);
- authorization record path;
- exact request, command, or browser action as run, with secrets redacted;
- start/end time, target/environment, identity/role, and action counter;
- raw response/result, exit status, and artifact path;
- stop-condition state, rollback action, and cleanup verification.

Store transcripts under `10-impact-validation/transcripts/`, artifacts under
`10-impact-validation/artifacts/`, and cleanup results in
`10-impact-validation/cleanup.md`.

If actual conditions differ from the plan, evidence capture fails, a stop
condition occurs, scope or identity changes, or a new action is proposed, stop.
Revise the plan and obtain new human authorization before continuing.

## Phase 3: Analyze and Record Outcomes

The analyst checks provenance, authorization, plan compliance, contradictions,
cleanup, and whether the evidence answers the narrow objective. Do not invent
missing observations or imply that unselected findings were validated.

Write `10-impact-validation/impact-validation-outcomes.yaml`:

```yaml
generated_from: "Human-authorized Session 10"
outcomes:
  - id: VULN-001
    status: objective_achieved
    outcome_reason: "The authorized canary action produced the planned observation"
    executor: agent
    authorization_path: "10-impact-validation/authorizations/VULN-001-agent.yaml"
    readiness_path: "10-impact-validation/readiness/VULN-001-agent.yaml"
    execution:
      started_at: "2026-07-18T10:01:00Z"
      completed_at: "2026-07-18T10:02:00Z"
      environment: "owned local test environment"
      performed_actions:
        - id: action-1
          target: "https://local.example.test/api/canary/123"
          operation: "GET /api/canary/123 with test-user-a authorization"
          identity: "test-user-a"
          role: "member"
          started_at: "2026-07-18T10:01:10Z"
          completed_at: "2026-07-18T10:01:50Z"
          exit_status: completed
          result_summary: "Status code and response hash recorded"
          transcript_path: "10-impact-validation/transcripts/VULN-001.md"
          artifact_paths: []
      action_count: 1
      stop_condition_triggered: false
      rollback_status: not_needed
    evidence_ids: []
    transcripts:
      - "10-impact-validation/transcripts/VULN-001.md"
    artifact_paths: []
    cleanup_evidence:
      - "10-impact-validation/cleanup.md#vuln-001"
    cleanup_status: verified
    evidence_categories:
      - human_authorization
      - agent_execution
      - impact_validation_attempt
      - impact_validation_result
    notes: "Executed under plan revision rev-1"
```

Allowed outcome statuses:

- `objective_achieved`
- `objective_not_achieved`
- `blocked_by_control`
- `blocked_by_constraint`
- `inconclusive`

These are optional validation outcomes, not Session 09 finding statuses.
`objective_achieved` requires a transcript, evidence ID, or artifact that
directly supports the authorized objective. Notes alone are insufficient.
Every selected finding requires exactly one outcome, a complete separate
authorization record bound to the plan SHA-256, a structured execution record,
the actual executor, executor-specific evidence (`human_execution` or
`agent_execution`), `impact_validation_attempt` and `impact_validation_result`
evidence, cleanup evidence, and a terminal cleanup status (`verified` or
`not_needed`). Action counts, timestamps, environment, performed actions, and
rollback state must remain inside the authorization record's limits.
Every cited Session 10 evidence ID must exist in
`10-impact-validation/evidence.jsonl`, reference the same finding and Session
10, and pass hash-chain verification.

## Report

Write `10-impact-validation/report.md` with:

1. opt-in basis, selected findings, environment, and authorization provenance;
2. plan revision/SHA-256, pre-execution readiness result, executor, exact actions, and limits for each finding;
3. action accounting and stop-condition results;
4. observed facts and evidence citations;
5. outcome separate from the Session 09 status;
6. cleanup status and unresolved safety limitations;
7. contradictions requiring analyst reassessment;
8. an explicit statement that non-selected findings were not impact-validated.

Mark Session 10 `DONE` only when all selected findings have complete,
authorized outcomes and cleanup records. Do not start Session 11 unless the
human explicitly requests the optional derived report.
