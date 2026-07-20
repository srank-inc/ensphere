# Ensphere Workflow Contract

> Ensphere produces verifiable facts. The analyst produces security judgments.

This contract applies to every session. A session methodology may narrow these
rules, but it may not weaken scope, evidence, stop, or human-approval controls.

## Responsibilities

| Area | Deterministic Ensphere layer | Analyst layer |
|------|-------------------------------|---------------|
| Scope | Parse configured assets, validate hosts, and record identifiers. | Decide whether authorization and coverage are sufficient. |
| Discovery | Inventory cited endpoints, inputs, roles, fetchers, render contexts, cloud assets, and source candidates. | Decide relevance, applicability, and residual gaps. |
| Validation | Send bounded requests and record payloads, responses, timing, hashes, callbacks, counts, and configuration values. | Define falsifiable claims and interpret baseline/probe/control evidence. |
| External tools | Preserve raw source, rule, severity, transcript, and parser state. | Corroborate, deduplicate, classify, and prioritize leads. |
| Reporting | Check artifact presence, schemas, safe paths, selected IDs, and evidence integrity. | Assign status, confidence, severity, impact, priority, and remediation. |
| Optional Session 10 | Validate enablement, selected IDs, limits, outcome completeness, paths, and cleanup records. | Analyst writes the exact plan; a human authorizes it and names either the human or AI as executor; the analyst interprets and reports results. |

The deterministic layer must not assign vulnerability status, confidence,
exploitability, or business impact, and must not infer a threshold-based
security conclusion.

## Required Session Lifecycle

Every assessment session uses this sequence:

1. **Preflight** — confirm authorization, selected target, environment, scope,
   identity/role, source/live availability, prior artifacts, limits, and a
   writable evidence path.
2. **Coverage matrix** — enumerate the applicable surface and mark each item
   `planned`, `tested`, `not_tested`, `blocked`, or `not_applicable`, with a
   reason and provenance.
3. **Candidate generation** — create narrow claims from recon, source review,
   imported leads, and observed behavior. A candidate is not a finding.
4. **Controlled validation** — use the baseline/probe/control cycle in
   [evidence-standards.md](evidence-standards.md).
5. **Candidate resolution** — record status, confidence, evidence strength,
   alternatives considered, and citations.
6. **Stop check** — stop when the claim is supported or contradicted, the
   approved action/request limit is reached, safety or stability changes, or
   the next step would broaden scope or increase impact only for proof.
7. **Session report** — state coverage, resolved findings, tested defenses,
   unresolved candidates, limitations, evidence index, and next-session inputs.

Do not replace this lifecycle with fixed payload counts, bypass quotas, tool
escalation ladders, or "test until exploited" behavior.

## Session Decisions

| Decision | Required basis |
|----------|----------------|
| `run` | Affirmative evidence that relevant surface exists and required inputs are available. |
| `limited` | Surface exists, but named assets, roles, data, protocols, regions, or environments are unavailable. |
| `blocked` | Surface exists, but testing cannot proceed safely or meaningfully; name the missing input and impact. |
| `skip` | A deliberate human choice with evidence, rationale, and accepted coverage risk. |
| `force` | A human override with provenance, reason, and any tighter limits. |
| `uncertain` | Recon cannot prove presence or absence; preserve the gap and run only bounded discovery or request direction. |
| `not_applicable` | Affirmative inventory shows the category does not exist for the selected target. |

Do not infer `not_applicable` from missing credentials, failed discovery, or a
single absent signal.

## Execution States

`PENDING`, `IN_PROGRESS`, `DONE`, `SKIPPED`, `BLOCKED`, and
`NOT_APPLICABLE` describe workflow state only. `DONE` means the planned work
and session report are complete; it does not mean the target is secure.

## Coverage Labels

| Label | Meaning |
|-------|---------|
| `full` | All necessary source/environment inputs, accounts, roles, assets, regions, and relevant protocols for the planned surface were available and exercised. |
| `partial` | Some planned surface was exercised; the report names every material gap and its effect. |
| `blocked` | Relevant surface exists, but safe meaningful testing could not proceed. |
| `source_only` | Source/configuration review without a live target. |
| `black_box_only` | Live behavioral testing without source. |
| `client_only` | The supplied artifact is a client and its backend was not supplied or authorized. |
| `cloud_only` | Only cloud, Kubernetes, or IaC assets were in scope. |

Coverage labels describe the session plan, not product-wide assurance. They
must be supported by the coverage matrix.

## Scope and Safety

- Use only assets, accounts, tenants, data, and roles explicitly placed in
  scope. Default to an external unprivileged perspective.
- Prefer owned/synthetic objects, non-sensitive canaries, read-only provider
  APIs, and reversible changes.
- Do not enumerate unrelated assets, extract sensitive data, access secret
  values, obtain cloud tokens, dump credentials, establish persistence, evade
  rate limits, perform load/DoS testing, or test third parties.
- A higher-risk or state-changing step requires explicit authorization in the
  session plan, defined limits, rollback, and evidence of cleanup.
- Treat source candidates and scanner output as leads. Do not claim dynamic
  reachability or exploitability without corresponding evidence.

## Reporting Contract

Session 09 is always the complete, decision-ready assessment report. It must be
useful even when Sessions 10–11 never run.

For each finding preserve status, confidence, severity, priority, evidence
strength, affected assets and locations, observed facts, root cause, security
and business impact, remediation, validation criteria, and citations. Separate
observed attack paths from hypothetical risk scenarios. Compliance mappings
are contextual mappings, not certification `PASS`/`FAIL` judgments.

Session 10 never starts automatically. It requires explicit enablement,
selected finding IDs, environment acknowledgement, a bounded per-finding plan,
limits, cleanup, and a structured human-authorization record for the exact plan
revision and SHA-256. The separate record names `human` or `agent` as executor
and captures the environment, actions, and action/time/risk limits. A changed
plan hash requires new authorization. The outcome must include bounded action
and time accounting plus cleanup evidence. Before execution, the deterministic
`run impact-ready` gate must validate the strict plan and authorization with
`ready: true`.

Session 11 is an optional derived report. It preserves the Session 09 registry
and status, attaches a separate `impact_validation_outcome_status` with evidence and
cleanup state, and identifies the selected subset. Non-selected findings remain
valid assessment results but were not impact-validated.

## External Tool Trust

Imported tools create leads and coverage, not Ensphere-confirmed findings.
Preserve the tool, version, input scope, rule/template ID, source severity and
confidence, raw artifact, parser status, and errors. Any analyst conclusion
must cite the imported lead and whatever corroboration supports it.
