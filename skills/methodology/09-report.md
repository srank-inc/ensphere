# Session 09: Evidence-Based Assessment Report

## Objective

Produce the complete, decision-ready assessment from Sessions 01–08. Session
09 stands on its own; optional Sessions 10–11 are never required to make its
findings valid or its report complete.

Session 09 performs no new target probing.

## Pre-Report Gate

Run:

```bash
ensphere run report
```

Resolve every gate error. Warnings become explicit limitations. Confirm all
planned sessions are terminal, reports exist, evidence chains were checked, and
the assessment plan agrees with actual coverage.

## Synthesis Process

1. Read config, plan, progress, all session reports, evidence ledgers,
   transcripts, imported artifacts, and checkpoints/limitations.
2. Build a claim-to-evidence matrix. Deduplicate by root cause and affected
   control, while preserving distinct assets, roles, and consequences.
3. Separate observed facts from analyst judgments.
4. Resolve contradictions and source/live drift. Do not silently choose the
   more severe interpretation.
5. Assign status, evidence strength, confidence, severity, and priority
   independently under the shared evidence standard.
6. Write CVSS v4.0 metric rationale for applicable vulnerability findings.
7. Distinguish an observed multi-step attack path from a risk scenario whose
   edges were not all tested.
8. Write remediation at the root-cause/control level and concrete validation
   criteria.

## Finding Registry

Write `09-report/finding-registry.yaml` using the canonical finding schema:

```yaml
generated_from: "Sessions 01-08"
findings:
  - id: VULN-001
    title: "Cross-tenant invoice read"
    category: authorization
    status: confirmed
    confidence: high
    evidence_strength: direct
    severity: high
    priority: P1
    cvss_v4: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    affected_assets:
      - "test.example.invalid"
    affected_locations:
      - "GET /api/invoices/{id}"
    observed_facts:
      - "Account A received Account B's synthetic invoice fixture"
      - "The nonexistent-object control returned a distinct not-found response"
    root_cause: "The object lookup is not constrained by the authenticated tenant"
    security_impact: "A tenant can read another tenant's invoice object"
    business_impact: "Cross-customer financial-record confidentiality exposure"
    remediation: "Bind invoice lookup to the authenticated tenant in the data-access layer"
    validation_criteria:
      - "Cross-tenant fixture requests are denied without disclosing object data"
      - "Same-tenant owner and authorized-role controls continue to succeed"
    evidence_ids:
      - EVID-042
    transcripts:
      - "04-authz/transcripts/VULN-001.md"
    artifact_paths: []
    cleanup_evidence: []
    import_refs: []
    manual_notes: []
    evidence_categories:
      - ensphere_measurement
      - agent_judgment
    coverage_label: partial
    impact_validation_candidate: false
    impact_validation_candidate_reason: ""
    selected_for_impact_validation: false
    notes: "Tested with two synthetic tenant fixtures"
```

Use statuses `confirmed`, `likely`, `informational`, `not_supported`, or
`not_tested`. Do not use optional Session 10 outcomes as statuses. Every
reportable weakness needs affected assets/locations, observed facts, root
cause, security/business impact, remediation, validation criteria, and at least
one valid citation.

`impact_validation_candidate` is an optional recommendation only. It does not enable
Session 10, select the finding, or imply exploitation is necessary.

## Required Report Structure

Write `09-report/report.md`:

1. **Authorization and attestation** — target, environment, dates, authorized
   perspective, and constraints. Redact secrets.
2. **Executive summary** — overall risk themes, top priorities, business
   relevance, and material coverage limitations. Avoid counts without context.
3. **Scope and methodology** — in/out of scope, modes, standards used, and the
   baseline/probe/control approach.
4. **Coverage** — asset/session/role/protocol matrix, skipped/blocked work,
   evidence integrity, and source/live gaps.
5. **Finding summary** — ID, title, status, severity, priority, affected asset,
   and evidence strength.
6. **Detailed findings** — observed facts, root cause, impact, prerequisites,
   safe reproduction, citations, CVSS rationale, remediation, and validation
   criteria.
7. **Tested defenses and not-supported candidates** — narrowly scoped; no broad
   assurance wording.
8. **Unresolved and not-tested areas** — missing input and decision impact.
9. **Attack paths and risk scenarios** — visibly separate observed paths from
   hypothetical combinations.
10. **Remediation roadmap** — prioritize by business context, exposure,
    dependencies, and fix leverage; do not impose universal deadlines.
11. **Contextual compliance mapping** — map relevant findings and tested
    controls; do not claim certification or blanket `PASS`/`FAIL`.
12. **Appendices** — evidence/provenance index, coverage detail, tool versions,
    redactions, limitations, and optional Session 10 candidates.

Write `09-report/evidence-appendix.md` as a claim-to-evidence table containing
finding ID, claim/observed fact, evidence category and strength, evidence ID or
path, producer/source, target/role context, integrity state, and limitations.

## Quality Gate

Run `ensphere run report` again after writing the registry and report artifacts.
Then review for:

- uncited or missing-path findings;
- status/evidence-strength inconsistencies;
- severity unsupported by stated impact/prerequisites;
- duplicated findings or missing affected instances;
- scanner severity laundering;
- inferred attack-path edges presented as observed;
- compliance certification language;
- broad negative assurance;
- secrets/personal data or unsafe artifact paths;
- mismatch between coverage statements and the plan/session reports.

Mark Session 09 `DONE` only after the registry, report, appendix, and gate are
consistent. The normal assessment is then complete.
