# Session 11: Optional Validation-Aware Final Report

## Objective

Create a derived report that attaches human-authorized Session 10 outcomes to the
complete Session 09 assessment. Preserve the Session 09 registry, evidence, and
base finding status.

## Preconditions

- Session 09 is complete and its report/registry remain available.
- Session 10 is `DONE` and was explicitly selected.
- Every selected finding has exactly one valid outcome, evidence citation,
  authorization provenance, executor provenance, and cleanup status.
- All cited paths are workspace-relative and available.

Run:

```bash
ensphere run final
```

Resolve every error before writing the report. The command derives
`11-final-report/finding-registry.yaml`; it must not modify Session 09 artifacts.

## Merge Rules

For every finding:

- preserve `status`, `confidence`, `evidence_strength`, severity, priority, and
  Session 09 citations;
- if selected, attach `impact_validation_outcome_status`, outcome reason,
  executor, authorization evidence, transcripts/artifacts, and cleanup state;
- if not selected, leave optional outcome fields empty and label the finding
  “not selected for optional impact validation” in the report;
- do not interpret a missing outcome as a negative security result;
- do not present selection coverage as assessment coverage.

A contradictory Session 10 outcome does not
automatically rewrite the base status. Record the contradiction and have the
analyst issue a cited reassessment/erratum if the original judgment should
change. Deterministic merging never makes that judgment.

## Required Report Structure

Write `11-final-report/report.md` with:

1. authorization, scope, and derivation statement;
2. executive summary from Session 09 plus clearly separated validation changes;
3. assessment coverage and a separate selected-validation coverage table;
4. the original finding summary with base statuses preserved;
5. optional validation outcome summary;
6. detailed findings showing Session 09 judgment and Session 10 outcome in
   separate fields;
7. contradictions or analyst errata;
8. cleanup and unresolved operational/safety limitations;
9. remediation roadmap and validation criteria;
10. evidence/provenance appendix identifying original versus Session 10
    evidence.

For each selected finding show:

- Session 09 status, confidence, and evidence strength;
- Session 10 outcome and outcome reason;
- exact approved objective and limits;
- executor and human-authorization references;
- validation evidence citations;
- cleanup status;
- whether the outcome changed any analyst recommendation, with reasoning.

## Honesty Rules

- Session 11 is derived, not a replacement history.
- `objective_achieved` describes only the optional outcome for the selected
  finding; it is not a new base status.
- Non-selected findings remain valid assessment results but were not
  impact-validated.
- Blocked validation does not mean a security control is effective unless the
  cited outcome establishes that exact claim.
- Do not remove failed attempts, contradictory facts, cleanup limitations, or
  Session 09 coverage gaps.
- Do not expand compliance or assurance claims because optional validation ran.

Mark Session 11 `DONE` only after the report, derived registry, evidence
appendix, and original/derived separation are internally consistent.
