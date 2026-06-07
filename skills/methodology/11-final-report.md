# Session 11: Exploit-Verified Final Report

Session 11 runs only after Session 10 executed. It regenerates the final report
from Session 09 plus Session 10 outcomes. It must not rewrite original evidence
rows or imply exploit proof where none exists.

Read first:
- `skills/shared/workflow-contract.md`
- `skills/shared/evidence-standards.md`
- `ensphere-pentest/config.md`
- `ensphere-pentest/assessment-plan.yaml`
- `ensphere-pentest/09-report/report.md`
- `ensphere-pentest/09-report/finding-registry.yaml`
- `ensphere-pentest/10-exploitation/report.md`
- `ensphere-pentest/10-exploitation/exploit-outcomes.yaml`
- `ensphere-pentest/10-exploitation/evidence.jsonl`
- `ensphere-pentest/10-exploitation/cleanup.md`

## Output Artifacts

```text
ensphere-pentest/11-final-report/
  report.md
  finding-registry.yaml
  evidence-appendix.md
```

## Preconditions

1. Session 10 exists and was not skipped.
2. Every selected finding has an outcome bucket.
3. Cleanup or rollback status is recorded for every exploit attempt.
4. Session 09 finding registry exists.
5. Evidence hash-chain verification has been run or failure is documented.

If any precondition fails, write a blocked report explaining the missing input
and do not produce an exploit-verified final report.

Run `ensphere run final` before writing the final report. The runner validates
that selected findings exist, every selected finding has exactly one Session 10
outcome, exploited outcomes have proof citations, cleanup status is present,
and citation paths are workspace-relative. It then writes
`ensphere-pentest/11-final-report/finding-registry.yaml` as a derived registry.
It does not modify `09-report/finding-registry.yaml` or any evidence rows.

## Phase 1: Merge Finding State

Start from the Session 09 finding registry. For each finding:

- If selected and Session 10 reached impact proof, promote to `EXPLOITED`.
- If selected and blocked by security control, mark `BLOCKED_BY_SECURITY`.
- If selected and blocked by missing operational input, mark
  `BLOCKED_BY_OPERATIONAL_CONSTRAINT`.
- If selected and disproven, mark `FALSE_POSITIVE`.
- If not selected, preserve Session 09 status and label it clearly as not
  exploit-verified.

Do not remove or rewrite original evidence IDs. Add Session 10 evidence IDs,
transcript paths, artifact paths, and cleanup evidence as additional references
in the Session 11 registry only.

## Phase 2: Regenerate Final Report

The report must clearly separate:

- Exploited findings
- Strong evidence but not exploited
- Blocked by security controls
- Blocked by operational constraints
- False positives
- Not selected for exploitation
- Cleanup limitations

## Report Template

Write `ensphere-pentest/11-final-report/report.md`:

```markdown
# Exploit-Verified Final Security Report

## Authorization & Attestation
[Copy authorization from config.md]

## Executive Summary
- **Target**:
- **Assessment Mode**:
- **Exploit Verification**: enabled and completed
- **Selected Findings**:
- **Cleanup Status**:

## Scope, Coverage, and Limitations

| Session | Decision | Execution State | Coverage Label | Limitation |
|---------|----------|-----------------|----------------|------------|

## Finding State Summary

| State | Count |
|-------|-------|
| EXPLOITED | N |
| STRONG_EVIDENCE_NOT_EXPLOITED | N |
| BLOCKED_BY_SECURITY | N |
| BLOCKED_BY_OPERATIONAL_CONSTRAINT | N |
| FALSE_POSITIVE | N |

## Exploited Findings

For each exploited finding:
- Original Session 09 evidence
- Session 10 exploit evidence
- Reproduction steps
- Cleanup evidence
- Remediation

## Strong Evidence Not Exploited

Include findings that were not selected or did not reach exploit proof.

## Blocked Findings

Separate security-control blocks from operational blocks.

## False Positives

Appendix only unless client needs explicit closure.

## Evidence Appendix

| Evidence ID | Source Session | Category | Path | Finding |
|-------------|----------------|----------|------|---------|

## Cleanup Appendix

| Finding | Cleanup Status | Evidence | Residual Risk |
|---------|----------------|----------|---------------|
```

## Report Honesty Rules

- Do not use "exploited" unless Session 10 evidence proves impact.
- Do not imply skipped or blocked sessions were covered.
- Do not convert source-provided scanner severity into Ensphere severity without
  cited corroborating evidence or manual proof.
- Do not hide hash-chain, transcript, cleanup, or redaction failures.
- Do not rewrite Session 09 evidence rows.

## End State

Mark Session 11 `DONE` only after the final report and updated finding registry
are written.
