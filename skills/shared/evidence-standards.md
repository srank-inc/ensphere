# Evidence Standards

Read this with [workflow-contract.md](workflow-contract.md). The evidence
ledger records facts; the finding registry and reports hold security judgments.

## CLI Evidence Rows

`ensphere evidence log` and automated verify/callback/cloud parser writes assign `EVID-XXX` IDs at write time and maintain a hash chain. The `result` field is a factual stage only: `baseline`, `probe`, `payload`, `control`, `callback`, or `manual_note`. Do not store AI/human conclusions such as confirmed, potential, safe, confidence, or exploitability in `result`; put those judgments in session reports and the final report.

## Evidence Categories

Use these categories in finding registries and report appendices. They are not
replacement values for the evidence `result` field.

| Category | Meaning |
|----------|---------|
| `imported_lead` | Factual scanner or external tool output. Source severity remains source-provided. |
| `ensphere_measurement` | Native Ensphere probe, payload selection, response measurement, callback, hash, or parser result. |
| `agent_judgment` | AI or human classification, confidence, severity, exploitability, impact, or remediation priority. |
| `exploit_attempt` | Session 10 planned exploit command, request sequence, expected proof, stop condition, and observed response. |
| `exploit_result` | Session 10/11 outcome bucket backed by exploit evidence. |

## Proof Levels

| Level | Name | Evidence Required | Classification |
|-------|------|-------------------|----------------|
| L1 | Weakness Identified | Error messages, timing differences, or response variations | Report may classify as suspected or strong evidence only with context. |
| L2 | Structure Manipulated | Boolean-blind working, UNION SELECT succeeds, partial bypass | Report may classify as strong evidence not exploited. |
| L3 | Impact Confirmed | Actual data extracted, unauthorized access achieved, JS executed | Report may classify as exploited. |
| L4 | Critical Impact | Admin credentials, sensitive data dump, RCE, full account takeover | Report may classify as exploited with critical impact. |

You MUST reach L3+ with cited evidence to mark a finding as `EXPLOITED`.
That label belongs in reports and finding registries, not CLI evidence rows.

## Report Bucket Decision Framework

After exhaustive bypass attempts, ask:
**"Is this preventing factor a security implementation designed to stop this attack, or an external operational constraint?"**

- **Security feature that withstands bypass attempts** -> `BLOCKED_BY_SECURITY` or `FALSE_POSITIVE`
- **External constraint (server crash, missing auth you can't obtain)** -> `BLOCKED_BY_OPERATIONAL_CONSTRAINT`
- **Strong evidence but no exploit proof** -> `STRONG_EVIDENCE_NOT_EXPLOITED`
- **Successfully exploited with concrete evidence** -> `EXPLOITED`

Report bucket assignment is only valid after attempting systematic bypasses
across multiple techniques, or after explicitly recording why bypass attempts
were out of scope.

## Bypass Exhaustion Protocol

Classification is FORBIDDEN until you have:
1. Attempted **3+ distinct bypass techniques** per vulnerability
2. Tried **systematic approach across different attack vectors** (encoding, obfuscation, alternate syntax)
3. **Escalated** through manual → automated → custom techniques
4. **Documented each failed attempt** with what was tried and why it failed

## Reproducibility Requirements

Every finding must be completely reproducible:
- Full endpoint URL with protocol, domain, port, path, parameters
- Complete payload/command exactly as used
- Authentication context (cookies, tokens, headers)
- Expected vs actual response
- Clear placeholders for variable values: `[SESSION_TOKEN]`, `[USER_ID]`, etc.

Write as if the reader has never seen the application. Another tester must reproduce from documentation alone.

## Confidence Scoring

- **High**: Clear, unambiguous evidence. Direct code path or deterministic behavior. No material alternate control.
- **Medium**: Strongly indicated but one material uncertainty remains (possible upstream control, conditional behavior).
- **Low**: Plausible but unverified. Indirect evidence, unclear scope, inconsistent indicators.

Rule: when uncertain, round down to minimize false positives.

## Report Honesty Requirements

- No uncited finding: every finding needs an evidence ID, transcript path,
  import reference, or explicitly labeled manual note.
- Transcript, artifact, and cleanup references must be relative to the
  workspace root and safe to cite. Do not use absolute paths, URLs,
  parent-directory traversal, or paths outside `ensphere-pentest/`.
- No implied coverage: skipped, blocked, partial, source-only, black-box-only,
  client-only, and cloud-only coverage must be visible in report coverage
  sections.
- No exploit wording unless Session 10 or category evidence proves impact.
- No scanner laundering: imported severity remains source-provided until
  corroborated by native Ensphere evidence or manual proof.
- No silent evidence failure: hash-chain or transcript failures are report
  limitations.

## False Positive Documentation

Record false positives in `ensphere-pentest/{NN}-{name}/false-positives.md` with:
- Vulnerability ID and description
- All techniques attempted
- Why it was determined to be a false positive

Do NOT include false positives in the main report.
