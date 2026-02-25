# Evidence Standards

## Proof Levels

| Level | Name | Evidence Required | Classification |
|-------|------|-------------------|----------------|
| L1 | Weakness Identified | Error messages, timing differences, or response variations | POTENTIAL (Low) |
| L2 | Structure Manipulated | Boolean-blind working, UNION SELECT succeeds, partial bypass | POTENTIAL (Medium) |
| L3 | Impact Confirmed | Actual data extracted, unauthorized access achieved, JS executed | EXPLOITED |
| L4 | Critical Impact | Admin credentials, sensitive data dump, RCE, full account takeover | EXPLOITED (Critical) |

You MUST reach L3+ with evidence to mark as EXPLOITED.

## Classification Decision Framework

After exhaustive bypass attempts, ask:
**"Is this preventing factor a security implementation designed to stop this attack, or an external operational constraint?"**

- **Security feature that withstands bypass attempts** → FALSE POSITIVE
- **External constraint (server crash, missing auth you can't obtain)** → POTENTIAL
- **Successfully exploited with concrete evidence** → EXPLOITED

Classification is only valid AFTER attempting systematic bypasses across multiple techniques.

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

## False Positive Documentation

Record false positives in `ensphere-pentest/{NN}-{name}/false-positives.md` with:
- Vulnerability ID and description
- All techniques attempted
- Why it was determined to be a false positive

Do NOT include false positives in the main report.
