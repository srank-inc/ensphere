# Security Policy

Ensphere is a security automation toolkit and may contain offensive payloads, proof-of-concept templates, and verification probes. Use it only for systems where you have explicit authorization.

## Reporting Security Issues

Do not open public issues for sensitive vulnerabilities. Report privately to the project owner through the agreed internal channel for this repository.

Include:

- Affected component or command
- Reproduction steps
- Expected and actual behavior
- Impact
- Logs or evidence with secrets redacted

## Scope

Security reports should focus on vulnerabilities in Ensphere itself, including:

- Scope bypasses
- Evidence integrity failures
- Secret redaction failures
- Unsafe default behavior
- Supply-chain or dependency risk
- Command behavior that violates the measurement-only boundary

Reports about third-party targets assessed with Ensphere belong to that target owner's disclosure process.

## Handling Secrets

Do not commit credentials, tokens, evidence from third-party targets, or pentest artifacts. Local evidence and assessment output are ignored by default.
