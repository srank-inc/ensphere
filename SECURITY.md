# Security Policy

Ensphere is an evidence-first application security assessment toolkit and may contain offensive payloads and measurement probes. Use it only for systems where you have explicit authorization. Session 10 is disabled by default; when explicitly selected, each strict plan must name a human or AI executor, receive human authorization bound to its exact SHA-256, and pass the pre-execution readiness gate.

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

## Dependency Monitoring

GitHub Dependabot vulnerability alerts are enabled for detection. Dependabot version-update pull requests are also enabled through grouped configuration so dependency and GitHub Actions updates are visible, reviewable, and covered by CI before merge.

When GitHub reports a vulnerable dependency, maintainers should review the generated PR or create an equivalent maintainer-authored update, run the full validation gate, and include the alert context in the commit or pull request notes.
