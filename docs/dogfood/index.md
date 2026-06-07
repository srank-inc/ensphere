# Dogfood Index

Last updated: 2026-06-07

Use this folder to regenerate sample reports from intentionally vulnerable
local targets. Dogfood evidence must come from local workspaces, saved command
transcripts, and verified `evidence.jsonl` files.

| Target | Runbook | Sample Report | Main Coverage |
|--------|---------|---------------|---------------|
| OWASP Juice Shop | [juice-shop.md](juice-shop.md) | [../../sample-reports/ensphere-report-juice-shop.md](../../sample-reports/ensphere-report-juice-shop.md) | Web app plus API, injection, auth, XSS, SSRF-style workflows |
| OWASP crAPI | [crapi.md](crapi.md) | [../../sample-reports/ensphere-report-crapi.md](../../sample-reports/ensphere-report-crapi.md) | API-heavy flows, authz, mass assignment, JWT/API checks |
| Capital API | [capital-api.md](capital-api.md) | [../../sample-reports/ensphere-report-capital-api.md](../../sample-reports/ensphere-report-capital-api.md) | API-only target and registry/report workflow |

## Regeneration Gate

Read [regenerate-sample-reports.md](regenerate-sample-reports.md) before
editing sample reports. Every report claim must cite evidence IDs, transcripts,
or artifacts from the corresponding dogfood workspace.

## Folder Rules

- Do not regenerate reports from memory or public challenge writeups.
- Verify evidence chains before citing `evidence.jsonl`.
- Keep raw credentials, tokens, and secrets out of committed reports.
- Preserve blocked, skipped, and limited coverage statements.
