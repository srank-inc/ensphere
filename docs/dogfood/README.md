# Dogfood Runbooks

These runbooks are for running Ensphere against intentionally vulnerable local targets and producing sample reports from real evidence.

Targets:

| Target | Runbook | Primary DB/Profile |
|--------|---------|--------------------|
| OWASP Juice Shop | [juice-shop.md](juice-shop.md) | SQLite-style SQLi probes, web + API |
| OWASP crAPI | [crapi.md](crapi.md) | PostgreSQL/API probes |
| Capital API | [capital-api.md](capital-api.md) | API-only sandbox probes |

Rules for sample reports:

- Do not update `sample-reports/*.md` from memory, challenge writeups, or copied public examples.
- Every finding in a regenerated sample report must trace back to a local `evidence.jsonl` entry or a saved command transcript in the matching dogfood workspace.
- Keep raw secrets out of reports. Evidence writers redact common token shapes, but manually review before publishing.
- Run `ensphere evidence verify --file <evidence.jsonl>` before using evidence in a report.

Recommended workspace layout:

```text
ensphere-pentest/
  juice-shop/
    config.md
    evidence.jsonl
    transcripts/
    report.md
  crapi/
    config.md
    evidence.jsonl
    transcripts/
    report.md
  capital-api/
    config.md
    evidence.jsonl
    transcripts/
    report.md
```

Regeneration flow:

1. Start the vulnerable target locally.
2. Copy `templates/config.md` into the target workspace and fill scope, URLs, auth, and constraints.
3. Run deterministic Ensphere commands and save JSON output/transcripts.
4. Verify the evidence hash chain.
5. Have the AI classify findings and write the report from the evidence only.
6. Replace the matching sample report only after the report can be traced back to the evidence workspace.

See [regenerate-sample-reports.md](regenerate-sample-reports.md) for the exact report gate.
