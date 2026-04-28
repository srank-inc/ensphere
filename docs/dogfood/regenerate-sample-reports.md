# Regenerating Sample Reports

Sample reports must be regenerated from real dogfood evidence, not edited as standalone marketing copy.

## Required Inputs

Each target needs:

- `ensphere-pentest/<target>/config.md`
- `ensphere-pentest/<target>/evidence.jsonl`
- `ensphere-pentest/<target>/transcripts/*`
- A draft report generated from those local artifacts

## Verification Gate

Run:

```bash
ensphere evidence verify --file ensphere-pentest/<target>/evidence.jsonl
ensphere evidence query --file ensphere-pentest/<target>/evidence.jsonl --summary
```

The report can replace `sample-reports/ensphere-report-<target>.md` only when:

- The evidence hash chain is valid.
- Every finding includes evidence IDs or transcript filenames.
- Tokens, cookies, passwords, and internal-only host details are redacted.
- The report separates raw measurements from AI security judgments.
- The target version, run date, Ensphere commit, and command set are recorded.

## Report Prompt

Use this instruction when asking the AI to write the report:

```text
Write the sample report only from these files:
- config.md
- evidence.jsonl
- transcripts/*

Do not invent findings. For every finding, cite the evidence IDs or transcript filenames that support it. Keep raw measurements separate from severity, confidence, and exploitability judgments.
```

## Output Paths

| Target | Output |
|--------|--------|
| Juice Shop | `sample-reports/ensphere-report-juice-shop.md` |
| crAPI | `sample-reports/ensphere-report-crapi.md` |
| Capital API | `sample-reports/ensphere-report-capital-api.md` |
