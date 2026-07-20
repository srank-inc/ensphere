# Reproducible Benchmark Runbooks

These runbooks evaluate Ensphere against intentionally vulnerable local targets
with published ground truth. They are evaluation protocols, not canned finding
lists and not sample-report generators.

| Target | Runbook | Primary evaluation value |
|--------|---------|--------------------------|
| OWASP Juice Shop | [juice-shop.md](juice-shop.md) | Web/API coverage, injection, authentication, authorization, and browser-dependent behavior |
| OWASP crAPI | [crapi.md](crapi.md) | API-heavy identity, object authorization, workflow, and input-handling coverage |
| Capital API | [capital-api.md](capital-api.md) | Small API-only runner and evidence-contract checks |

## Evaluation Rules

1. Pin the target image or commit and record it in the workspace.
2. Start the target locally and place only that local deployment in scope.
3. Run Sessions 01–09 without consulting challenge solutions during analysis.
4. Verify every evidence chain and retain command/browser transcripts.
5. Compare the frozen report with the ground-truth source only after reporting.
6. Record true positives, unsupported claims, missed known conditions, coverage
   gaps, and claims that cannot be compared because prerequisites were absent.
7. Do not commit the generated report unless its complete redacted evidence
   workspace is also reviewable and publication is explicitly chosen.

Use [../../skills/evaluation/README.md](../../skills/evaluation/README.md) for
the scoring and review format.
