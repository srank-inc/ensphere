# Contributing

Ensphere is currently proprietary and privately maintained. Contributions are accepted only from authorized collaborators.

## Engineering Bar

- Preserve the measurement-only boundary.
- Keep business logic out of `cli/cmd/`.
- Add tests for public CLI behavior and internal package changes.
- Keep generated assets synchronized with source files.
- Do not introduce dependencies without a clear production need.

## Required Checks

Run these before opening a pull request:

```bash
make test
make smoke
make verify-generated
cd cli && go test -race -short ./internal/verify/
git diff --check
```

## Generated Files

`cli/internal/payloads/payloads.sqlite` and `cli/internal/checklist/data/` are generated and committed intentionally. Regenerate them with:

```bash
make verify-generated
```

Do not edit generated files by hand.

## Pull Requests

Every pull request should describe:

- What changed
- Why it changed
- What public CLI or evidence contract changed, if any
- Which validation commands passed
- Any residual risk or follow-up work
