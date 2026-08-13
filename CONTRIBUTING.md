# Contributing

Ensphere is licensed under the GNU Affero General Public License v3.0 and is maintained as a proof of concept. Contributions are accepted under the same license; by submitting a contribution you agree it may be distributed under AGPL-3.0.

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

## Dependency Updates

Dependency updates are maintained through controlled Dependabot pull requests plus maintainer review. Dependabot alerts provide vulnerability detection, and `.github/dependabot.yml` groups routine Go module and GitHub Actions updates so the repository gets a small number of reviewable PRs instead of update noise.

For manual verification or maintainer-driven updates:

```bash
cd cli
go list -m -u all
go get <module>@<version>
go mod tidy
cd ..
make test
make smoke
make verify-generated
cd cli && go test -race -short ./internal/verify/
```

Merge dependency PRs only after CI passes and the change is understood. Do not auto-merge major updates or updates that alter generated assets without reviewing the regenerated output.

## Pull Requests

Every pull request should describe:

- What changed
- Why it changed
- What public CLI or evidence contract changed, if any
- Which validation commands passed
- Any residual risk or follow-up work
