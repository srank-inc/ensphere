# Ensphere Development Guide

## Architecture

Ensphere is a 4-layer security testing toolkit:
1. **Payloads** — Curated YAML seeds compiled to SQLite, queried at runtime
2. **Verify** — Targeted verification probes with evidence logging
3. **Templates** — Pre-built Python 3 exploit scripts
4. **Checklists** — Framework-specific security checklists

Delivery: Go CLI binary (`ensphere`) + Claude Code skill files (`skills/`).

## Build

```bash
make build        # YAML seeds → SQLite → Go binary (bin/ensphere)
make seeds        # only recompile seed database
make test         # go vet + go test
make install      # copy binary to /usr/local/bin
make install-all  # install binary + skill files
make clean        # remove build artifacts
```

## Key Paths

| Path | Purpose |
|------|---------|
| `cli/` | Go module root (`github.com/srank/ensphere`) |
| `cli/cmd/` | Cobra command files (one per command) |
| `cli/internal/` | Business logic packages |
| `cli/internal/enums/` | Enum validation maps |
| `cli/internal/payloads/` | SQLite DB + query logic |
| `cli/internal/verify/` | Verification probe logic |
| `cli/internal/evidence/` | JSONL evidence writer/reader |
| `cli/internal/templates/` | Pre-built Python 3 exploit scripts |
| `cli/internal/checklist/` | Framework-specific security checklists |
| `cli/internal/compliance/` | Compliance framework mappings |
| `cli/internal/cvss/` | CVSS v3.1/v4.0 scoring engine |
| `cli/internal/scan/` | Code scanning engine |
| `cli/internal/sinks/` | Sink pattern database |
| `cli/tools/seedgen/` | YAML → SQLite compiler |
| `assets/seeds/` | YAML payload seed files |
| `skills/` | Claude Code skill files |
| `skills/methodology/` | Session methodology (01-07) |
| `skills/checklists/` | Security checklists |

## Conventions

- **Commands**: One file per command in `cli/cmd/`. Register with parent in `init()`.
- **Logic**: All business logic in `cli/internal/<package>/`. Commands only parse flags, build config, call logic, encode JSON output.
- **JSON output**: `json.NewEncoder(os.Stdout).SetIndent("", "  ")` for all structured output.
- **Errors**: `fmt.Errorf("context: %w", err)` for wrapping.
- **Exit codes**: Exit 1 on confirmed/potential findings (CI-friendly).
- **Flag vars**: Package-level vars in cmd files, named `<command><FlagName>`.

## Adding Payloads

1. Edit or create YAML in `assets/seeds/`
2. Follow format: `defaults:` section + `payloads:` array
3. All enum values validated at build time (`make build`)
4. Valid enums defined in `cli/internal/enums/enums.go`

## Adding Commands

1. Create `cli/cmd/<name>.go` with Cobra command
2. Create `cli/internal/<package>/` for business logic
3. Register command with parent in `init()`
4. Follow patterns in existing commands (e.g., `verify_sqli.go`)

## What NOT To Do

- Don't modify `payloads.sqlite` directly — it's generated from YAML
- Don't add Go dependencies without clear need
- Don't put business logic in `cli/cmd/` files
- Don't skip `--in-scope` validation on verify commands
