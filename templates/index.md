# Template Index

Last updated: 2026-06-07

This folder contains source templates used to create assessment workspaces.

| Template | Purpose |
|----------|---------|
| [config.md](config.md) | Baseline `ensphere-pentest/config.md` structure with target, auth, scope, optional impact validation, and authorization fields |

## Embedded Measurement Templates

Python 3 stdlib-only measurement templates live under
`cli/internal/templates/data/` and are exposed through the CLI:

```bash
ensphere template --list
ensphere template <name> --out ./poc
```

The embedded templates are for reproducible proof-of-concept work and optional
Session 10 planning. They do not introduce Python package dependencies.
