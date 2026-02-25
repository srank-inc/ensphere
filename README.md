<div align="center">

<img src="./assets/ensphere-banner.png" alt="Ensphere" width="100%">

</div>

# Ensphere

Autonomous penetration testing as Claude Code skills. Go CLI binary + skill files (portable markdown).

> **Design Principle:** Ensphere produces verifiable facts. The AI produces all security judgments.

All Ensphere tooling — Go CLI, Python templates, payload databases — is purely deterministic: same inputs → same outputs. It measures, hashes, compares, and counts. It never classifies findings or assigns confidence. The AI layer consumes raw measurements and applies context, reasoning, and security expertise to interpret results.

## Quick Start

```bash
git clone https://github.com/srank/ensphere.git && cd ensphere
./install-skills.sh
# In target project: claude → /ensphere
```

## Sessions

Each session covers one vulnerability category. Run `/clear` between sessions. Progress persists in `ensphere-pentest/`.

```
01-recon → 02-injection → 03-auth → 04-authz → 05-xss → 06-ssrf → 07-report
```

| # | Category | Scope |
|---|----------|-------|
| 01 | Recon | Endpoints, roles, tech stack via code review + live crawling + external tools |
| 02 | Injection | SQLi, command injection, LFI/RFI, SSTI, path traversal, deserialization |
| 03 | Auth | Session management, credential handling, OAuth, MFA bypass |
| 04 | Authz | IDOR, privilege escalation, workflow bypass, role confusion |
| 05 | XSS | Reflected, stored, DOM-based |
| 06 | SSRF | Classic, blind, semi-blind, stored SSRF with redirect chains |
| 07 | Report | Executive summary with risk ratings from all sessions |

First run prompts creation of `ensphere-pentest/config.md` (target URL, credentials, scope, authorization). Template: [`templates/config.md`](templates/config.md).

## Build

Requires Go 1.23+.

```bash
make build        # YAML seeds → SQLite → Go binary (bin/ensphere)
make install      # → /usr/local/bin/ensphere
make install-all  # binary + skill files
```

## CLI Reference

### payloads — Query payload database

1059 payloads across 22 vulnerability types. YAML seeds compiled to SQLite, queried at runtime.

```bash
ensphere payloads sqli --db postgres --technique blind_time
ensphere payloads ssrf --max-risk 2
ensphere payloads csv_injection
ensphere payloads sqli --tag pg_sleep --limit 5
```

JSON output: `query`, `count`, `results[]` (payload, placeholders, evidence_type, risk, notes, tags). Invalid filters return valid values list.

### verify — Targeted verification probes

All verify commands output JSON (schema v2: measurements only, no status/confidence), log evidence to `./evidence.jsonl`, and use exit codes: 0 = probes completed, 2 = scope/usage error, 3 = runtime failure.

**SQLi** — `--in-scope` required, default throttle 500ms, default `--max-risk 3`
```bash
ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --technique blind_time --in-scope *.localhost
```
Techniques: `blind_time` (default), `blind_boolean`, `error_based`.

**RLS** — Supabase cross-tenant via PostgREST. Builds JWTs with `company_id` claims.
```bash
ensphere verify rls --project-url http://127.0.0.1:54321 --anon-key eyJ... --jwt-secret super-secret-jwt-token --table invoices --tenant-a uuid-a --tenant-b uuid-b --in-scope 127.0.0.1
```

**IDOR** — URL uses `{id}` placeholder. `--in-scope` required.
```bash
ensphere verify idor --url "http://target/api/items/{id}" --id "victim-uuid" --token "attacker-jwt" --in-scope *.target.com
```

**XSS** — Checks reflection in response. Supports `--method POST`. `--in-scope` required.
```bash
ensphere verify xss --url "http://target/search" --param q --payload "<script>alert(1)</script>" --in-scope *.target.com
```

**SSRF** — Internal URL injection + cloud metadata detection. Optional `--callback-url`. `--in-scope` required.
```bash
ensphere verify ssrf --url "http://target/fetch" --param url --in-scope *.target.com
```

**Auth Bypass** — `--in-scope` required. Techniques: `no_token`, `expired_token`, `alg_none`, `method_override`.
```bash
ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique alg_none --in-scope *.target.com
```

### template — Exploit templates

Python 3 scripts using only stdlib (urllib, json, time, sys, uuid).

```bash
ensphere template --list
ensphere template idor-uuid
ensphere template sqli-time-postgres --out ./poc/sqli
```

| Template | Type | Description |
|----------|------|-------------|
| `idor-uuid` | IDOR | UUID enumeration across tenants |
| `sqli-time-postgres` | SQLi | pg_sleep timing injection with multi-round verification |
| `ssrf-probe` | SSRF | Internal URL probing with 9 bypass variants |
| `auth-header-replay` | AuthZ | Token replay across users/tenants |
| `upload-polyglot-check` | Upload | Mismatched content-type/extension bypass tests |

### scan — Code scanning

```bash
ensphere scan ./src
ensphere scan ./src --category sqli,xss
ensphere scan ./src --exclude "test/**"
```

JSON output with match details, file locations, risk levels. Exit 1 if matches found. Use `--exit-zero` to always exit 0, or `--min-risk N` to only fail on matches at or above risk level N.

### evidence — Evidence management

```bash
ensphere evidence log --probe-type sqli --technique blind_time --url "http://target/api" --result confirmed --session 2
ensphere evidence query --file ./evidence.jsonl --result confirmed --summary
ensphere evidence verify --file ./evidence.jsonl  # verify hash chain integrity
```

### cvss — CVSS calculator

```bash
ensphere cvss --version 3.1 --av N --ac L --pr N --ui N --s C --c H --i L --a N
ensphere cvss --version 4.0 --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H
```

JSON output: `version`, `vector_string`, `base_score`, `severity`, `metrics`.

### sinks — Sink pattern database

```bash
ensphere sinks              # list categories with counts
ensphere sinks sqli         # patterns for category
```

Categories: `sqli`, `xss`, `ssrf`, `cmdi`, `lfi`, `ssti`, `deserialization`, `xxe`. Each pattern: regex, file extensions, description, risk.

### compliance — Compliance mapping

Maps vuln types to OWASP Top 10, PCI-DSS v4.0, SOC 2, ISO 27001.

```bash
ensphere compliance sqli
ensphere compliance --list
```

### checklist — Security checklists

```bash
ensphere checklist                # list available
ensphere checklist supabase-rls   # print content
ensphere checklist --list         # JSON with item counts
```

| Checklist | Items | Covers |
|-----------|-------|--------|
| `nextjs-app-router` | 17 | Server Actions, middleware bypass, RSC data leaks, caching, routing |
| `supabase-rls` | 10 | RLS bypass, PostgREST, JWT claims, Storage ACL, Realtime isolation |
| `trpc` | 8 | Auth middleware gaps, Zod validation, batch abuse, cross-tenant |
| `cloudflare-r2` | 6 | Presigned URL scope, public buckets, CORS, SSE-C, enumeration |

## Requirements

- **Claude Code** (Pro/Max/Team/Enterprise)
- **Playwright MCP server** for browser-based testing:
  ```bash
  claude mcp add playwright -- npx @anthropic-ai/mcp-playwright@latest
  ```
- **Go 1.23+** for building CLI
- **Optional recon tools**: `nmap`, `subfinder`, `whatweb`

## Sample Reports

- [Juice Shop](sample-reports/ensphere-report-juice-shop.md) — 27 findings (8 critical) in OWASP Juice Shop
- [crAPI](sample-reports/ensphere-report-crapi.md) — API security assessment
- [Capital API](sample-reports/ensphere-report-capital-api.md) — Financial API assessment

