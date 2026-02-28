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
01-recon → 02-injection → 03-auth → 04-authz → 05-xss → 06-ssrf → 07-cloud → 09-api → 08-report
```

| # | Category | Scope |
|---|----------|-------|
| 01 | Recon | Endpoints, roles, tech stack via code review + live crawling + external tools |
| 02 | Injection | SQLi, command injection, LFI/RFI, SSTI, path traversal, deserialization |
| 03 | Auth | Session management, credential handling, OAuth, MFA bypass |
| 04 | Authz | IDOR, privilege escalation, workflow bypass, role confusion |
| 05 | XSS | Reflected, stored, DOM-based |
| 06 | SSRF | Classic, blind, semi-blind, stored SSRF with redirect chains |
| 07 | Cloud | AWS, Azure, GCP, K8s config audit + IaC scanning (Prowler, Trivy). Sub-files: 07a-aws, 07b-gcp, 07c-azure, 07d-k8s |
| 09 | API | Rate limiting, property-level authz, mass assignment, pagination abuse, webhook SSRF |
| 08 | Report | Executive summary with risk ratings from all sessions |

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

1188 payloads across 26 vulnerability types. YAML seeds compiled to SQLite, queried at runtime.

```bash
ensphere payloads sqli --db postgres --technique blind_time
ensphere payloads ssrf --max-risk 2
ensphere payloads csv_injection
ensphere payloads sqli --tag pg_sleep --limit 5
```

JSON output: `query`, `count`, `results[]` (payload, placeholders, evidence_type, risk, notes, tags). Invalid filters return valid values list.

### verify — Targeted verification probes

29 probe types. All verify commands output JSON (schema v2: measurements only, no status/confidence), log evidence to `./evidence.jsonl`, and use exit codes: 0 = probes completed, 2 = scope/usage error, 3 = runtime failure. All require `--in-scope`.

**SQLi** — Techniques: `blind_time` (default), `blind_boolean`, `error_based`
```bash
ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --technique blind_time --in-scope *.localhost
```

**XSS** — Checks reflection in response. Supports `--method POST`
```bash
ensphere verify xss --url "http://target/search" --param q --payload "<script>alert(1)</script>" --in-scope *.target.com
```

**IDOR** — URL uses `{id}` placeholder
```bash
ensphere verify idor --url "http://target/api/items/{id}" --id "victim-uuid" --token "attacker-jwt" --in-scope *.target.com
```

**SSRF** — Internal URL injection + cloud metadata detection. Optional `--callback-url`
```bash
ensphere verify ssrf --url "http://target/fetch" --param url --in-scope *.target.com
```

**Auth Bypass** — Techniques: `no_token`, `expired_token`, `alg_none`, `method_override`
```bash
ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique alg_none --in-scope *.target.com
```

**RLS** — Supabase cross-tenant via PostgREST. Builds JWTs with `company_id` claims
```bash
ensphere verify rls --project-url http://127.0.0.1:54321 --anon-key eyJ... --jwt-secret super-secret-jwt-token --table invoices --tenant-a uuid-a --tenant-b uuid-b --in-scope 127.0.0.1
```

**CMDi** — Time-based blind command injection. `--os linux|windows`
```bash
ensphere verify cmdi --url "http://target/api?cmd=test" --param cmd --in-scope *.target.com
```

**LFI** — Path traversal with file content signature detection. `--os linux|windows`
```bash
ensphere verify lfi --url "http://target/api?file=test" --param file --in-scope *.target.com
```

**SSTI** — Template expression injection. `--engine auto|jinja2|twig|freemarker|erb`
```bash
ensphere verify ssti --url "http://target/search?q=test" --param q --in-scope *.target.com
```

**XXE** — XML external entity injection. Techniques: `file_read`, `ssrf`, `oob`
```bash
ensphere verify xxe --url "http://target/api/xml" --technique file_read --in-scope *.target.com
```

**Deserialization** — Time-based blind. `--runtime java|python|php|node`
```bash
ensphere verify deserialization --url "http://target/api" --runtime python --in-scope *.target.com
```

**CSRF** — Origin header validation + SameSite cookie checks
```bash
ensphere verify csrf --url "http://target/api/action" --method POST --in-scope *.target.com
```

**NoSQL** — Techniques: `operator_injection` (default), `where_time`
```bash
ensphere verify nosql --url "http://target/api/login" --param username --in-scope *.target.com
```

**JWT** — Techniques: `alg_none`, `kid_injection`
```bash
ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique alg_none --in-scope *.target.com
```

**CORS** — Origin reflection testing (evil, null, subdomain origins)
```bash
ensphere verify cors --url "http://target/api/data" --in-scope *.target.com
```

**Prototype Pollution** — Techniques: `proto_assignment`, `constructor_pollution`, `json_merge`
```bash
ensphere verify protopollution --url "http://target/api/config" --in-scope *.target.com
```

**GraphQL** — Techniques: `introspection`, `batch_query`, `nested_query_dos`
```bash
ensphere verify graphql --url "http://target/graphql" --technique introspection --in-scope *.target.com
```

**Race Condition** — Concurrent request bursts. `--concurrency N` (default 10)
```bash
ensphere verify race --url "http://target/api/redeem" --method POST --body '{"code":"PROMO"}' --in-scope *.target.com
```

**Request Smuggling** — Techniques: `cl_te`, `te_cl`, `te_te`
```bash
ensphere verify smuggling --url "http://target/" --technique cl_te --in-scope *.target.com
```

**Cache Poisoning** — Techniques: `unkeyed_header`, `unkeyed_cookie`, `fat_get`
```bash
ensphere verify cachepoisoning --url "http://target/page" --in-scope *.target.com
```

**Open Redirect** — Location header inspection with redirect chain tracking
```bash
ensphere verify redirect --url "http://target/login?next=/dashboard" --param next --in-scope *.target.com
```

**CSV Injection** — Formula payload submission + export verification
```bash
ensphere verify csvinjection --submit-url "http://target/api/items" --export-url "http://target/api/export.csv" --param name --in-scope *.target.com
```

**AuthZ Bypass** — Privilege level comparison (high-priv vs low-priv response)
```bash
ensphere verify authz --url "http://target/api/admin" --low-token "user-jwt" --high-token "admin-jwt" --in-scope *.target.com
```

**Rate Limit** — Sequential burst measurement. Counts success (2xx) vs throttled (429/503) responses
```bash
ensphere verify ratelimit --url "http://target/api/login" --method POST --burst-count 100 --window-sec 10 --in-scope *.target.com
```

**Property AuthZ** — Field-level authorization comparison between privilege levels
```bash
ensphere verify propertyauthz --url "http://target/api/users/me" --high-token "admin-jwt" --low-token "user-jwt" --watch-fields "ssn,salary" --in-scope *.target.com
```

### callback — OOB callback listener

Receives out-of-band callbacks for blind SSRF, XXE, and SSTI confirmation. Token-based path routing for correlation.

```bash
ensphere callback --port 8888 --wait 30 --external-url "https://abc.ngrok.app" --evidence ./evidence.jsonl
```

### cloud — Cloud security verification

Probes cloud infrastructure via provider CLIs (aws, gcloud, az). No SDK dependencies.

```bash
ensphere cloud storage --provider aws --bucket my-bucket --in-scope "aws://123456789012"
ensphere cloud iam --provider aws --principal arn:aws:iam::123:user/alice --in-scope "aws://123456789012"
ensphere cloud network --provider aws --in-scope "aws://123456789012" --vpc-id vpc-abc123
ensphere cloud parse-prowler ./prowler-output.json --evidence ./evidence.jsonl
ensphere cloud parse-trivy ./trivy-results.json --evidence ./evidence.jsonl
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
| `xss-reflected-poc` | XSS | Reflected XSS with DOM confirmation |
| `nosql-extraction` | NoSQL | Operator injection data extraction |
| `jwt-forge` | JWT | Algorithm none / confusion token forging |
| `cmdi-reverse-check` | CMDi | Blind command injection with callback verification |
| `deserialization-java` | Deser | Java deserialization RCE chain testing |
| `ssti-rce` | SSTI | Multi-engine template injection to RCE |
| `lfi-to-rce` | LFI | Path traversal escalation to code execution |
| `xxe-oob-extract` | XXE | OOB data exfiltration via external entities |

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

Categories: `cmdi`, `cors`, `csrf`, `deserialization`, `file_upload`, `header_injection`, `idor`, `jwt`, `ldap`, `lfi`, `nosql`, `redirect`, `sqli`, `ssrf`, `ssti`, `xpath`, `xss`, `xxe`, `iac_terraform`, `iac_cloudformation`, `iac_dockerfile`, `iac_kubernetes`. Each pattern: regex, file extensions (or filenames for Dockerfile), description, risk.

### compliance — Compliance mapping

Maps 40 vuln types (including 8 cloud categories) to OWASP Top 10 2025, PCI-DSS v4.0.1, SOC 2, ISO 27001, OWASP API Security Top 10 2023.

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
| `django` | 10 | ORM injection, pickle deserialization, CSRF exempt, admin exposure, CORS |
| `rails` | 12 | Mass assignment, ActiveRecord injection, Marshal, redirect_to |
| `spring-boot` | 12 | Actuator endpoints, SpEL injection, Thymeleaf SSTI, Jackson deser |
| `express-js` | 12 | NoSQL injection, prototype pollution, path traversal, JWT, Helmet |
| `laravel` | 10 | Mass assignment, Eloquent injection, Blade XSS, debug mode |
| `fastapi` | 10 | Depends() auth, Pydantic bypass, CORS, OpenAPI exposure |
| `aws-s3` | 12 | Public access blocks, encryption, versioning, logging, presigned URLs |
| `aws-iam` | 12 | Least privilege, MFA, key rotation, role trust, permission boundaries |
| `k8s-pod-security` | 10 | Privileged containers, hostNetwork, root user, capabilities, seccomp |

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

