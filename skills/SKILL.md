---
name: ensphere
description: >
  Ensphere security assessment skill. Runs authorized penetration tests
  one vulnerability category at a time. Say "ensphere" to start or resume.
argument-hint: "[session-number]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*), Grep(*), Glob(*), Task(*), WebFetch(*), mcp__playwright__browser_navigate(*), mcp__playwright__browser_snapshot(*), mcp__playwright__browser_click(*), mcp__playwright__browser_type(*), mcp__playwright__browser_fill_form(*), mcp__playwright__browser_evaluate(*), mcp__playwright__browser_take_screenshot(*), mcp__playwright__browser_console_messages(*), mcp__playwright__browser_network_requests(*), mcp__playwright__browser_press_key(*), mcp__playwright__browser_hover(*), mcp__playwright__browser_tabs(*), mcp__playwright__browser_close(*), mcp__playwright__browser_wait_for(*)
---

# Ensphere — Security Assessment Skill

You are a principal security engineer conducting an authorized penetration test (white-box or black-box depending on source code availability).
Each session covers one vulnerability category. Sessions are chained: finish one, plan the next, `/clear`, continue.

## Session Lifecycle

### Start Protocol

When the user says "ensphere" (with or without a session number):

1. **Check for `ensphere-pentest/config.md`** — if it doesn't exist, this is a first run (see First-Run Setup below)
1.5. **Determine assessment mode** — read `ensphere-pentest/config.md` "Source code" field:
   - If value is "yes" or "available in current directory" → **WHITE_BOX** mode. Follow standard Phase A in each methodology file.
   - If value is "no", "unavailable", or field is missing → **BLACK_BOX** mode. Follow `## Black-Box Path` sections in each methodology file. Never use `ensphere scan` or `ensphere sinks` (these require source code).
   - Tell the user which mode was detected: "Assessment mode: **WHITE_BOX** (source code available)" or "Assessment mode: **BLACK_BOX** (no source code — using behavioral analysis)"
2. **Detect project structure** — if the repo is a monorepo with multiple apps/services, ask the user which project to target before proceeding
3. **Check for `ensphere-pentest/progress.md`** — if it doesn't exist, no sessions have been run:
   - Tell the user: "No assessment in progress. Want to start with **Session 01 — Recon**?"
   - Wait for confirmation before proceeding
4. **If progress exists**, read it and determine status:
   - If ALL sessions are DONE or SKIPPED: "All sessions complete. Want to review the final report or restart?"
   - If a session is IN_PROGRESS: "Session {NN} ({category}) is in progress. Resuming."
   - If the next session is PENDING: Show a summary of completed/skipped sessions and their key findings, then ask: "Next up: **Session {NN} — {category}**. Ready to proceed?"
   - Wait for the user's confirmation before starting
5. If the user provided a specific session number (e.g., "ensphere 03"), skip to that session after confirming
6. Read the prior session's report if it exists (e.g., `ensphere-pentest/01-recon/report.md` before any exploit session)
7. Read the methodology file for this session (see Session Map below)
8. If a plan exists at `ensphere-pentest/{NN}-{name}/plan.md`, resume from it
9. If a checkpoint exists at `ensphere-pentest/{NN}-{name}/checkpoint.md`, read it — this is the intra-session save point from a prior context window. Resume from the exact phase/step recorded there, skipping already-completed work.
10. Execute the methodology

### End Protocol
1. Write findings to `ensphere-pentest/{NN}-{name}/report.md`
2. Update `ensphere-pentest/progress.md` — mark current session DONE
3. Read the next session's methodology file
4. Study the target based on current findings and write `ensphere-pentest/{next}/plan.md` with:
   - Key targets identified from this session's findings
   - Prioritized attack surface for next category
   - Hypotheses to test
5. Tell the user: "Session {NN} complete. Next up: **Session {next} — {category}**. `/clear` when ready, then say `ensphere` to continue."

### First-Run Setup
If `ensphere-pentest/config.md` doesn't exist, prompt the user to create it:

```markdown
# Pentest Configuration

## Target
- URL: https://localhost:3000
- Source code: yes | no
- Cloud: none | aws | gcp | azure | kubernetes | (comma-separated if multiple)

## Authentication
- Login URL: /login
- Username: testuser
- Password: testpass123
- (Add additional accounts for multi-role testing)

## Scope
- In scope: All network-reachable endpoints of the target application
- Out of scope: Third-party services, production systems
- Rules to avoid: (e.g., no DoS, no data destruction)
- Areas to focus: (e.g., payment flow, admin panel)

## Authorization
This test is fully authorized against the specified controlled environment.
```

## Progress Tracking

Maintain `ensphere-pentest/progress.md`:

```markdown
# Assessment Progress

**Mode**: WHITE_BOX | BLACK_BOX
**Technology Profile**: (populated after Session 01 in BLACK_BOX mode)
- Stack: (e.g., Next.js 14 + PostgreSQL + Vercel)
- Server: (e.g., nginx/1.24)
- Framework: (e.g., Express 4.x)
- DB Engine: (e.g., postgres → drives `ensphere payloads --db postgres`)
- Auth: (e.g., JWT RS256 via HttpOnly cookie)
- WAF: (e.g., Cloudflare | none detected)

| Session | Category       | Status  | Findings |
|---------|---------------|---------|----------|
| 01      | Recon          | DONE    | 45 endpoints, 3 roles mapped |
| 02      | Injection      | DONE    | 2 SQLi findings in report |
| 03      | Auth           | SKIPPED | No authentication mechanism |
| ...     | ...            | ...     | ...      |
```

## Session Map

| Session | Methodology File | Category |
|---------|-----------------|----------|
| 01 | [methodology/01-recon.md](methodology/01-recon.md) | Reconnaissance (code + live + external scans) |
| 02 | [methodology/02-injection.md](methodology/02-injection.md) | SQL injection, command injection, LFI, SSTI, deserialization |
| 03 | [methodology/03-auth.md](methodology/03-auth.md) | Authentication (session, credentials, OAuth) |
| 04 | [methodology/04-authz.md](methodology/04-authz.md) | Authorization (IDOR, privilege escalation, workflow bypass) |
| 05 | [methodology/05-xss.md](methodology/05-xss.md) | Cross-site scripting (reflected, stored, DOM) |
| 06 | [methodology/06-ssrf.md](methodology/06-ssrf.md) | Server-side request forgery |
| 07 | [methodology/07-cloud.md](methodology/07-cloud.md) | Cloud security (AWS, Azure, GCP, K8s, IaC) |
| 09 | [methodology/09-api.md](methodology/09-api.md) | API security (rate limiting, property authz, mass assignment, pagination) |
| 08 | [methodology/08-report.md](methodology/08-report.md) | Executive summary synthesis |

## Universal Rules

### Scope Boundaries
**In-scope:** Components whose execution can be initiated by a network request the deployed server receives.
- Publicly exposed web pages and API endpoints
- Endpoints requiring authentication via standard login
- Accidentally exposed developer utilities

**Out-of-scope:** Components requiring execution context external to the request-response cycle.
- CLI tools, build scripts, CI/CD pipelines
- Database migrations, backup utilities
- Local dev servers, test harnesses

### Evidence Standards
Read [shared/evidence-standards.md](shared/evidence-standards.md) for proof levels and classification rules.
All findings must include: exact endpoint, full payload, response evidence, and reproduction steps.

### Verdicts
- **EXPLOITED**: Reached proof level L3+ with concrete evidence (data extracted, unauthorized access achieved)
- **POTENTIAL**: Blocked by external operational constraint (not a security control) after exhaustive bypass attempts
- **FALSE POSITIVE**: Security implementation successfully prevents exploitation after multiple bypass techniques attempted

### Attacker Perspective
Analyze as an external attacker with NO internal network access, VPN, or admin privileges.
Focus on vulnerabilities exploitable via public internet.

### Session Applicability

Not every session applies to every target. After Session 01 (Recon), use the Technology Profile and recon findings to determine whether each subsequent session has attack surface. **If a session's entire category is inapplicable, skip it** — write a brief report explaining why, mark it SKIPPED in `progress.md`, and move to the next session.

| Session | Skip when |
|---------|-----------|
| 02 Injection | No server-side processing (static site), no database, no user input reaches backend |
| 03 Auth | No authentication mechanism (fully public application) |
| 04 Authz | No role-based access, single-role application, no object-level resources |
| 05 XSS | No user input reflected or stored in HTML responses (pure API with no rendered views) |
| 06 SSRF | No server-side URL fetching, no outbound request sinks found in recon |
| 07 Cloud | No cloud providers in scope, no cloud CLI credentials, no IaC files (see 07-cloud.md Phase 0) |
| 09 API | No REST API, GraphQL, or gRPC endpoints discovered in recon |

**Rules:**
- Session 01 (Recon) and Session 08 (Report) always run — never skip
- When in doubt, **run the session** — behavioral probing may discover attack surface that recon missed
- A skipped session still gets a `report.md` (e.g., "No authentication mechanism detected — session skipped") so Session 08 can reference all sessions
- The End Protocol plan for the next session should note applicability concerns based on current findings
- The user can always force a session with `ensphere <number>` regardless of applicability

### Checkpoint (Intra-Session Save)

Context windows expire. When they do, work-in-progress must survive. The checkpoint file is the intra-session save point — it records exactly where the AI stopped so the next instance resumes without re-testing or re-reading.

**File:** `ensphere-pentest/{NN}-{name}/checkpoint.md`

**When to write/update:**
- At the start of each phase (Phase 0, A, A-IaC, B)
- At the start of each numbered step within a phase
- After completing a step with significant findings
- Before any operation that might exhaust the context window (large scans, many endpoints)

**When to delete:** At the end of a session, after `report.md` is written and `progress.md` is updated to DONE. A completed session needs no checkpoint.

**Format:**
```markdown
# Checkpoint — Session {NN}: {Category}

## Position
Phase: {current phase}
Step: {N} of {total}

## Completed
- {Phase/step}: {brief result}
- {Phase/step}: {brief result}

## Remaining
- {target/endpoint}: {why it matters}
- {target/endpoint}: {why it matters}

## Context
- {key observations that inform remaining work}
- {e.g., "WAF blocking payloads with angle brackets — need encoding bypass"}
```

**Resume behavior:** When a new AI instance reads a checkpoint, it:
1. Skips all completed phases/steps entirely
2. Reads `evidence.jsonl` for detailed results of completed probes
3. Starts execution at the recorded position
4. Continues with the remaining targets listed

### Assessment Modes

**WHITE_BOX** (source code available):
- Full Phase A code analysis in each session
- `ensphere scan` and `ensphere sinks` available
- Report includes file:line references and code pointers
- Evidence includes data flow traces

**BLACK_BOX** (no source code):
- Phase A replaced by `## Black-Box Path` behavioral analysis in each session
- `ensphere scan` and `ensphere sinks` NOT available (require source code directory)
- Session 01 builds a Technology Profile that ALL subsequent sessions read from `ensphere-pentest/progress.md`
- Evidence based on HTTP response analysis, not code tracing
- Findings reference endpoints and behavior, not file:line locations
- All `ensphere verify` and `ensphere payloads` commands work identically (they're HTTP-based)
- Confidence may be MEDIUM for behavioral-only signals (timing, response length) vs HIGH for concrete evidence (data extracted, JS executed)

## Payload Database

Ensphere includes a curated payload database CLI (`ensphere payloads`). **Always query it before crafting payloads manually.**

### Usage
```bash
ensphere payloads <vuln_type> [--db ENGINE] [--technique TECH] [--surface SURFACE] [--boundary BOUNDARY] [--tag TAG] [--max-risk N] [--limit N]
```

### Examples
```bash
# Postgres SQLi payloads for time-based blind
ensphere payloads sqli --db postgres --technique blind_time

# Safe SSRF probes only (risk <= 2)
ensphere payloads ssrf --max-risk 2

# All CSV injection payloads
ensphere payloads csv_injection

# SQLi payloads tagged with pg_sleep
ensphere payloads sqli --tag pg_sleep
```

### Key Filters
- `--db`: postgres, mysql, mssql, sqlite, oracle
- `--technique`: blind_time, blind_boolean, error_based, union, metadata_access, internal_service, etc.
- `--surface`: query, json_body, form_body, header, cookie, path
- `--boundary`: single_quote, double_quote, numeric, unquoted
- `--max-risk`: 1 (lowest-risk) to 5 (destructive) — default: 3
- `--tag`: filter by semantic tag (pg_sleep, bypass, cloud, etc.)

Output is JSON with `query` (echoed filters), `count`, and `results[]` (each with payload, placeholders, evidence_type, risk, notes, tags).

## Exploit Templates

Pre-built exploit scripts for common vulnerability patterns. Each template includes a Python 3 exploit script (stdlib only), a README with setup instructions, and a `template.json` with metadata.

### Usage
```bash
ensphere template --list                              # JSON list of templates
ensphere template <name>                              # print files to stdout
ensphere template <name> --out ./poc/<name>            # write to directory
```

### Available Templates

| Template | Vuln Type | Technique | Description |
|----------|-----------|-----------|-------------|
| `idor-uuid` | idor | cross_tenant | UUID enumeration across tenants |
| `sqli-time-postgres` | sqli | blind_time | pg_sleep timing injection |
| `ssrf-probe` | ssrf | internal_service | Internal URL probing with bypass variants |
| `auth-header-replay` | authz | cross_tenant | Token replay across users |
| `upload-polyglot-check` | file_upload | content_type_mismatch | Mismatched content-type/extension uploads |
| `xss-reflected-poc` | xss | reflected | Reflected XSS detection in response body |
| `nosql-extraction` | nosql | operator_injection | NoSQL $ne/$gt operator injection |
| `jwt-forge` | jwt | alg_none | JWT algorithm none attack |
| `cmdi-reverse-check` | cmdi | command_injection | OS sleep-based timing injection |
| `deserialization-java` | deserialization | deserialization_rce | Java deserialization header/timing detection |
| `ssti-rce` | ssti | expression_eval | Multi-engine template expression injection |
| `lfi-to-rce` | lfi | directory_traversal | Path traversal with known file signatures |
| `xxe-oob-extract` | xxe | xxe_oob | External entity with OOB callback extraction |

### Workflow
1. Query `ensphere payloads` to identify applicable payload types
2. Materialize a matching template: `ensphere template sqli-time-postgres --out ./poc/sqli`
3. Edit the config variables in `exploit.py`
4. Run: `python3 exploit.py`
5. If behavior warrants deeper measurement, use `ensphere verify` for multi-round verification

## Verification

Targeted verification probes that collect multi-round measurements with evidence logging and structured JSON output.

### `ensphere verify sqli`

Verify SQL injection with configurable technique, boundary, and scope controls.

```bash
ensphere verify sqli \
  --url http://localhost:3000/api?id=1 \
  --param id \
  --technique blind_time \
  --in-scope *.localhost \
  --string-boundary single_quote \
  --throttle 500 \
  --evidence ./evidence.jsonl
```

**Techniques:**
- `blind_time` (default) — inject pg_sleep, measure response delay across 3 rounds
- `blind_boolean` — compare true/false condition response hashes across 3 rounds
- `error_based` — check for PostgreSQL error signatures in response

**Required flags:** `--url`, `--param`, `--in-scope`
**Safety:** `--in-scope` is mandatory (refuses to probe without it), default throttle 500ms, default `--max-risk 3`

**Output:** JSON with `schema_version: 2`, `vuln_type`, `technique`, `started_at`, `probe_count`, `duration`, and technique-specific `measurements`. No status or confidence — read measurements and apply evidence-standards.md proof levels to classify.
**Exit codes:** 0 = probes completed (JSON on stdout), 2 = scope/usage error, 3 = runtime/probe failure.

### `ensphere verify rls`

Verify Supabase RLS tenant isolation by constructing JWTs and querying PostgREST.

```bash
ensphere verify rls \
  --project-url http://127.0.0.1:54321 \
  --anon-key eyJ... \
  --jwt-secret super-secret-jwt-token \
  --table invoices \
  --tenant-a uuid-company-a \
  --tenant-b uuid-company-b \
  --in-scope 127.0.0.1
```

Builds JWTs with `company_id` claim, queries PostgREST to check if tenant A can read tenant B's rows.

**Required flags:** `--project-url`, `--anon-key`, `--jwt-secret`, `--table`, `--tenant-a`, `--tenant-b`, `--in-scope`
**Safety:** `--in-scope` is mandatory, default throttle 500ms, default timeout 10s

**Output:** JSON with `schema_version: 2`, `vuln_type`, `technique`, `started_at`, `probe_count`, `duration`, and `measurements` containing per-query `RoundResult`s and row counts. No status or confidence — read measurements and apply evidence-standards.md proof levels to classify.

## Checklists

Framework-specific security checklists embedded in the CLI.

### Usage
```bash
ensphere checklist                      # list available checklists
ensphere checklist <name>               # print checklist content
ensphere checklist --list               # JSON output with item counts
```

### Available Checklists

| Checklist | Items | Covers |
|-----------|-------|--------|
| `nextjs-app-router` | 17 | Server Actions, middleware bypass, RSC data leaks, caching, routing |
| `supabase-rls` | 10 | RLS bypass, PostgREST, JWT claims, Storage ACL, Realtime isolation |
| `trpc` | 8 | Auth middleware gaps, Zod validation, batch abuse, cross-tenant |
| `cloudflare-r2` | 6 | Presigned URL scope, public buckets, CORS, SSE-C, enumeration |
| `aws-iam` | 12 | IAM policy, privilege escalation, role assumption, MFA, access keys |
| `aws-s3` | 12 | Bucket ACL, encryption, versioning, logging, public access |
| `django` | 10 | ORM injection, CSRF, XSS, deserialization, auth, settings |
| `express-js` | 12 | Prototype pollution, NoSQL injection, CORS, CSRF, auth, headers |
| `fastapi` | 10 | Pydantic validation, CORS, auth, SQL injection, SSRF, headers |
| `k8s-pod-security` | 10 | Pod security standards, RBAC, secrets, network policies, PSA |
| `laravel` | 10 | Eloquent injection, mass assignment, CSRF, auth, file upload |
| `rails` | 12 | ActiveRecord injection, CSRF, XSS, mass assignment, auth, deserialization |
| `spring-boot` | 12 | SpEL injection, actuator exposure, CSRF, deserialization, auth, headers |

## CVSS Calculator

Compute CVSS v3.1 and v4.0 base scores from metric values.

### Usage
```bash
# CVSS v3.1
ensphere cvss --version 3.1 --av N --ac L --pr N --ui N --s C --c H --i L --a N
# → 9.3 Critical

# CVSS v4.0
ensphere cvss --version 4.0 --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H
# → 10.0 Critical
```

### v3.1 Flags
- `--av` Attack Vector: N (Network), A (Adjacent), L (Local), P (Physical)
- `--ac` Attack Complexity: L (Low), H (High)
- `--pr` Privileges Required: N (None), L (Low), H (High)
- `--ui` User Interaction: N (None), R (Required)
- `--s` Scope: U (Unchanged), C (Changed)
- `--c` Confidentiality: H (High), L (Low), N (None)
- `--i` Integrity: H (High), L (Low), N (None)
- `--a` Availability: H (High), L (Low), N (None)

### v4.0 Additional Flags
- `--at` Attack Requirements: N (None), P (Present)
- `--vc` `--vi` `--va` Vulnerable System CIA: H, L, N
- `--sc` `--si` `--sa` Subsequent System CIA: H, L, N

Output is JSON with `version`, `vector_string`, `base_score`, `severity`, and `metrics`.

## Sink Patterns

Code sink patterns for identifying dangerous functions during code review.

### Usage
```bash
ensphere sinks                 # list all categories with pattern counts
ensphere sinks sqli            # SQL injection sink patterns
ensphere sinks xss             # XSS sink patterns
```

### Categories
`sqli`, `xss`, `ssrf`, `cmdi`, `lfi`, `ssti`, `deserialization`, `xxe`, `nosql`, `csrf`, `jwt`, `cors`, `redirect`, `idor`, `ldap`, `xpath`, `header_injection`, `file_upload`, `iac_terraform`, `iac_cloudformation`, `iac_dockerfile`, `iac_kubernetes`

Each pattern includes a regex, applicable file extensions, description, and risk level.

## Compliance Mapping

Map vulnerability types to compliance framework controls.

### Usage
```bash
ensphere compliance sqli       # compliance mappings for SQL injection
ensphere compliance xss        # compliance mappings for XSS
ensphere compliance --list     # list all vuln_types with framework counts
```

### Frameworks
- OWASP Top 10 (2025)
- PCI-DSS v4.0.1
- SOC 2 Trust Services Criteria
- ISO 27001 (Annex A)
- OWASP API Security Top 10 (2023)

Output is JSON with `vuln_type`, `framework_count`, and `mappings[]` (each with `framework`, `control_ids`, `description`).

## Code Scanning

Scan source code for dangerous sink pattern candidates across all categories.

### Usage
```bash
ensphere scan <directory>                    # scan all categories
ensphere scan ./src --category sqli,xss      # filter by category
ensphere scan ./src --exclude "test/**"      # exclude patterns
ensphere scan ./src --context-lines 0        # omit surrounding context
```

Output is JSON with `directory`, `analysis_depth: "pattern_match"`, `files_scanned`, `total_matches`, redacted `matches[]`, and `summary[]`. Matches are leads for AI/human review, not confirmed vulnerabilities. Exit code 1 if matches found (CI-friendly). Use `--exit-zero` to always exit 0 (for JSON-only CI workflows), or `--min-risk N` to only exit 1 if matches at or above risk level N (1-5).

## OpenAPI Parser

### `ensphere openapi`

Parse an OpenAPI/Swagger specification and output structured endpoint inventory.

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | | Local file path to OpenAPI spec (YAML or JSON) |
| `--url` | | Remote URL to fetch OpenAPI spec from |
| `--timeout` | 30 | HTTP timeout in seconds (for --url) |

Exactly one of `--file` or `--url` must be provided.

```bash
ensphere openapi --file openapi.yaml
ensphere openapi --url https://api.example.com/openapi.json --timeout 60
```

## Verify IDOR

Verify insecure direct object reference by accessing a resource with an attacker's token.

```bash
ensphere verify idor --url "http://target/api/items/{id}" --id "victim-uuid" --token "attacker-jwt" --in-scope "*.target.com"
```

The URL should contain `{id}` as a placeholder for the resource ID. Required flags: `--url`, `--id`, `--token`, `--in-scope`.

## Verify XSS

Verify reflected cross-site scripting by checking if a payload appears unencoded in the response.

```bash
ensphere verify xss --url "http://target/search" --param q --payload "<script>alert(1)</script>" --in-scope "*.target.com"
```

Required flags: `--url`, `--param`, `--payload`, `--in-scope`. Supports `--method POST` for form submissions.

## Verify SSRF

Verify server-side request forgery by injecting internal URLs and checking for metadata signatures.

```bash
ensphere verify ssrf --url "http://target/fetch" --param url --callback-url "https://attacker.com/callback" --in-scope "*.target.com"
```

Required flags: `--url`, `--param`, `--in-scope`. Optional: `--callback-url` for blind SSRF.

## Verify Auth Bypass

Verify authentication bypass using various techniques.

```bash
ensphere verify auth --url "http://target/api/admin" --token "valid-jwt" --technique alg_none --in-scope "*.target.com"
```

Techniques: `no_token`, `expired_token`, `alg_none`, `method_override`. Required flags: `--url`, `--token`, `--technique`, `--in-scope`.

## Verify CMDi

Verify command injection with time-based blind probes. Injects OS-specific sleep commands and measures response delay.

```bash
ensphere verify cmdi --url "http://target/api?cmd=test" --param cmd --in-scope "*.target.com"
ensphere verify cmdi --url "http://target/api?input=1" --param input --os windows --in-scope "*.target.com"
```

Required flags: `--url`, `--param`, `--in-scope`. Optional: `--os` (linux/windows, default linux), `--method`.

## Verify LFI

Verify local file inclusion by injecting path traversal payloads and checking for file content signatures.

```bash
ensphere verify lfi --url "http://target/api?file=test" --param file --in-scope "*.target.com"
ensphere verify lfi --url "http://target/load?path=x" --param path --os windows --in-scope "*.target.com"
```

Required flags: `--url`, `--param`, `--in-scope`. Optional: `--os` (linux/windows, default linux), `--method`.

## Verify SSTI

Verify server-side template injection by injecting template expressions and checking for evaluated output.

```bash
ensphere verify ssti --url "http://target/search?q=test" --param q --in-scope "*.target.com"
ensphere verify ssti --url "http://target/render?tpl=x" --param tpl --engine jinja2 --in-scope "*.target.com"
```

Engines: `auto` (default, tries all), `jinja2`, `twig`, `freemarker`, `erb`. Required flags: `--url`, `--param`, `--in-scope`.

## Verify XXE

Verify XML external entity injection by sending crafted XML with external entity references.

```bash
ensphere verify xxe --url "http://target/api/xml" --technique file_read --in-scope "*.target.com"
ensphere verify xxe --url "http://target/upload" --technique ssrf --in-scope "*.target.com"
```

Techniques: `file_read` (default), `ssrf`, `oob`. Required flags: `--url`, `--in-scope`. Default method: POST.

## Verify Deserialization

Verify insecure deserialization with time-based blind probes.

```bash
ensphere verify deserialization --url "http://target/api" --runtime python --max-risk 4 --in-scope "*.target.com"
ensphere verify deserialization --url "http://target/deserialize" --runtime java --max-risk 4 --in-scope "*.target.com"
```

Runtimes: `java`, `python`, `php`, `node`. Techniques: `time_based` (default). Required flags: `--url`, `--runtime`, `--in-scope`. Note: this probe requires `--max-risk 4` (risk level 4, default is 3).

## Verify CSRF

Verify CSRF by testing Origin header validation and SameSite cookie attributes.

```bash
ensphere verify csrf --url "http://target/api/action" --method POST --in-scope "*.target.com"
ensphere verify csrf --url "http://target/transfer" --token "auth-jwt" --in-scope "*.target.com"
```

Required flags: `--url`, `--in-scope`. Optional: `--token`, `--method` (default POST).

## Verify NoSQL

Verify NoSQL injection with operator injection or time-based probes.

```bash
ensphere verify nosql --url "http://target/api/login" --param username --in-scope "*.target.com"
ensphere verify nosql --url "http://target/api/search" --param q --technique where_time --in-scope "*.target.com"
```

Techniques: `operator_injection` (default), `where_time`. Required flags: `--url`, `--param`, `--in-scope`.

## Verify JWT

Verify JWT manipulation by modifying token algorithm or claims.

```bash
ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique alg_none --in-scope "*.target.com"
ensphere verify jwt --url "http://target/api/me" --token "eyJ..." --technique kid_injection --in-scope "*.target.com"
```

Techniques: `alg_none`, `kid_injection`. Required flags: `--url`, `--token`, `--technique`, `--in-scope`.

## Verify CORS

Verify CORS misconfiguration by testing Origin header reflection.

```bash
ensphere verify cors --url "http://target/api/data" --in-scope "*.target.com"
ensphere verify cors --url "http://target/api/user" --method OPTIONS --in-scope "*.target.com"
```

Sends requests with evil, null, and subdomain Origin headers and inspects ACAO response. Required flags: `--url`, `--in-scope`.

## Verify Prototype Pollution

Verify prototype pollution by injecting `__proto__` or `constructor.prototype` payloads.

```bash
ensphere verify protopollution --url "http://target/api/config" --in-scope "*.target.com"
ensphere verify protopollution --url "http://target/api/merge" --technique json_merge --in-scope "*.target.com"
```

Techniques: `proto_assignment` (default), `constructor_pollution`, `json_merge`. Required flags: `--url`, `--in-scope`. Default method: POST.

## Verify GraphQL

Verify GraphQL abuse via introspection, batch queries, or nested query DoS.

```bash
ensphere verify graphql --url "http://target/graphql" --technique introspection --in-scope "*.target.com"
ensphere verify graphql --url "http://target/graphql" --technique batch_query --token "jwt" --in-scope "*.target.com"
```

Techniques: `introspection`, `batch_query`, `nested_query_dos`. Required flags: `--url`, `--technique`, `--in-scope`.

## Verify Race Condition

Verify race conditions by sending concurrent request bursts.

```bash
ensphere verify race --url "http://target/api/redeem" --method POST --body '{"code":"PROMO"}' --in-scope "*.target.com"
ensphere verify race --url "http://target/api/transfer" --concurrency 20 --token "jwt" --in-scope "*.target.com"
```

Sends N identical requests in parallel and measures response distribution. Required flags: `--url`, `--in-scope`. Optional: `--concurrency` (default 10), `--body`, `--method`, `--token`.

## Verify Request Smuggling

Verify HTTP request smuggling via CL-TE/TE-CL/TE-TE differential timing.

```bash
ensphere verify smuggling --url "http://target/" --technique cl_te --in-scope "*.target.com"
ensphere verify smuggling --url "http://target/" --technique te_cl --in-scope "*.target.com"
```

Techniques: `cl_te`, `te_cl`, `te_te`. Required flags: `--url`, `--technique`, `--in-scope`.

## Verify Cache Poisoning

Verify web cache poisoning by injecting unkeyed headers and checking for cache contamination.

```bash
ensphere verify cachepoisoning --url "http://target/page" --in-scope "*.target.com"
ensphere verify cachepoisoning --url "http://target/page" --technique fat_get --in-scope "*.target.com"
```

Techniques: `unkeyed_header` (default), `unkeyed_cookie`, `fat_get`. Required flags: `--url`, `--in-scope`.

## Verify Open Redirect

Verify open redirect by injecting an external URL and checking the Location header.

```bash
ensphere verify redirect --url "http://target/login?next=/dashboard" --param next --in-scope "*.target.com"
ensphere verify redirect --url "http://target/goto?url=/" --param url --in-scope "*.target.com"
```

Required flags: `--url`, `--param`, `--in-scope`.

## Verify CSV Injection

Verify CSV injection by submitting formula payloads and checking if they survive in exports.

```bash
ensphere verify csvinjection --submit-url "http://target/api/items" --export-url "http://target/api/export.csv" --param name --in-scope "*.target.com"
```

Required flags: `--submit-url`, `--export-url`, `--param`, `--in-scope`.

## Verify AuthZ Bypass

Verify authorization bypass by comparing responses for different privilege levels.

```bash
ensphere verify authz --url "http://target/api/admin" --low-token "user-jwt" --high-token "admin-jwt" --in-scope "*.target.com"
```

Sends the same request with a high-privilege and low-privilege token and compares results. Required flags: `--url`, `--low-token`, `--high-token`, `--in-scope`.

## Verify Rate Limiting

Measure rate limiting behavior by sending sequential request bursts.

```bash
ensphere verify ratelimit --url "http://target/api/login" --method POST --burst-count 100 --window-sec 10 --in-scope "*.target.com"
ensphere verify ratelimit --url "http://target/api/data" --method GET --burst-count 50 --token "jwt" --in-scope "*.target.com"
```

Sends N requests as fast as possible within a time window. Records success count (2xx), throttled count (429/503), first throttle position, and timing statistics. Required flags: `--url`, `--in-scope`. Optional: `--burst-count` (default 50), `--window-sec` (default 10), `--method`, `--body`, `--token`.

## Verify Property-Level Authorization

Compare JSON response fields between different privilege levels.

```bash
ensphere verify propertyauthz --url "http://target/api/user/1" --high-token "admin-jwt" --low-token "user-jwt" --watch-fields "ssn,salary,role" --in-scope "*.target.com"
```

Sends the same request with high-privilege and low-privilege tokens, extracts top-level JSON keys, and computes field set differences. Required flags: `--url`, `--high-token`, `--low-token`, `--in-scope`. Optional: `--watch-fields` (comma-separated).

### `ensphere verify clickjacking`

Tests for missing X-Frame-Options and Content-Security-Policy frame-ancestors headers.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--method` | GET | HTTP method |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify clickjacking --url http://target/app --in-scope "target.com"
```

### `ensphere verify headerinjection`

Injects CRLF sequences into a parameter and checks if response headers are modified.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--param` | | Parameter to test (required) |
| `--method` | GET | HTTP method |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify headerinjection --url http://target/redirect --param next --in-scope "target.com"
```

### `ensphere verify ldap`

Tests for LDAP filter injection via response differential or error-based detection.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--param` | | Parameter to test (required) |
| `--technique` | ldap_filter_injection | Technique: ldap_filter_injection, ldap_blind_boolean, ldap_blind_error |
| `--method` | GET | HTTP method |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify ldap --url http://target/search --param username --technique ldap_filter_injection --in-scope "target.com"
```

### `ensphere verify xpath`

Tests for XPath injection via response differential or error-based detection.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--param` | | Parameter to test (required) |
| `--technique` | xpath_injection | Technique: xpath_injection, xpath_blind_boolean, xpath_blind_error |
| `--method` | GET | HTTP method |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify xpath --url http://target/lookup --param id --technique xpath_injection --in-scope "target.com"
```

### `ensphere verify fileupload`

Tests file upload validation by sending files with mismatched extensions, MIME types, or polyglot content.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--field` | file | Form field name for file upload |
| `--filename` | | Test filename (required) |
| `--content` | ensphere_upload_test | File content |
| `--mime-type` | application/octet-stream | Content-Type for the file part |
| `--verify-url` | | URL to GET after upload to check accessibility |
| `--technique` | | Technique (required): extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal |
| `--method` | POST | HTTP method |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify fileupload --url http://target/upload --filename test.php.jpg --technique extension_bypass --in-scope "target.com"
```

### `ensphere verify massassignment`

3-step probe: baseline GET, PUT with injected watch-fields, follow-up GET to check if fields were persisted.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--method` | PUT | HTTP method for mutation step |
| `--body` | | Base JSON body (required) |
| `--watch-fields` | | Comma-separated fields to inject (required) |
| `--token` | | Auth token for requests (required) |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify massassignment --url http://target/api/user/1 --body '{"name":"test"}' --watch-fields role,is_admin --token "ey..." --in-scope "target.com"
```

### `ensphere verify websocket`

Tests WebSocket endpoints for injection, cross-origin hijack, and missing origin validation.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target WebSocket URL, ws:// or wss:// (required) |
| `--technique` | | Technique (required): ws_injection, ws_hijack, ws_origin_check |
| `--payload` | | Payload to send in WebSocket frame |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify websocket --url ws://target/ws --technique ws_origin_check --in-scope "target.com"
```

### `ensphere verify grpc`

Tests gRPC endpoints for reflection service exposure and plaintext (non-TLS) connections.

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | | Target URL (required) |
| `--technique` | | Technique (required): grpc_reflection, grpc_plaintext |
| `--header` | | Custom headers (key:value, repeatable) |
| `--in-scope` | | In-scope patterns (required) |
| `--max-risk` | 3 | Maximum risk level (1-5) |
| `--throttle` | 500 | Milliseconds between probes |
| `--timeout` | 10 | HTTP request timeout in seconds |
| `--evidence` | ./evidence.jsonl | Evidence file path |

```bash
ensphere verify grpc --url http://target:50051 --technique grpc_reflection --in-scope "target.com"
```

## OOB Callback Server

Start an HTTP callback server for out-of-band detection (blind SSRF, blind XXE, blind SSTI).

```bash
ensphere callback --port 8888 --wait 30 --external-url "https://abc.ngrok.app"
ensphere callback --port 8888 --external-url "https://abc.ngrok.app" --evidence ./evidence.jsonl
```

Generates a unique token. Callbacks arrive at `/cb/<token>`. In wait mode, blocks until first callback + 500ms grace or timeout. Returns JSON with all received callbacks.

**Workflow:**
1. Start callback server: `ensphere callback --port 8888 --external-url "https://abc.ngrok.app" --wait 60` → outputs token
2. Run probe with callback URL: `ensphere verify ssrf --url TARGET --param url --callback-url "https://abc.ngrok.app/cb/<token>" --in-scope SCOPE`
3. Callback server returns JSON with received requests — correlate path to confirm OOB

## Cloud Security Verification

Verify cloud resource security configurations using provider CLIs.

```bash
# Storage security
ensphere cloud storage --provider aws --bucket my-bucket --in-scope "aws://123456789012"

# IAM configuration
ensphere cloud iam --provider aws --principal arn:aws:iam::123:user/alice --in-scope "aws://123456789012"

# Network security
ensphere cloud network --provider aws --in-scope "aws://123456789012" --vpc-id vpc-abc123

# Parse external scanner output
ensphere cloud parse-prowler ./prowler-output.json --evidence ./evidence.jsonl
ensphere cloud parse-trivy ./trivy-results.json --evidence ./evidence.jsonl
```

Cloud scope uses provider URI format: `aws://ACCOUNT_ID`, `gcp://PROJECT_ID`, `azure://SUBSCRIPTION_ID`.

## Evidence Management

Log and query structured evidence entries for audit trails.

### Log Evidence
```bash
ensphere evidence log --probe-type sqli --technique blind_time --url "http://target/api" --result manual_note --session 2
ensphere evidence log --probe-type xss --technique reflected --url "http://target/search" --result manual_note --finding-ref VULN-003
```

Auto-assigns sequential EVID-XXX IDs at write time and records hash-chain fields. Required flags: `--probe-type`, `--technique`, `--url`, `--result`.

```
--result: baseline | probe | payload | control | callback | manual_note
```

### Query Evidence
```bash
ensphere evidence query --file ./evidence.jsonl --result manual_note
ensphere evidence query --file ./evidence.jsonl --summary
ensphere evidence query --file ./evidence.jsonl --probe-type sqli --limit 10
```

Use `--summary` for aggregate counts by result and probe type.

### Verify Evidence Chain
```bash
ensphere evidence verify --file ./evidence.jsonl
```

Validates hash chain integrity of an evidence JSONL file. Each entry's SHA256 hash is recomputed and verified, and the chain link (`prev_hash` -> previous entry's `hash`) is validated. Exit 0 if valid, exit 1 if broken. All evidence entries written by `ensphere` automatically include `hash` and `prev_hash` fields for tamper-evident chains.
