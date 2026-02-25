# Session 02: Injection

Covers: SQL injection, command injection, LFI/RFI, SSTI, path traversal, deserialization.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| SQL injection verification | Tier 1 | `ensphere verify sqli` — ALWAYS use first |
| Payload lookup | Tier 1 | `ensphere payloads sqli/cmdi/lfi/ssti/xxe` |
| Exploit templates | Tier 1 | `ensphere template sqli-time-postgres` |
| Sink pattern discovery | Tier 1 | `ensphere sinks sqli/cmdi/lfi/ssti/deserialization/xxe` |
| Non-SQLi injection (CMDi, LFI, SSTI, XXE) | Tier 2 | `curl` via Bash |
| Browser-based testing | Tier 3 | **NEVER** — no benefit for server-side injection |

**Decision flow:**
1. Run `ensphere sinks <type>` for each injection category to get patterns
2. Query `ensphere payloads <type>` for curated payloads before crafting custom ones
3. For SQLi: **always** use `ensphere verify sqli` for multi-round verification with evidence
4. For non-SQLi: use `curl` for manual probing and payload injection
5. Never use Playwright for server-side injection — it adds latency with no benefit

**Black-box note:** In BLACK_BOX mode, `ensphere sinks` is not available. Skip step 1 (sink pattern discovery) and rely on behavioral detection instead.

## Black-Box Path

When assessment mode is BLACK_BOX, replace Phase A (code review) with the following. Phase B (Exploitation) still applies after this.

### Phase A-BB: Behavioral Injection Detection (replaces code review)

Read `ensphere-pentest/01-recon/report.md` sections 5 (Input Vectors) and 11 (Injection Candidate Inputs) for your target list.
Read the Technology Profile from `ensphere-pentest/progress.md` for DB engine and framework info.

**Step 1 — Error Character Probing**: For each candidate endpoint+parameter from the recon report, inject error-inducing characters ONE AT A TIME and record status code, response length, and notable content:

| Probe | Targets | Indicates |
|-------|---------|-----------|
| `'` (single quote) | SQL string context | SQLi (string boundary) |
| `"` (double quote) | SQL/JSON context | SQLi or JSON parse error |
| `1 OR 1=1` | SQL numeric context | SQLi (boolean) |
| `1' OR '1'='1` | SQL string context | SQLi (boolean in string) |
| `;--` | SQL statement termination | SQLi (stacked queries) |
| `;ls` / `\|id` / `` `id` `` | Command execution | Command injection |
| `{{7*7}}` | Template expression (Jinja2, Twig) | SSTI — check for `49` in response |
| `${7*7}` | Template expression (Mako, Freemarker) | SSTI — check for `49` in response |
| `../../etc/passwd` | File path traversal | LFI |
| `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | XML entity | XXE (only on XML-accepting endpoints) |

**Step 2 — Response Classification**: Map observed behaviors to injection types:

| Observed Behavior | Classification | Next Step |
|-------------------|---------------|-----------|
| SQL error message (syntax error, unterminated string, relation does not exist, ORA-, MySQL error) | **SQLi confirmed** | Proceed to exploitation |
| Different response for `' AND 1=1--` vs `' AND 1=2--` | **SQLi likely (boolean-based blind)** | Verify with `ensphere verify sqli --technique blind_boolean` |
| Same response regardless of input | **Input sanitized or ignored** | Try encoding variants |
| `49` appears for `{{7*7}}` | **SSTI confirmed** | Proceed to exploitation |
| File contents in response for `../../etc/passwd` | **LFI confirmed** | Proceed to exploitation |
| Generic 403/block page | **WAF detected** | See Step 5 |
| HTTP 500 with framework stack trace | **Error-based info disclosure** | Extract framework/DB info, retry with context-aware payloads |

**Step 3 — Technology-Aware Payload Selection**: Read Technology Profile from `ensphere-pentest/progress.md`:
- If DB Engine is `postgres`: `ensphere payloads sqli --db postgres --technique blind_time`
- If DB Engine is `mysql`: `ensphere payloads sqli --db mysql --technique blind_time`
- If DB Engine is `mssql`: `ensphere payloads sqli --db mssql --technique blind_time`
- If DB Engine is unknown: use generic payloads first, identify from error messages, then switch to engine-specific payloads
- For each non-SQLi type: `ensphere payloads cmdi|lfi|ssti|xxe --max-risk 3`

**Step 4 — Blind Technique Prioritization**: When no visible errors are returned, escalate through techniques in order:
1. **Time-based blind** (most reliable): `ensphere verify sqli --url URL --param PARAM --technique blind_time --in-scope SCOPE`
2. **Boolean-based blind** (requires two distinguishable response states): `ensphere verify sqli --technique blind_boolean`
3. **Error-based** (requires error messages in response): `ensphere verify sqli --technique error_based`

**Step 5 — WAF Detection and Bypass**: If payloads are consistently blocked (403, custom block page, connection reset):
1. Confirm WAF from response headers: `cf-ray` (Cloudflare), `x-amzn-waf-` (AWS WAF), `akamai-` (Akamai), `x-sucuri-` (Sucuri)
2. Try encoding variants: test same payloads with URL encoding, double URL encoding, Unicode encoding, case randomization
3. Try different injection surfaces: `--surface header` (inject in Referer, User-Agent), `--surface cookie`
4. Try comment-based keyword breaking: `SEL/**/ECT`, `UN/**/ION`
5. Document WAF behavior separately from underlying vulnerability — WAF blocking ≠ proof that code is secure

**Step 6 — Non-SQLi Injection Testing**:
- **Command injection**: test endpoints that perform file operations, generate reports, or interact with OS. Use `ensphere payloads cmdi --max-risk 3`
- **LFI**: test file download/include endpoints, path parameters. Use `ensphere payloads lfi --max-risk 3`
- **SSTI**: test endpoints where user input appears in server-rendered HTML. Use `ensphere payloads ssti`
- **XXE**: test XML-accepting endpoints (check Content-Type headers from recon). Use `ensphere payloads xxe`
- **Deserialization**: test endpoints accepting serialized data (Java objects, PHP serialize, Python pickle). Use `ensphere payloads deserialization`

After Phase A-BB, proceed to **Phase B: Exploitation** (same as white-box path — the exploitation steps are identical regardless of how injection points were discovered).

## Phase A: Vulnerability Analysis (Code Review)

Read `ensphere-pentest/01-recon/report.md` section 11 (Injection Sources) for your target list.
Create a task for each injection source to trace.

### Slot Type Taxonomy

Label every sink with its slot type — this determines what defense is required:

| Slot Type | Context | Required Defense |
|-----------|---------|-----------------|
| SQL-val | Value in WHERE/INSERT | Parameter binding |
| SQL-like | LIKE pattern | Bind + escape `%_` |
| SQL-num | Numeric comparison | Type cast to int/float |
| SQL-enum | ENUM/status value | Strict whitelist |
| SQL-ident | Column/table name in ORDER BY, GROUP BY | Strict whitelist (binds don't work) |
| CMD-argument | Shell command argument | Array args (shell=False) OR shlex.quote() |
| CMD-part-of-string | Interpolated into shell string | Array args (shell=False) — no other defense sufficient |
| FILE-path | File path for read/write/include | Whitelist paths OR resolve() + boundary check |
| FILE-include | Dynamic include/require | Whitelist only |
| TEMPLATE-expression | Template engine expression | Sandboxed context + autoescape, no user input in expressions |
| DESERIALIZE-object | Deserialization input | Trusted sources only + safe formats + HMAC |
| PATH-component | URL path segment | Whitelist or strict validation |

### Tracing Methodology

For each source from the recon report:
1. **Trace data flow** from source to sink — record all assignments, function calls, string operations
2. **Record sanitizers** on the path — name, file:line, type (binding, cast, whitelist, escape)
3. **Record concatenations** — each concat/format/join with file:line. **Flag any concat AFTER sanitization** (invalidates the sanitizer)
4. **Label the sink slot type** from the taxonomy above
5. **Match sanitization to slot context** — is the defense correct for THIS slot type?
6. **Verdict**: vulnerable if tainted input reaches a slot with no defense or wrong defense

### Key Rules
- Normalizers (lowercasing, trimming, JSON parse) do NOT remove taint
- Concat after sanitization treats the sanitizer as non-effective
- Binds protect values but NOT identifiers or keywords
- Regex/generic escaping is insufficient where binds are required
- Blacklists are insufficient for command injection

## Phase B: Exploitation

**Before crafting payloads manually, query the payload database:**
```bash
ensphere payloads sqli --db postgres --technique blind_time --surface query
ensphere payloads sqli --db postgres --technique error_based --boundary single_quote
```
Use the returned payloads as starting points. Substitute placeholders (SLEEP_SECONDS, TABLE_NAME, etc.) with target-specific values. Only craft custom payloads if the database doesn't cover your exact context.

**For structured exploitation, materialize a template:**
```bash
ensphere template sqli-time-postgres --out ./poc/sqli
# Edit ./poc/sqli/exploit.py with target-specific values, then run:
python3 ./poc/sqli/exploit.py
```

**For multi-round verification with evidence logging:**
```bash
ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --in-scope *.localhost --technique blind_time
ensphere verify sqli --url http://localhost:3000/api?id=1 --param id --in-scope *.localhost --technique error_based
```

For each vulnerable path found in Phase A, follow OWASP stages:

### Stage 1: Confirmation
Inject error-inducing characters, boolean conditions, and time delays.
- **SQLi**: `'`, `"`, `)`, `;`, `\` | `' AND 1=1--` vs `' AND 1=2--` | `'; WAITFOR DELAY '00:00:05'--`
- **CMDi**: `; ls -la` | `| whoami` | `` `id` `` | `$(cat /etc/passwd)`
- **LFI**: `../../../../etc/passwd` | `....//....//etc/passwd`
- **SSTI**: `{{7*7}}` | `${7*7}` | `<%= 7*7 %>`

### Stage 2: Fingerprinting
Extract DB version, current user, table names. Identify most sensitive table and its columns.

### Stage 3: Exfiltration
Extract first 5 rows from the most sensitive table as proof of impact.

### Tool Strategy
- Use `curl` for manual probing and crafting specific bypasses
- Use `sqlmap` for time-consuming blind injection or when manual testing exceeds 10-12 attempts without progress
- Use Task agent for custom scripting (payload loops, enumeration)

## Report Format

Write to `ensphere-pentest/02-injection/report.md`:

### Successfully Exploited
For each: vulnerability ID, type, endpoint, slot type, payload chain, proof of data extraction.

### False Positive Rules
- Early sanitization followed by concat = still tainted
- Application-level 400 errors ≠ backend execution errors
- WAF blocking ≠ proof of underlying flaw (document WAF behavior separately)
- Binds on values don't protect identifiers
- Generic regex/escaping ≠ parameter binding

### Vectors Confirmed Secure
Table: Source | Endpoint | Defense Mechanism | Verdict
