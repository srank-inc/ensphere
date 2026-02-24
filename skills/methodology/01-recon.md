# Session 01: Reconnaissance

Merge of code analysis and live reconnaissance. This report is the foundation for ALL subsequent sessions.

## Phase 0: Target Triage

Before any testing, classify the target project and determine Ensphere's applicability.

1. **Analyze the codebase** to determine the project structure. Look for monorepo indicators: workspace configs (pnpm-workspace.yaml, lerna.json, nx.json, Cargo.toml workspaces, go.work), `packages/` or `apps/` directories, multiple Dockerfiles, multiple `package.json` or `go.mod` files, docker-compose with multiple services.
2. **If monorepo or multi-service project detected**:
   - Inventory all deployable components: backends, frontends, databases, mobile apps, CLI tools, libraries, workers, etc.
   - Present the inventory to the user and ask which specific service(s) to target. Ensphere tests one network-accessible surface at a time — the user must choose.
   - Example: "This monorepo contains 3 backends (api-gateway, billing-service, auth-service), 2 web apps (dashboard, admin-panel), 1 iOS app, and 2 databases. Which service should Ensphere target? Note: mobile apps are client-only — if you want to test the API they call, point me at that backend."
   - Wait for user response before proceeding.
3. **Classify the target** (the selected service, or the whole project if single-service): web app, API backend, microservice, mobile client (iOS/Flutter/React Native), desktop app (Electron/native), CLI tool, library, or other.
4. **Detect network-accessible attack surface**: Look for HTTP servers, API route definitions, database connections, RPC endpoints, WebSocket handlers, or any code that listens on a network port.
5. **Decide applicability**:
   - **Network surface found** → proceed with assessment. Record the project classification and available attack surface in the report.
   - **Client-only project with a remote backend** → inform the user that Ensphere tests network-accessible surfaces, the client-side code itself is out of scope, and suggest pointing Ensphere at the backend repository or API instead.
   - **No network surface at all** → inform the user that this project has no network-accessible attack surface and Ensphere cannot effectively test it. Explain what was found and why.
6. **Determine tool availability** based on project type:
   - **Has a browser UI** (web app, full-stack) → use Playwright in Phase B for interactive exploration
   - **API-only backend** (no UI, serves mobile/desktop/other clients) → skip Playwright, use `curl` for endpoint probing
   - **No network surface** → exit early after informing the user

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Endpoint probing, header inspection | Tier 2 | `curl` via Bash |
| Browser-based exploration | Tier 3 | Playwright MCP |
| Sink pattern lookup | Tier 1 | `ensphere sinks <category>` |
| Automated codebase scanning | Tier 1 | `ensphere scan <directory>` |
| Pattern matching in source | — | Grep tool |

**Decision flow:**
1. Use `ensphere scan <dir>` for automated detection of dangerous patterns across the codebase
2. Use `ensphere sinks <category>` to get pattern lists, then Grep to find actual matches in source
3. Use `curl` for endpoint probing and header inspection during live exploration
4. Use Playwright for browser-based Phase B exploration (login flows, multi-step processes)

## Black-Box Path

When assessment mode is BLACK_BOX (no source code available), replace Phase A AND Phase B with the following phases. Phase C (External Scans) still applies after these complete. Do NOT run the white-box Phase A or Phase B — the black-box phases below fully replace them.

Note: Phase 0 (Target Triage) runs first in ALL modes — it determines project structure and tool availability. The black-box path starts AFTER Phase 0 completes.

### Phase BB-1: Passive Intelligence

Gather information using only normal HTTP requests — no attack payloads, no fuzzing.

**Step 1 — Well-Known Paths**: Fetch each with `curl -sI` or `curl -s` via Bash. Record status codes and content.

| Path | Intelligence Value |
|------|-------------------|
| `/robots.txt` | Disallowed paths = discovery targets for Phase BB-3 |
| `/sitemap.xml` | Canonical URL inventory |
| `/.well-known/security.txt` | Security contacts, scope hints |
| `/.well-known/openid-configuration` | OAuth/OIDC metadata, token endpoints |
| `/swagger.json`, `/openapi.json`, `/api-docs`, `/docs`, `/redoc` | API documentation = complete endpoint inventory |
| `/graphql` (POST `{"query":"{__schema{types{name}}}"}`) | GraphQL introspection = full type/query/mutation schema |
| `/api/graphql` (same POST) | Alternative GraphQL path |

If an OpenAPI/Swagger spec is found, parse it — this is equivalent to reading route definitions in source code. Extract all endpoints, methods, parameters, and response schemas.

If GraphQL introspection succeeds, extract all queries, mutations, types, and fields. This reveals the complete data model without source code.

**Step 2 — HTTP Header Fingerprinting**: Fetch response headers from three URLs: the root `/`, a 404-triggering path `/ensphere-nonexistent-path-404`, and `/api/` (or known API base). Record:

| Header | What It Reveals |
|--------|----------------|
| `Server` | Web server software (nginx, Apache, IIS, Caddy) |
| `X-Powered-By` | Language/framework (PHP, ASP.NET, Express) |
| `X-Frame-Options` | Security header configuration |
| `Content-Security-Policy` | CSP policy (affects XSS exploitation) |
| `Strict-Transport-Security` | HSTS enforcement |
| `Set-Cookie` | Cookie names + flags (see Step 3) |
| `X-Request-Id` / `X-Trace-Id` | Backend request tracing (framework clue) |
| CORS headers | Cross-origin configuration |

**Step 3 — Cookie Fingerprinting**: Map observed cookie names to known frameworks:

| Cookie Name | Framework |
|-------------|-----------|
| `JSESSIONID` | Java (Tomcat, Spring) |
| `PHPSESSID` | PHP |
| `connect.sid` | Express/Node.js (express-session) |
| `_rails_session` | Ruby on Rails |
| `csrftoken` + `sessionid` | Django |
| `ASP.NET_SessionId` | ASP.NET |
| `next-auth.session-token` | NextAuth.js (Next.js) |
| `sb-*-auth-token` | Supabase |
| `laravel_session` | Laravel (PHP) |
| `__Host-` / `__Secure-` prefix | Modern security-conscious framework |

### Phase BB-2: Technology Fingerprinting (replaces Phase A code analysis)

**Step 1 — Error Page Analysis**: Trigger error responses to identify framework:
- `curl -s TARGET/nonexistent-path` → 404 error format
- `curl -s -X DELETE TARGET/` → method not allowed format
- `curl -s -H "Content-Type: application/json" -d "invalid-json" TARGET/api/` → parse error format

Framework identification from error responses:
| Pattern | Framework |
|---------|-----------|
| `__NEXT_DATA__` in 404 page | Next.js |
| "ActionController::RoutingError" | Ruby on Rails |
| "Page not found" + Django template | Django |
| "Whitelabel Error Page" | Spring Boot |
| "Cannot GET /path" | Express.js |
| "404 page not found" (plain) | Go stdlib |
| ASP.NET yellow error page | ASP.NET |

**Step 2 — HTML Source Analysis** (if target has browser UI): Fetch the root page and analyze:
- `__NEXT_DATA__` script tag → Next.js (extract build ID, props)
- `ng-version` attribute → Angular (extract version)
- `data-reactroot` or `__REACT_DEVTOOLS_GLOBAL_HOOK__` → React
- `__nuxt` or `window.__NUXT__` → Nuxt.js
- `data-v-` attribute prefixes → Vue.js
- `<meta name="generator" content="...">` → CMS identification
- Script src paths: `/_next/` (Next.js), `/static/js/` (CRA React), `/assets/` (Vite)

**Step 3 — JavaScript File Analysis**: Extract all loaded JS files (via Playwright `browser_network_requests` if browser UI, or parse HTML `<script src>` tags with curl). For each JS file, search for:
- API endpoint paths: `/api/`, `/v1/`, `/graphql`, route patterns
- Hardcoded keys: `API_KEY`, `SECRET`, `token`, `Bearer`
- OAuth configuration: `client_id`, `redirect_uri`, `authorize`
- WebSocket URLs: `wss://`, `ws://`
- DOM sinks (note for Session 05): `innerHTML`, `eval(`, `document.write(`, `setTimeout(` with string arg
- Internal hostnames or IP addresses

**Step 4 — API-Specific Discovery** (for API backends without browser UI):
- Send `OPTIONS` requests to discovered endpoints → extract `Allow` header for permitted methods
- Content-Type probing: test if endpoints accept `application/json`, `application/xml`, `multipart/form-data`, `application/x-www-form-urlencoded`
- Error verbosity comparison: compare error responses at different paths for framework clues
- JWT decode (if auth uses Bearer tokens): base64-decode header and payload (no secret needed) → extract `alg`, claims structure (`sub`, `role`, `iss`, `exp`), custom claims

**Step 5 — Build Technology Profile**: Consolidate all findings into a structured profile:

```
## Technology Profile

| Layer | Technology | Confidence | Evidence |
|-------|-----------|------------|---------|
| Server | nginx 1.24 | HIGH | Server header |
| Runtime | Node.js | HIGH | X-Powered-By header |
| Framework | Next.js 14 | HIGH | __NEXT_DATA__ in HTML |
| CSS | Tailwind | MEDIUM | Utility classes in HTML |
| Auth | JWT RS256 | HIGH | Decoded JWT header |
| Database | PostgreSQL | MEDIUM | Error message pattern |
| Hosting | Vercel | MEDIUM | Response headers |
| WAF | Cloudflare | HIGH | cf-ray header |

### Payload Selection Implications
- SQLi: use `ensphere payloads sqli --db postgres`
- XSS: React auto-escapes JSX — focus on `dangerouslySetInnerHTML`, server-rendered content, and DOM sinks found in JS
- SSTI: Not applicable (React/Next.js don't use server-side template engines with user input)
- Auth: JWT-based — test alg:none, weak secrets, claim manipulation
- SSRF: Check for image processing, webhook, or proxy endpoints
```

Write this Technology Profile to `pentest/progress.md` (it persists across sessions).

### Phase BB-3: Active Discovery (replaces Phase B live exploration)

**Step 1 — Crawl**:
- If browser UI: Use Playwright to navigate target URL, authenticate per `pentest/config.md`, then systematically click every navigation link, open dropdowns, submit forms with benign data. Use `browser_network_requests` to capture all XHR/fetch calls — these reveal the real API surface.
- If API-only: Skip to Step 2.

**Step 2 — Authentication Flow Mapping**: Use curl to map the auth lifecycle:
- Login request → capture tokens/cookies, note token type (JWT vs opaque), location (cookie vs Authorization header)
- If JWT: decode header+payload, document algorithm, claims, roles
- Test token refresh (if refresh token present)
- Test session expiry behavior
- If OAuth: use Playwright to follow redirect chain, capture authorization URL parameters

**Step 3 — Framework-Specific Directory Probing**: Based on Technology Profile, probe TARGETED paths (NOT brute-force). Use curl with status code checking.

For Next.js:
```
/_next/data/BUILD_ID/*.json, /api, /api/auth/session, /api/auth/signin, /api/auth/signout, /api/trpc, /_next/image
```

For Django:
```
/admin, /admin/login, /api/schema, /__debug__, /api/v1, /static
```

For Rails:
```
/rails/info, /rails/info/routes, /rails/mailers, /sidekiq, /admin, /api/v1
```

For Express/Node.js:
```
/api/v1, /health, /healthz, /readiness, /metrics, /debug, /status, /graphql, /socket.io
```

For any framework:
```
/.env, /.git/HEAD, /config, /actuator, /actuator/health, /server-status, /phpinfo.php, /wp-admin, /elmah.axd
```

**Step 4 — GraphQL Deep Introspection**: If GraphQL detected in Phase BB-1, run full introspection:
```bash
curl -s -X POST TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } } } } }"}'
```
This reveals the COMPLETE data model — equivalent to reading database schema from source code.

**Step 5 — Canary Injection for Reflection Detection**: For every input parameter discovered, inject a unique tracking string (e.g., `ensph3r3canary`). Check each response for the canary. For each reflection, record:
- **Parameter**: which input
- **Location in response**: HTML body, HTML attribute, JS string, JSON value, HTTP header
- **Encoding applied**: none (raw reflection), HTML-encoded, URL-encoded, JS-escaped, stripped

This data feeds directly into Session 02 (injection candidate inputs) and Session 05 (XSS reflection points).

**Step 6 — Input Vector Catalog**: For every discovered endpoint, document:

| Endpoint | Method | Param | Location | Type | Reflects | Context | Candidate For |
|----------|--------|-------|----------|------|----------|---------|---------------|
| /api/search | GET | q | query | string | yes | HTML body | XSS, SQLi |
| /api/users/{id} | GET | id | path | uuid | no | — | IDOR |
| /api/webhook | POST | url | json_body | url | no | — | SSRF |
| /api/login | POST | email | json_body | string | yes | JSON | SQLi |

### Black-Box Report Template

Write to `pentest/01-recon/report.md` with these adapted sections:

#### 1. Executive Summary
Same as white-box.

#### 2. Technology Profile
Full technology profile from Phase BB-2 Step 5 (instead of white-box "Technology & Service Map").

#### 3. Authentication & Session Management
Behavioral findings: token type, cookie flags, session handling, OAuth flow. No file:line references.

#### 4. API Endpoint Inventory
Table: Method | Path | Required Role | Object ID Params | Auth Mechanism | **Discovery Method** (crawl, JS analysis, directory probe, API schema, robots.txt, GraphQL introspection)

#### 5. Input Vectors
Table from Phase BB-3 Step 6. Includes "Reflects" and "Candidate For" columns.

#### 6. Network & Interaction Map
Same as white-box but inferred from behavior.

#### 7. Role & Privilege Architecture
Inferred from JWT claims, API responses, UI elements. No code-level role mapping.

#### 8. Authorization Vulnerability Candidates
Same structure (8.1 Horizontal, 8.2 Vertical, 8.3 Context) but based on endpoint+behavior analysis, not code tracing.

#### 9. XSS Reflection Points (replaces "XSS Sinks")
From Phase BB-3 Step 5 canary injection. Table: Parameter | Endpoint | Reflection Context | Encoding Applied

#### 10. SSRF Candidate Inputs (replaces "SSRF Sinks")
URL-accepting parameters identified from endpoint names and parameter analysis.

#### 11. Injection Candidate Inputs (replaces "Injection Sources")
Parameters that produced interesting error responses during canary injection.

#### 12. External Scan Results (replaces "Critical File Paths")
nmap, subfinder, whatweb results.

## Phase A: Code Analysis

Use Task agents (subagent_type: Explore) to scan the codebase. If source code is not available, skip to Phase B.

Launch these analyses in parallel:

1. **Architecture Scanner**: Map technology stack, frameworks, architectural patterns, security-relevant configurations. Determine app type (web, API, microservices, hybrid). Note security implications.

2. **Entry Point Mapper**: Find ALL network-accessible entry points — API endpoints, web routes, webhooks, file uploads, externally-callable functions. Catalog API schema files (OpenAPI, GraphQL, JSON Schema). Distinguish public vs authenticated endpoints. Provide exact file paths and route definitions.

3. **Security Pattern Hunter**: Identify authentication flows, authorization mechanisms, session management, security middleware. Map JWT handling, OAuth flows, RBAC, permission validators, security headers. Provide exact file locations.

After Phase 1, launch in parallel:

4. **XSS/Injection Sink Hunter**: Find dangerous sinks — innerHTML, document.write, eval, setTimeout(string), SQL construction, exec/system calls, file operations (fopen, include, readFile), template engines, deserialization. Provide file:line locations. Report explicitly if none found.

5. **SSRF/External Request Tracer**: Find all server-side outbound request locations — HTTP clients, URL fetchers, webhook handlers, external API integrations, file inclusion. Map user-controllable request parameters. Report explicitly if none found.

6. **Data Security Auditor**: Trace sensitive data flows, encryption, secret management, database security. Identify PII handling, payment data, compliance-relevant code.

## Phase B: Live Exploration

**If the target has a browser UI** — use Playwright MCP tools:

1. Navigate to target URL from `pentest/config.md`
2. Map user-facing functionality: login, registration, password reset, dashboards
3. Follow login instructions from config to authenticate
4. Explore authenticated areas systematically
5. Observe network requests to identify API patterns
6. Document multi-step processes and form submissions

**If the target is an API-only backend** (no browser UI) — use `curl` via Bash:

1. Probe documented endpoints from code analysis (OpenAPI specs, route definitions)
2. Test authentication flows (obtain tokens, test session handling)
3. Enumerate API responses, error formats, and header policies
4. Map multi-step API workflows (e.g., create → update → delete)
5. Document response patterns and authorization behavior

## Phase C: External Scans

Run via Bash. Gracefully skip any tool not installed.

```bash
# Port scanning
nmap -sV -sC -T4 TARGET_HOST -oN pentest/01-recon/nmap.txt 2>/dev/null || echo "nmap not installed, skipping"

# Subdomain enumeration
subfinder -d TARGET_DOMAIN -o pentest/01-recon/subdomains.txt 2>/dev/null || echo "subfinder not installed, skipping"

# Technology fingerprinting
whatweb TARGET_URL -v > pentest/01-recon/whatweb.txt 2>/dev/null || echo "whatweb not installed, skipping"
```

## Report Template

Write to `pentest/01-recon/report.md` with these sections:

### 1. Executive Summary
2-3 paragraph overview of security posture and critical attack surfaces.

### 2. Technology & Service Map
Frontend, backend, infrastructure, subdomains, open ports.

### 3. Authentication & Session Management
Entry points, mechanism details, cookie flags, session handling, role assignment, privilege storage.
**Must include**: all auth API endpoints, exact file:line of cookie flag configuration, SSO/OAuth flow details if present.

### 4. API Endpoint Inventory
Table: Method | Path | Required Role | Object ID Params | Auth Mechanism | Code Pointer

### 5. Input Vectors
URL parameters, POST body fields, HTTP headers, cookie values — with file:line locations.

### 6. Network & Interaction Map
Entities (services, datastores, third parties), flows between them, guards (auth, network, protocol), metadata.

### 7. Role & Privilege Architecture
Discovered roles with privilege levels, privilege lattice, role entry points, role-to-code mapping.

### 8. Authorization Vulnerability Candidates
Pre-prioritized lists organized by:
- **8.1 Horizontal**: Endpoints with object IDs that could allow cross-user access
- **8.2 Vertical**: Admin/privileged endpoints testable from lower-privilege roles
- **8.3 Context/Workflow**: Multi-step endpoints that assume prior steps completed

### 9. XSS Sinks and Render Contexts
All dangerous sinks with file:line, organized by render context (HTML body, attribute, JavaScript, CSS, URL).

### 10. SSRF Sinks
All server-side request locations with file:line — HTTP clients, raw sockets, URL openers, redirect handlers, headless browsers, media processors, webhook testers, JWKS fetchers, importers.

### 11. Injection Sources
SQL injection, command injection, LFI/RFI, SSTI, deserialization sources traced to dangerous sinks with file:line and data flow path.

### 12. Critical File Paths
Categorized: config, auth, API/routing, data models, dependencies, secrets, middleware, infrastructure.
