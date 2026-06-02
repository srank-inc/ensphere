# Ensphere Pricing Reference

## Pricing Model: License-Based (Not Per-Call Credits)

Ensphere has zero marginal cost per tool call — probes run locally on the user's machine, not on Ensphere's servers. Per-call credits would be artificial scarcity. Instead, all plans include **unlimited tool calls**.

The recurring value is the **server-side payload intelligence feed** — 1,206+ curated payloads, updated monthly with new CVEs and techniques.

---

## Plans

| Plan | Monthly | Annual (per month) | Annual Total | Seats | Sessions |
|------|---------|-------------------|-------------|-------|----------|
| **Solo** | $29/mo | $24/mo | $290/yr | 1 | 1 |
| **Team** | $99/mo | $83/mo | $990/yr | 5 | 5 |
| **Business** | $249/mo | $208/mo | $2,490/yr | 15 | 15 |
| **Enterprise** | Custom | Custom | Custom | Unlimited | Unlimited |

Annual billing = pay 10 months, get 12 (2 months free).

---

## What Each Plan Includes

### All Plans

- Unlimited MCP tool calls (all 55 tools)
- Server-side payload API (latest payloads, monthly updates)
- All 33 verification probes
- All cloud security tools
- Evidence system, CVSS, compliance mapping
- 30-day offline grace period
- Auto-updates (payloads, templates, checklists)
- 14-day free trial (no credit card)

### Plan Differences

| Feature | Solo | Team | Business | Enterprise |
|---------|------|------|----------|-----------|
| **Seats** | 1 | 5 | 15 | Unlimited |
| **Concurrent MCP sessions** | 1 | 5 | 15 | Unlimited |
| **Additional seats** | — | $15/mo each | $12/mo each | Included |
| **Support** | Community | Email (48h) | Email (24h) | Priority (4h SLA) |
| **Offline license** | 30-day cache | 30-day cache | 30-day cache | 365-day JWT |
| **Encrypted payload bundles** | — | — | — | Included |
| **SSO (SAML/OIDC)** | — | — | — | Included |
| **Invoice billing (NET-30)** | — | — | — | Included |
| **Custom payload sets** | — | — | — | Included |

---

## Community Edition (Free, Forever)

The open-source CLI remains fully functional without a license.

| Component | CE (Free) | Pro (Paid) |
|-----------|-----------|------------|
| All 33 verification probes | Full | Full |
| Payload database | ~1,206 (frozen at release) | 1,206+ (updated monthly via API) |
| Evidence system | Full | Full |
| CVSS calculator | Full | Full |
| Compliance mapping | Full | Full |
| 13 framework checklists | Static | Updated |
| 13 exploit templates | Static | Updated |
| Sink pattern database | Full | Full |
| OpenAPI parser | Full | Full |
| **MCP server mode** | — | Included |
| **AI agent integration** | Manual CLI | Claude Code, Cursor, any MCP agent |
| **Payload updates** | Wait for GitHub release | Monthly via server API |
| **Support** | Community | Email / Priority |

---

## All 55 MCP Tools (Unlimited)

With license-based pricing, every tool is unlimited. No credit tiers.

### Free Tools (available without license in CE CLI mode)

| Tool | Description |
|------|-------------|
| `evidence_log` | Log evidence entry to JSONL |
| `evidence_query` | Query and filter evidence entries |
| `evidence_verify` | Verify evidence hash chain integrity |
| `cvss` | Calculate CVSS v3.1 / v4.0 score |
| `compliance` | Map vulnerability to OWASP/PCI-DSS/SOC2/ISO 27001 |
| `checklist` | Security checklist (13 frameworks) |
| `sinks` | Sink pattern database (22 categories) |
| `openapi` | Parse OpenAPI spec, extract endpoints |

### Pro Tools (require valid license via MCP mode)

#### Reference (3 tools)

| Tool | Description |
|------|-------------|
| `payloads` | Query server-side payload database (1,206+ payloads) |
| `template_list` | List exploit templates |
| `template_get` | Get specific exploit template (Python 3 POC) |

#### Scanning (1 tool)

| Tool | Description |
|------|-------------|
| `scan` | Static code sink scanner |

#### Standard Verification (26 tools)

| Tool | Typical Rounds |
|------|---------------|
| `verify_sqli` | 3-6 rounds (baseline + payload) |
| `verify_xss` | 1 probe per context |
| `verify_idor` | 1 probe (two-user comparison) |
| `verify_ssrf` | baseline + probe |
| `verify_auth` | baseline + modified probe |
| `verify_authz` | 2 probes (role comparison) |
| `verify_cmdi` | 3-6 rounds (time-based) |
| `verify_lfi` | baseline + probe |
| `verify_ssti` | multi-engine probes |
| `verify_xxe` | 1 probe |
| `verify_deserialization` | 3-6 rounds (time-based) |
| `verify_nosql` | varies by technique |
| `verify_jwt` | token manipulation probes |
| `verify_protopollution` | 3-step probe |
| `verify_graphql` | varies by technique |
| `verify_redirect` | 1 probe |
| `verify_csvinjection` | submit + export |
| `verify_headerinjection` | baseline + probe |
| `verify_propertyauthz` | 2 probes + comparison |
| `verify_ldap` | varies by technique |
| `verify_xpath` | varies by technique |
| `verify_fileupload` | upload + verify |
| `verify_massassignment` | 3-step (GET/mutate/GET) |
| `verify_cors` | 4 origin probes |
| `verify_csrf` | 3 probes + cookie check |
| `verify_clickjacking` | single-request header check |

#### Heavy Verification (7 tools)

| Tool | Why Heavier |
|------|-------------|
| `verify_rls` | 3 cross-tenant probes |
| `verify_race` | N concurrent requests (default 10) |
| `verify_smuggling` | Raw TCP, multiple rounds |
| `verify_cachepoisoning` | 3-step (baseline/inject/verify) |
| `verify_websocket` | WebSocket upgrade + frames |
| `verify_grpc` | TCP probing |
| `verify_ratelimit` | N sequential requests (default 100) |

#### Cloud Security (8 tools)

| Tool | Description |
|------|-------------|
| `cloud_storage` | S3/GCS/Blob security audit |
| `cloud_iam` | IAM role/permission analysis |
| `cloud_network` | Security group/firewall audit |
| `cloud_compute` | Lambda/Functions config audit |
| `cloud_logging` | CloudTrail/GCP sinks audit |
| `cloud_secrets` | Secrets Manager/Key Vault audit |
| `cloud_parse_prowler` | Parse Prowler output |
| `cloud_parse_trivy` | Parse Trivy output |

#### Callback (1 tool)

| Tool | Description |
|------|-------------|
| `callback` | OOB callback HTTP listener |

#### Admin (1 tool)

| Tool | Description |
|------|-------------|
| `license_status` | Show license info, plan, expiry |

---

## Assessment Capacity Per Plan

### Assessments Are Unlimited

With license-based pricing, there is no credit budget per assessment. Run as many probes as you want. The constraint is seats/sessions, not usage.

### Typical Assessment Workload (for reference)

A full 9-session web application assessment typically involves:

| Session | Phase | Approximate Tool Calls |
|---------|-------|----------------------|
| 01 | Recon | ~7 (openapi + payloads + scan) |
| 02 | Injection | ~18 (8 verify + 10 payloads) |
| 03 | Auth | ~10 (5 verify + 5 payloads) |
| 04 | AuthZ | ~10 (6 verify + 4 payloads) |
| 05 | XSS | ~13 (5 verify + 8 payloads) |
| 06 | SSRF | ~9 (4 verify + 4 payloads + 1 callback) |
| 07 | Cloud | ~8 (6 cloud + 2 parse) |
| 08 | API | ~11 (6 verify + 5 payloads) |
| 09 | Report | evidence queries only |
| **Total** | | **~86 tool calls** |

All unlimited on any plan.

---

## Cost Comparison

### vs Burp Suite Pro ($449/yr)

| | Burp Suite | Ensphere Solo | Ensphere Team |
|--|-----------|---------------|---------------|
| **Annual cost** | $449/yr | $290/yr | $990/yr |
| **Seats** | 1 | 1 | 5 |
| **Per-seat cost** | $449 | $290 | $198 |
| **AI integration** | None | Claude Code, Cursor, etc. | Claude Code, Cursor, etc. |
| **Updated payloads** | Scanner updates | Monthly payload feed | Monthly payload feed |
| **Evidence chain** | Manual | SHA-256 hash chain | SHA-256 hash chain |

### vs Caido ($99/yr)

| | Caido | Ensphere Solo |
|--|-------|---------------|
| **Annual cost** | $99/yr | $290/yr |
| **AI-driven testing** | No | Yes (MCP) |
| **Payload intelligence** | No | Monthly updates |
| **Methodology** | Manual | 9-session skill-guided |

### vs Nuclei (Free)

| | Nuclei | Ensphere CE | Ensphere Pro |
|--|--------|-------------|-------------|
| **Cost** | Free | Free | $29+/mo |
| **Approach** | Template scanning | Measurement probes | Measurement + payload feed |
| **AI reasoning** | No (matched/not) | Manual CLI | AI interprets measurements |
| **Evidence** | No chain | SHA-256 chain | SHA-256 chain |
| **Payload updates** | Community templates | Frozen at release | Monthly server-side |

---

## Free Trial

- **14 days**, all features, Solo plan equivalent
- No credit card required
- Full MCP access + payload API
- After 14 days: converts to paid or falls back to CE (all local data preserved)
