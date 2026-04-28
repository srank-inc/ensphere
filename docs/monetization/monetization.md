# Ensphere Monetization Design

License-based monetization with server-side payload intelligence and open-core distribution.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Business Model: Open Core + Payload-as-a-Service](#2-business-model-open-core--payload-as-a-service)
3. [MCP Server Mode](#3-mcp-server-mode)
4. [Tool Registry](#4-tool-registry)
5. [License Validation](#5-license-validation)
6. [Server-Side Payload API](#6-server-side-payload-api)
7. [Licensing API](#7-licensing-api)
8. [Offline / Air-Gapped Mode](#8-offline--air-gapped-mode)
9. [Security & IP Protection](#9-security--ip-protection)
10. [Edge Cases](#10-edge-cases)
11. [What Stays Free](#11-what-stays-free)
12. [Pricing Tiers](#12-pricing-tiers)
13. [Migration Path](#13-migration-path)
14. [Database Schema](#14-database-schema)
15. [Stripe Integration](#15-stripe-integration)
16. [User Dashboard](#16-user-dashboard)
17. [Marketing / Positioning](#17-marketing--positioning)
18. [Implementation Plan](#18-implementation-plan)

---

## 1. Architecture Overview

### Current Architecture

```
Claude Code / Cursor / any AI agent
    |
    |--> ensphere (CLI binary, local execution, open source)
    |       |-- ensphere verify sqli --url ... --in-scope ...
    |       |-- ensphere payloads sqli --db postgres   ← payloads embedded in binary
    |       |-- ensphere evidence log ...
    |       \-- ... (56 Cobra commands)
    |
    |--> skills/ (markdown methodology files)
```

### Monetized Architecture

```
Claude Code / Cursor / any MCP-compatible agent
    |
    |--> ensphere --mcp (stdio MCP server, closed-source)
    |       |
    |       |-- [MCP JSON-RPC over stdin/stdout]
    |       |-- License validation on startup (one check, not per-call)
    |       |-- Unlimited tool calls during valid license period
    |       |
    |       |-- HTTPS --> api.ensphere.dev
    |       |               |-- /v1/payloads (server-side payload database)
    |       |               |-- /v1/license/validate (license check)
    |       |               |-- /v1/updates (new probes, techniques)
    |       |               \-- PostgreSQL (users, licenses, payload versions)
    |       |
    |       \-- Offline: signed license JWT + cached payload bundle
    |
    |--> ensphere (CLI mode, open source, still works with embedded payloads)
    |--> skills/ (markdown, always free)
```

### Key Design Decisions

1. **No per-call billing.** Ensphere has zero marginal cost per tool call (probes run locally). Per-call credits would be artificial scarcity. License model is more honest.

2. **Payloads move server-side.** The 1,206 curated payloads are the core IP. In the open-source CLI they're embedded in SQLite; in Pro they're fetched from an API with monthly updates. Can't reverse-engineer what's not in the binary.

3. **Open core.** CLI stays open source (Apache 2.0). MCP server mode is closed-source, never published. New code, not hiding existing code.

4. **License = unlock, not meter.** One validation on MCP server startup. All tools are unlimited for the license period. No credit anxiety, no mid-assessment interruptions.

### New Go Packages

```
cli/internal/mcp/              # MCP server (CLOSED SOURCE, never published)
    server.go                  # MCP server setup, stdio transport
    tools.go                   # Tool registry (maps commands to MCP tools)
    handlers.go                # Tool handler implementations
    license.go                 # License validation middleware

cli/internal/payloadapi/       # Server-side payload client (CLOSED SOURCE)
    client.go                  # HTTP client for payload API
    cache.go                   # Local payload cache (offline support)
    model.go                   # Types

cli/cmd/
    mcp.go                     # --mcp flag handler (CLOSED SOURCE)
    auth.go                    # ensphere auth login/status/logout
```

---

## 2. Business Model: Open Core + Payload-as-a-Service

### Two Products, One Binary

| | Community Edition (CE) | Pro |
|--|------------------------|-----|
| **Source** | Open source (Apache 2.0) | Closed source, binary only |
| **Distribution** | GitHub, `go install` | Download from ensphere.dev, `brew` |
| **Mode** | CLI (`ensphere verify ...`) | MCP (`ensphere --mcp`) |
| **Payloads** | Embedded SQLite (static, ships with release) | Server-side API (updated monthly) |
| **Probes** | All 33 probes | All 33 probes |
| **Evidence** | Full | Full |
| **Templates** | 13 templates (static) | 13+ templates (updated) |
| **Checklists** | 13 checklists (static) | 13+ checklists (updated) |
| **AI integration** | Manual CLI usage | Claude Code / Cursor / any MCP agent |
| **Updates** | When you pull from GitHub | Automatic via payload API |
| **Support** | Community (GitHub Issues) | Email + priority |
| **Price** | Free | $29-499/mo |

### The Value Split

**CE gives you the engine** — probes, evidence chain, CVSS, compliance mapping. This is the community trust layer. It works, it's auditable, it's free.

**Pro gives you the ammunition and automation** — continuously updated payloads, MCP integration for AI-driven testing, new technique feeds, and support. This is the professional layer.

### Why This Works

1. **CE users become Pro users.** Try the CLI for free → love it → pay for MCP mode + payload updates.
2. **CE is uncrackable.** You can't pirate "free." Open source eliminates the piracy problem entirely for the base product.
3. **Pro's value is server-side.** Payload API can't be cracked. Monthly updates create genuine recurring value. The MCP binary can be cracked, but without the payload API it's a gun without bullets.
4. **Adobe's lesson applied.** Don't protect the binary (losing battle). Move the value to the server (winning architecture).

---

## 3. MCP Server Mode

### Entry Point

```go
// cli/cmd/root.go
rootCmd.PersistentFlags().BoolVar(&mcpMode, "mcp", false, "Run as MCP server (stdio)")

if mcpMode {
    mcp_server.Run() // blocks on stdio
    return
}
```

### MCP Server Setup

```go
// cli/internal/mcp/server.go (CLOSED SOURCE)
func Run() {
    // 1. Resolve license
    license, err := validateLicense()
    if err != nil {
        log.Fatalf("License error: %v", err)
    }

    // 2. Initialize payload API client
    payloadClient := payloadapi.NewClient(license.APIKey)

    // 3. Create MCP server
    server := mcp.NewServer(&mcp.Implementation{
        Name:    "ensphere",
        Version: version,
    }, nil)

    // 4. Register all tools (unlimited, no per-call billing)
    registerAllTools(server, payloadClient)

    // 5. Block on stdio
    server.Run(context.Background(), &mcp.StdioTransport{})
}
```

### License Resolution Order

1. `ENSPHERE_LICENSE_KEY` environment variable
2. `~/.config/ensphere/credentials.json`
3. `--license-key` CLI flag
4. If none found: MCP server exits with error and link to ensphere.dev/pricing

### MCP Server Configuration in Claude Code

```json
{
  "mcpServers": {
    "ensphere": {
      "command": "ensphere",
      "args": ["--mcp"],
      "env": {
        "ENSPHERE_LICENSE_KEY": "ens_..."
      }
    }
  }
}
```

### Lifecycle

```
Agent session starts
  → Agent spawns `ensphere --mcp` as subprocess
  → License validated once on startup (HTTPS → api.ensphere.dev)
  → Payload database fetched/refreshed from API (if stale)
  → MCP server listens on stdin/stdout
  → ALL tools available, UNLIMITED calls

Agent session ends
  → stdin closes → MCP server shuts down
  → No usage reporting, no meter events
```

---

## 4. Tool Registry

### All 55 MCP Tools — Unlimited

With license-based pricing, there are no credit tiers. All tools are available equally.

| Category | Tools | Count |
|----------|-------|-------|
| **Evidence** | `evidence_log`, `evidence_query`, `evidence_verify` | 3 |
| **Reference** | `cvss`, `compliance`, `checklist`, `sinks` | 4 |
| **Payloads** | `payloads` (server-side in Pro, embedded in CE) | 1 |
| **Scanning** | `openapi`, `scan` | 2 |
| **Templates** | `template_list`, `template_get` | 2 |
| **Verification** | `verify_sqli`, `verify_xss`, ... (33 probes) | 33 |
| **Cloud** | `cloud_storage`, `cloud_iam`, ... (6 scans + 2 parsers) | 8 |
| **Callback** | `callback` | 1 |
| **Admin** | `license_status` | 1 |
| **Total** | | **55** |

### Tool Registration (No Billing Middleware)

```go
func registerAllTools(server *mcp.Server, payloadClient *payloadapi.Client) {
    // All tools registered directly — no billing wrapper
    registerTool(server, "evidence_log", evidenceLogHandler)
    registerTool(server, "payloads", makePayloadsHandler(payloadClient)) // uses server-side API
    registerTool(server, "verify_sqli", verifySQLiHandler)
    // ... all 55 tools
    registerTool(server, "license_status", licenseStatusHandler)
}
```

### The `payloads` Tool: CE vs Pro

| | CE (CLI mode) | Pro (MCP mode) |
|--|---------------|----------------|
| Source | Embedded SQLite (`payloads.sqlite`) | Server API (`api.ensphere.dev/v1/payloads`) |
| Payload count | ~1,206 (frozen at release) | 1,206+ (growing monthly) |
| Updates | Manual (`go install` or GitHub release) | Automatic (API always returns latest) |
| Offline | Always works | Works with cached bundle (see §8) |
| New CVEs | Wait for next release | Available within days |

---

## 5. License Validation

### License Key Format

```
ens_pro_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
ens_team_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
ens_ent_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

- Prefix: `ens_` (identifies Ensphere)
- Plan: `pro_`, `team_`, `ent_` (plan tier)
- Body: 32 random hex characters (128-bit entropy)

### Validation Flow (One-Time on Startup)

```
MCP server starts
    │
    ├─ Read license key (env → config → flag)
    │
    ├─ POST api.ensphere.dev/v1/license/validate
    │   │
    │   ├─ 200 OK → license valid
    │   │   {
    │   │     "valid": true,
    │   │     "plan": "pro",
    │   │     "expires_at": "2027-03-01T00:00:00Z",
    │   │     "payload_version": "2026.03.1",
    │   │     "features": ["mcp", "payload_api", "priority_support"]
    │   │   }
    │   │   → Cache response locally (~/.config/ensphere/license_cache.json)
    │   │   → Start MCP server with full access
    │   │
    │   ├─ 401 → invalid key → exit with error
    │   │
    │   ├─ 402 → expired → exit with renewal link
    │   │
    │   └─ Network error → check local cache
    │       │
    │       ├─ Cache exists + not expired → start with cached license
    │       │   (allows offline startup for up to 30 days)
    │       │
    │       └─ No cache or expired → exit with error
    │
    └─ MCP server running (all tools unlimited)
```

### License Cache

Location: `~/.config/ensphere/license_cache.json`

```json
{
  "valid": true,
  "plan": "pro",
  "expires_at": "2027-03-01T00:00:00Z",
  "payload_version": "2026.03.1",
  "cached_at": "2026-03-03T10:00:00Z",
  "offline_grace_days": 30
}
```

The cache allows MCP server startup without network for up to 30 days after last successful validation. After 30 days offline, re-validation is required.

### No Per-Call Checks

Once the MCP server starts with a valid license, there are **zero billing checks during the session**. Every tool call executes immediately. No latency, no API dependency, no grace mode complexity.

---

## 6. Server-Side Payload API

This is the core monetization mechanism. The payload database moves from embedded SQLite (crackable) to a server API (uncrackable).

### Endpoint

`GET api.ensphere.dev/v1/payloads`

### Query Interface

```json
// Request
GET /v1/payloads?vuln_type=sqli&db_engine=postgres&technique=blind_time&max_risk=3

// Response
{
  "version": "2026.03.1",
  "count": 34,
  "payloads": [
    {
      "id": "sqli-pg-bt-001",
      "payload": "' AND (SELECT pg_sleep({SLEEP}))--",
      "technique": "blind_time",
      "evidence_type": "timing_delta",
      "risk": 2,
      "placeholders": ["SLEEP"],
      "notes": "Standard PostgreSQL time-based blind",
      "tags": ["postgres", "blind", "time"],
      "added": "2025-08-15",
      "source": "original"
    }
  ]
}
```

### Payload Updates

Monthly payload releases:
- New payloads for emerging CVEs
- Refined payloads based on false positive/negative data
- New technique variants
- New vulnerability types

Versioned: `YYYY.MM.N` (e.g., `2026.03.1`). Clients always get the latest version.

### Local Payload Cache

For offline operation and performance, payloads are cached locally:

Location: `~/.config/ensphere/payload_cache.sqlite`

```go
// On MCP server startup:
// 1. Check local cache version
// 2. Compare with server version (from license validation response)
// 3. If stale: fetch full bundle from GET /v1/payloads/bundle
// 4. If fresh: use local cache
// 5. If offline: use whatever cache exists (may be stale)
```

### Payload Bundle Endpoint

`GET api.ensphere.dev/v1/payloads/bundle`

Returns the complete payload database as a SQLite file download (~2MB). Refreshed on startup if version mismatch. This is more efficient than querying individual payloads.

### What This Achieves

1. **IP protection**: Payloads aren't in the distributed binary. Reverse engineering the binary yields probe logic but no ammunition.
2. **Recurring value**: Monthly updates create genuine reason to maintain subscription. Not artificial scarcity — real new content.
3. **Graceful offline**: Cache allows air-gapped operation with last-synced payloads. Not as fresh as online, but functional.
4. **CE parity**: CE still ships with embedded SQLite (frozen at release version). CE users get payloads, just not the latest.

---

## 7. Licensing API

Full specification in [billing-api-spec.md](billing-api-spec.md).

### Base URL

`https://api.ensphere.dev/v1`

### Endpoints Summary

| Method | Path | Purpose |
|--------|------|---------|
| `POST /v1/license/validate` | Validate license key on MCP startup |
| `GET /v1/payloads` | Query payloads (server-side database) |
| `GET /v1/payloads/bundle` | Download full payload database (SQLite) |
| `GET /v1/updates/check` | Check for new probe/template/checklist versions |
| `GET /v1/updates/download` | Download update bundle |
| `POST /v1/auth/login` | OAuth login, returns license key |
| `GET /v1/account` | Account info, plan, expiry |

### Authentication

All requests use the license key as Bearer token:

```
Authorization: Bearer ens_pro_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Rate Limits

| Endpoint | Limit | Notes |
|----------|-------|-------|
| `POST /v1/license/validate` | 10/min | Per key, called once per session |
| `GET /v1/payloads` | 120/min | Per key, called per tool invocation |
| `GET /v1/payloads/bundle` | 5/day | Per key, full DB download |
| `GET /v1/updates/*` | 10/min | Per key |

---

## 8. Offline / Air-Gapped Mode

### How Offline Works

License validation caches locally for 30 days. Payload database caches as SQLite file. Both work without network after initial sync.

```
Online startup (normal):
  1. Validate license → cache result
  2. Check payload version → refresh if stale
  3. Start MCP server with fresh data

Offline startup (within 30 days of last online):
  1. Read license_cache.json → check offline_grace_days
  2. Read payload_cache.sqlite → use cached payloads
  3. Start MCP server with cached data
  4. Warning: "Running offline. Payloads may be stale (last sync: 2026-02-15)."

Offline startup (past 30 days):
  1. Read license_cache.json → expired
  2. Error: "License requires re-validation. Connect to internet."
  3. MCP server exits
```

### Enterprise Offline License

For classified networks where 30-day sync is impossible, Enterprise plan includes extended offline licenses:

- Ed25519-signed JWT with 365-day validity
- Payload bundle shipped as encrypted file (AES-256, key in license JWT)
- Manual refresh: download updated bundle on connected machine, transfer via USB
- No sync requirement — license is self-validating via embedded public key

```json
// Enterprise offline license JWT payload
{
  "iss": "api.ensphere.dev",
  "sub": "team_xyz",
  "aud": "ensphere-cli",
  "exp": 1741003260,
  "jti": "lic_unique_id",
  "plan": "enterprise",
  "team_name": "Acme Security",
  "max_seats": 20,
  "offline": true,
  "payload_bundle_key": "base64-encoded-AES-key"
}
```

---

## 9. Security & IP Protection

### Architecture-Level Protection (What Actually Works)

| Asset | Where it lives | Protection |
|-------|---------------|------------|
| **Payload database** | Server API (api.ensphere.dev) | Uncrackable — not in the binary |
| **Payload updates** | Server API | Uncrackable — monthly new content |
| **MCP server code** | Closed-source binary | Obfuscated (`garble`), never published |
| **Probe logic** | Open source (CE) / binary (Pro) | Not the primary IP — the logic is public |
| **Evidence system** | Open source (CE) | Intentionally free |
| **License validation** | Server-side check | Can be patched out, but then no payloads |

### Why Patching Out License Checks Doesn't Help

Even if someone cracks the Pro binary and removes the license validation:
1. The `payloads` tool calls `api.ensphere.dev/v1/payloads` — needs valid license key
2. Without payloads, the verify probes have no ammunition
3. They could use CE's embedded payloads... but those are already free in CE
4. No updates — stuck on whatever payload cache existed at crack time

**The license check protects access to the payload API. The payload API is the value. The payload API is server-side.**

### Data Sent to Ensphere Servers

**SENT** (on startup + payload queries):
- License key (authentication)
- Payload query parameters (`vuln_type`, `technique`, `db_engine`)
- Client version (for update checks)

**NEVER SENT**:
- Target URL, hostname, or IP
- Probe results or measurements
- Evidence data
- Target credentials or tokens
- HTTP request/response content from probes
- `--in-scope` patterns
- Source code or scan results
- Cloud account identifiers

Enforced architecturally: the payload API client only sends query filters. Probe execution is entirely local.

### Binary Distribution

Pro binary built with:
- `garble build` — obfuscates Go symbols, types, and string literals
- `-ldflags="-s -w"` — strips debug info
- Code signing (Apple notarization for macOS, Authenticode for Windows)
- **No embedded payload SQLite** — payload data comes from API

### Anti-Abuse

- License key tied to Stripe customer. Revoke customer = key dies.
- Max 3 concurrent MCP sessions per license (tracked via startup validation).
- License key rotation: new key invalidates old after 72-hour grace.
- Enterprise: max_seats enforced via session counting at validation time.

---

## 10. Edge Cases

### 10.1 Network down on MCP server startup

Check local license cache. If valid (within 30-day offline grace): start with cached payloads. If expired: exit with error asking user to reconnect.

### 10.2 Payload API down mid-session

MCP server is already running (license validated at startup). Payload queries fall back to local cache. Probes that don't need payloads (e.g., `verify_clickjacking`) work normally. Warning logged: "Payload API unreachable, using cached payloads."

### 10.3 License expires mid-session

The MCP server does NOT check license during a session. If the license expires while the server is running, the current session continues normally. Next startup will fail with renewal link.

### 10.4 User shares license key

Max 3 concurrent sessions enforced at validation time. 4th session attempt returns error. If systematic abuse detected (many IPs, many geolocations), key is flagged for review.

### 10.5 CE user wants to try Pro

`ensphere auth login` → browser OAuth → returns license key → writes to `~/.config/ensphere/credentials.json`. Next `ensphere --mcp` startup uses the license. 14-day free trial, no credit card.

### 10.6 Pro user's license expires, falls back to CE

MCP server won't start without valid license. User can still use all CLI commands (CE mode) with embedded payloads. No data loss — evidence, reports, session files are all local.

### 10.7 Enterprise offline user needs payload update

Download payload bundle on connected machine: `ensphere payloads download-bundle --out ./payloads-2026.03.enc`. Transfer to air-gapped machine via USB. Import: `ensphere payloads import-bundle ./payloads-2026.03.enc`. Bundle is AES-256 encrypted, key is in the offline license JWT.

### 10.8 Upgrade/downgrade mid-billing cycle

Upgrade: immediate. Pro-rata charges via Stripe. Downgrade: takes effect at next billing cycle.

### 10.9 Annual vs monthly billing

Annual = pay 10 months, get 12. Locked-in rate. Monthly cancellation anytime.

---

## 11. What Stays Free

### Community Edition (Apache 2.0, forever free)

| Component | Notes |
|-----------|-------|
| All 33 verification probes | Full probe logic, open source |
| Embedded payload database | ~1,206 payloads, frozen at release version |
| Evidence system (log, query, verify) | Full hash chain integrity |
| CVSS v3.1 / v4.0 calculator | Public formula |
| Compliance mapping (OWASP, PCI-DSS, SOC 2, ISO 27001) | Reference data |
| 13 framework checklists | Community knowledge |
| Sink pattern database (22 categories) | Reference data |
| OpenAPI parser | Spec parsing |
| 13 exploit templates | Python 3 POCs |
| Skills/methodology files (9 sessions) | Markdown, freely distributed |
| CLI mode (all 56 commands) | Full functionality |

### What's Pro Only

| Component | Notes |
|-----------|-------|
| MCP server mode (`--mcp`) | AI agent integration |
| Server-side payload API | Monthly updates, new CVEs |
| New payload techniques | Emerging attack patterns |
| Updated templates & checklists | Expanding framework coverage |
| Priority support | Email, SLA |
| Offline enterprise licenses | Extended offline, encrypted bundles |

---

## 12. Pricing Tiers

### Plans

| Plan | Monthly | Annual (per month) | Seats | Target |
|------|---------|-------------------|-------|--------|
| **Solo** | $29/mo | $24/mo | 1 | Individual pentester, bug bounty |
| **Team** | $99/mo | $83/mo | 5 | Small consultancy |
| **Business** | $249/mo | $208/mo | 15 | Mid-size security firm |
| **Enterprise** | Custom | Custom | Unlimited | MSSP, government, classified |

### All Plans Include

- Unlimited MCP tool calls (no per-call billing)
- Full payload API access (latest payloads, monthly updates)
- All 55 MCP tools
- 30-day offline grace period
- Auto-updates (probes, templates, checklists)

### Plan Differences

| Feature | Solo | Team | Business | Enterprise |
|---------|------|------|----------|-----------|
| Seats | 1 | 5 | 15 | Unlimited |
| Concurrent MCP sessions | 1 | 5 | 15 | Unlimited |
| Support | Community | Email (48h) | Email (24h) | Priority (4h SLA) |
| Offline license | 30-day cache | 30-day cache | 30-day cache | 365-day JWT |
| Encrypted payload bundles | — | — | — | Included |
| SSO (SAML/OIDC) | — | — | — | Included |
| Invoice billing (NET-30) | — | — | — | Included |
| Custom payload sets | — | — | — | Included |

### Free Trial

- 14-day free trial of Solo plan
- No credit card required
- Full MCP access + payload API
- Converts to paid or falls back to CE

### Additional Seats

- Team: $15/mo per additional seat (beyond 5)
- Business: $12/mo per additional seat (beyond 15)

---

## 13. Migration Path

### Phase 1: Ship MCP Mode (Month 1)

- Build closed-source MCP server (`cli/internal/mcp/`)
- Build payload API (`api.ensphere.dev`)
- License validation on startup
- 14-day free trial for all signups
- CE CLI remains unchanged, open source
- Announce: "Ensphere Pro — AI-native penetration testing"

### Phase 2: Launch Paid Plans (Month 2)

- Stripe integration
- Dashboard at ensphere.dev/dashboard
- Solo + Team plans available
- Monthly payload update cycle begins

### Phase 3: Enterprise (Month 3-4)

- Offline license generation (Ed25519 JWT)
- Encrypted payload bundles
- SSO integration
- Business + Enterprise plans available
- First enterprise contracts

### Phase 4: Growth (Month 4+)

- Expand payload database (target: 2,000+ payloads by month 6)
- Add new probe types based on emerging techniques
- Integration guides for Cursor, Zed, Windsurf, other MCP agents
- Certification program ("Ensphere Certified Assessment" badge for reports)

---

## 14. Database Schema

PostgreSQL for the licensing/billing backend at `api.ensphere.dev`.

```sql
-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    stripe_customer_id TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Teams
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    owner_id UUID NOT NULL REFERENCES users(id),
    stripe_customer_id TEXT UNIQUE,
    max_seats INTEGER NOT NULL DEFAULT 5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    PRIMARY KEY (team_id, user_id)
);

-- License Keys
CREATE TABLE license_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    plan TEXT NOT NULL CHECK (plan IN ('solo', 'team', 'business', 'enterprise')),
    name TEXT NOT NULL DEFAULT 'Default',
    last_validated_at TIMESTAMPTZ,
    last_ip INET,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_license_keys_prefix ON license_keys(key_prefix) WHERE revoked_at IS NULL;

-- Subscriptions
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    team_id UUID REFERENCES teams(id),
    plan TEXT NOT NULL CHECK (plan IN ('solo', 'team', 'business', 'enterprise')),
    status TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'past_due', 'canceled')),
    stripe_subscription_id TEXT UNIQUE,
    billing_cycle TEXT NOT NULL CHECK (billing_cycle IN ('monthly', 'annual')),
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    trial_ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((user_id IS NOT NULL) != (team_id IS NOT NULL))
);

-- Active Sessions (concurrent session enforcement)
CREATE TABLE active_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key_id UUID NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
    session_id TEXT UNIQUE NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address INET
);

-- Payload Versions
CREATE TABLE payload_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version TEXT UNIQUE NOT NULL,
    payload_count INTEGER NOT NULL,
    bundle_hash TEXT NOT NULL,
    changelog TEXT,
    released_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Offline Licenses (Enterprise)
CREATE TABLE offline_licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES teams(id),
    license_jti TEXT UNIQUE NOT NULL,
    max_seats INTEGER NOT NULL,
    payload_version TEXT NOT NULL REFERENCES payload_versions(version),
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit Log (license validations, for abuse detection)
CREATE TABLE license_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key_id UUID REFERENCES license_keys(id),
    event TEXT NOT NULL CHECK (event IN ('validate', 'payload_fetch', 'bundle_download', 'session_start', 'session_end')),
    ip_address INET,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_key ON license_audit_log(license_key_id, created_at DESC);
```

---

## 15. Stripe Integration

### Stripe Resources

| Stripe Resource | Ensphere Entity |
|----------------|----------------|
| Customer | User or Team |
| Subscription | Plan (solo/team/business) |
| Price | Per-plan monthly/annual price |
| Invoice | Monthly/annual bill |
| Checkout Session | Signup flow |
| Customer Portal | Self-service billing management |

### Prices

| Plan | Monthly Price ID | Annual Price ID |
|------|-----------------|----------------|
| Solo | `price_solo_monthly` ($29) | `price_solo_annual` ($290) |
| Team | `price_team_monthly` ($99) | `price_team_annual` ($990) |
| Business | `price_business_monthly` ($249) | `price_business_annual` ($2,490) |

### Webhook Events

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Create user/team, subscription, generate license key |
| `invoice.paid` | Extend subscription period, update license expiry |
| `invoice.payment_failed` | Set status to `past_due`, email user |
| `customer.subscription.updated` | Update plan, seats, billing cycle |
| `customer.subscription.deleted` | Set status to `canceled`, revoke license after grace period |

### Trial Flow

1. User signs up at ensphere.dev → Stripe Checkout with 14-day trial
2. `checkout.session.completed` → create user, subscription (status: `trialing`), license key
3. Day 14: Stripe charges card → `invoice.paid` → status: `active`
4. If no card / payment fails: `customer.subscription.deleted` → license key revoked → falls back to CE

---

## 16. User Dashboard

### URL

`https://ensphere.dev/dashboard`

### Pages

1. **Overview**: License status, plan, expiry, payload version, active sessions
2. **License Keys**: List, create (up to 3 per seat), revoke. Masked key display.
3. **Billing**: Stripe Customer Portal (plan change, payment method, invoices)
4. **Team** (team/business/enterprise): Members, invites, per-member session history
5. **Downloads**: Pro binary (macOS/Linux/Windows), offline bundles (enterprise)
6. **Changelog**: Monthly payload updates, new probes/templates/checklists

### Tech Stack

Next.js app. Billing management via Stripe Customer Portal (minimal custom UI). Custom pages for license key management and team admin.

---

## 17. Marketing / Positioning

### Competitive Landscape

| Tool | Model | Price | Ensphere Differentiator |
|------|-------|-------|------------------------|
| **Burp Suite Pro** | Annual license | $449/yr | Ensphere: AI-native, MCP integration, no GUI |
| **Nuclei** | Free/OSS templates | Free | Ensphere: measurement-only probes for AI reasoning, evidence chain, payload intelligence feed |
| **OWASP ZAP** | Free/OSS | Free | Ensphere: MCP integration, AI-driven test selection |
| **Caido** | Annual license | $99/yr | Ensphere: autonomous AI testing, structured methodology |
| **Semgrep** | Free/paid | $0-299/mo | Ensphere: runtime verification, not static analysis |

### Value Proposition

1. **Plug security testing into any AI agent.** One MCP server, works with Claude Code, Cursor, Codex, any MCP-compatible tool.
2. **Measurement purity.** Ensphere never classifies. The AI reasons over raw measurements with full context. Fewer false positives.
3. **Continuously updated intelligence.** Monthly payload updates reflecting new CVEs and techniques. Not a static scanner.
4. **Evidence integrity.** Append-only JSONL with SHA-256 hash chain. Compliance-ready audit trail.
5. **Methodology as code.** 9-session pentest methodology in the skills layer. Junior testers execute at senior level.

### Tagline

"The measurement engine for AI-assisted security."

---

## 18. Implementation Plan

### Phase 1: MCP Server + Payload API (Week 1-3)

New closed-source code:
- `cli/internal/mcp/` — MCP server, tool registry, handlers
- `cli/internal/payloadapi/` — Payload API client, cache
- `cli/cmd/mcp.go` — `--mcp` flag
- `cli/cmd/auth.go` — `ensphere auth login/status/logout`

Server:
- `api.ensphere.dev` — License validation + Payload API
- PostgreSQL schema (§14)
- Seed payload database from existing YAML seeds

Dependency: `github.com/modelcontextprotocol/go-sdk`

### Phase 2: Stripe + Dashboard (Week 3-5)

- Stripe products/prices/checkout
- Webhook handler
- Dashboard (Next.js) at `ensphere.dev/dashboard`
- License key generation on checkout completion
- 14-day trial flow

### Phase 3: Offline + Enterprise (Week 5-7)

- Ed25519 offline license generation
- Encrypted payload bundle export
- License cache for 30-day offline grace
- `ensphere payloads download-bundle` / `import-bundle` commands

### Phase 4: Launch (Week 7-8)

- Binary distribution (GitHub Releases for CE, ensphere.dev/download for Pro)
- `brew` tap for macOS
- Documentation: setup guides for Claude Code, Cursor, Codex
- Blog post: "Introducing Ensphere Pro"
- 14-day trial for all signups

### Critical Files to Create/Modify

| File | Change |
|------|--------|
| `cli/cmd/root.go` | Add `--mcp` flag, mode switch |
| `cli/cmd/mcp.go` | NEW — MCP mode entry point |
| `cli/cmd/auth.go` | NEW — login/status/logout |
| `cli/internal/mcp/` | NEW — entire package (closed source) |
| `cli/internal/payloadapi/` | NEW — payload API client (closed source) |
| `cli/go.mod` | Add `modelcontextprotocol/go-sdk` |
| `Makefile` | Add `build-pro` target (garble + no embedded payloads) |
| `README.md` | CE/Pro distinction, pricing link |
