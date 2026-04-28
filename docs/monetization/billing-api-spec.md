# Ensphere Licensing API Specification

Base URL: `https://api.ensphere.dev/v1`

All requests require the license key as Bearer token:

```
Authorization: Bearer ens_pro_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

---

## Endpoints

### POST /v1/license/validate — Validate License

Called once on MCP server startup. Returns license status and current payload version.

**Request:** (empty body, key in Authorization header)

**Response 200 OK:**

```json
{
  "valid": true,
  "plan": "solo",
  "status": "active",
  "expires_at": "2027-03-01T00:00:00Z",
  "max_sessions": 1,
  "active_sessions": 0,
  "payload_version": "2026.03.1",
  "features": ["mcp", "payload_api"],
  "offline_grace_days": 30
}
```

**Response 401 Unauthorized:**

```json
{
  "error": "invalid_license_key",
  "message": "License key is invalid or revoked."
}
```

**Response 402 Payment Required:**

```json
{
  "error": "license_expired",
  "expired_at": "2026-02-28T00:00:00Z",
  "renewal_url": "https://ensphere.dev/dashboard/billing"
}
```

**Response 409 Conflict:**

```json
{
  "error": "max_sessions_exceeded",
  "max_sessions": 1,
  "active_sessions": 1,
  "message": "Maximum concurrent MCP sessions reached. Close other sessions or upgrade plan."
}
```

**Rate limit:** 10/min per key.

---

### GET /v1/payloads — Query Payloads

Server-side payload database. Replaces embedded SQLite for Pro users.

**Query Parameters:**

| Param | Type | Required | Notes |
|-------|------|----------|-------|
| `vuln_type` | string | yes | e.g., `sqli`, `xss`, `ssrf` |
| `technique` | string | no | e.g., `blind_time`, `reflected` |
| `db_engine` | string | no | e.g., `postgres`, `mysql`, `mssql` |
| `runtime` | string | no | e.g., `nodejs`, `python`, `java` |
| `content_type` | string | no | e.g., `json`, `xml`, `form` |
| `surface` | string | no | e.g., `query`, `header`, `body`, `cookie` |
| `encoding` | string | no | e.g., `none`, `url`, `base64`, `unicode` |
| `max_risk` | integer | no | 1-5, default 3 |
| `limit` | integer | no | Max results, default 50, max 200 |

**Response 200 OK:**

```json
{
  "version": "2026.03.1",
  "count": 34,
  "total": 34,
  "payloads": [
    {
      "id": "sqli-pg-bt-001",
      "vuln_type": "sqli",
      "technique": "blind_time",
      "payload": "' AND (SELECT pg_sleep({SLEEP}))--",
      "evidence_type": "timing_delta",
      "risk": 2,
      "placeholders": ["SLEEP"],
      "notes": "Standard PostgreSQL time-based blind",
      "tags": ["postgres", "blind", "time"],
      "source": "original",
      "added": "2025-08-15",
      "updated": "2026-02-10"
    }
  ]
}
```

**Rate limit:** 120/min per key.

---

### GET /v1/payloads/bundle — Download Full Payload Database

Downloads the complete payload database as a SQLite file. For local caching and offline operation.

**Request Headers:**

```
If-None-Match: "sha256:abc123..."
```

**Response 200 OK:**

```
Content-Type: application/x-sqlite3
Content-Disposition: attachment; filename="payloads-2026.03.1.sqlite"
X-Payload-Version: 2026.03.1
X-Payload-Count: 1206
ETag: "sha256:abc123..."
```

Binary SQLite file (~2MB).

**Response 304 Not Modified:**

Returned if `If-None-Match` matches current bundle hash. Client uses cached version.

**Rate limit:** 5/day per key.

---

### GET /v1/payloads/bundle/encrypted — Encrypted Bundle (Enterprise)

For air-gapped environments. AES-256-GCM encrypted, key embedded in offline license JWT.

**Response 200 OK:**

```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="payloads-2026.03.1.enc"
X-Payload-Version: 2026.03.1
X-Encryption: AES-256-GCM
X-Nonce: base64-encoded-nonce
```

**Rate limit:** 2/day per key.

---

### GET /v1/updates/check — Check for Updates

Check if new probes, templates, or checklists are available.

**Response 200 OK:**

```json
{
  "payload_version": {
    "current": "2026.03.1",
    "latest": "2026.03.2",
    "update_available": true,
    "changelog": "Added 15 new SQLi payloads for MySQL 9.x"
  },
  "probe_version": {
    "current": "1.4.0",
    "latest": "1.4.0",
    "update_available": false
  },
  "template_version": {
    "current": "1.2.0",
    "latest": "1.3.0",
    "update_available": true,
    "changelog": "New template: graphql-introspection-exploit"
  },
  "checklist_version": {
    "current": "1.1.0",
    "latest": "1.1.0",
    "update_available": false
  }
}
```

**Rate limit:** 10/min per key.

---

### POST /v1/auth/login — OAuth Login

Browser-based flow. Returns license key.

**Step 1:** Client opens browser to:
```
https://ensphere.dev/auth/login?callback=http://localhost:{PORT}
```

**Step 2:** User authenticates (email magic link or GitHub OAuth).

**Step 3:** Server redirects to callback with auth code.

**Step 4:** Client exchanges code:

```json
// Request
{
  "auth_code": "abc123",
  "callback_url": "http://localhost:{PORT}"
}

// Response
{
  "license_key": "ens_pro_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "plan": "solo",
  "expires_at": "2027-03-01T00:00:00Z"
}
```

Client saves to `~/.config/ensphere/credentials.json`.

---

### GET /v1/account — Account Info

**Response 200 OK:**

```json
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "name": "Jane Doe"
  },
  "team": {
    "id": "team_xyz",
    "name": "Acme Security",
    "member_count": 3,
    "max_seats": 5
  },
  "subscription": {
    "plan": "team",
    "status": "active",
    "billing_cycle": "monthly",
    "current_period_end": "2026-04-01T00:00:00Z",
    "trial_ends_at": null
  },
  "license_keys": [
    {
      "id": "lk_abc",
      "name": "MacBook Pro",
      "key_prefix": "ens_team_a1b2c3d4",
      "last_validated_at": "2026-03-03T10:00:00Z",
      "created_at": "2026-02-01T00:00:00Z"
    }
  ]
}
```

**Rate limit:** 30/min per key.

---

### POST /v1/session/heartbeat — Session Heartbeat

MCP server sends every 60 seconds to maintain session count.

**Request:**

```json
{
  "session_id": "sess_uuid"
}
```

**Response 200 OK:**

```json
{
  "active": true
}
```

**Response 409 Conflict (session replaced):**

```json
{
  "error": "session_terminated",
  "message": "Session replaced by a newer connection."
}
```

On 409: MCP server logs a warning but continues operating (don't kill an active assessment).

**Rate limit:** 120/min per key.

---

## Error Response Format

```json
{
  "error": "error_code",
  "message": "Human-readable description"
}
```

### Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `invalid_license_key` | 401 | Key is invalid, revoked, or malformed |
| `license_expired` | 402 | Subscription expired |
| `max_sessions_exceeded` | 409 | Too many concurrent MCP sessions |
| `session_terminated` | 409 | Session replaced by newer connection |
| `rate_limited` | 429 | Too many requests |
| `invalid_vuln_type` | 400 | Unknown vulnerability type |
| `server_error` | 500 | Internal error |

---

## Rate Limit Headers

All responses include:

```
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 115
X-RateLimit-Reset: 1709467260
```

When rate limited:

```
HTTP 429
Retry-After: 12
```

---

## Webhook Events (Stripe → Ensphere API)

| Event | Action |
|-------|--------|
| `checkout.session.completed` | Create user, subscription, generate license key |
| `invoice.paid` | Extend subscription period + license key expiry |
| `invoice.payment_failed` | Set status `past_due`, email user. 3 failures → `canceled` |
| `customer.subscription.updated` | Update plan, seats, billing cycle |
| `customer.subscription.deleted` | Set `canceled`, keys valid until period end then revoked |

---

## Key Storage

**Server-side:** SHA-256 hashed. First 16 characters as plaintext prefix for lookup.

```sql
-- 1. Extract prefix: "ens_pro_a1b2c3d4"
-- 2. SELECT FROM license_keys WHERE key_prefix = $1 AND revoked_at IS NULL
-- 3. Compare SHA256(full_key) with key_hash
```

**Client-side:** `~/.config/ensphere/credentials.json`

```json
{
  "license_key": "ens_pro_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "api_url": "https://api.ensphere.dev"
}
```

Or: `ENSPHERE_LICENSE_KEY` environment variable (takes precedence).
