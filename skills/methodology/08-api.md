# Session 08: API Security

Assess API-specific vulnerabilities: rate limiting, property-level authorization, mass assignment, pagination abuse, API documentation exposure, and webhook security.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Rate limit measurement | Tier 1 | `ensphere verify ratelimit` |
| Property-level authz | Tier 1 | `ensphere verify propertyauthz` |
| Mass assignment | Tier 1 | `ensphere verify massassignment` |
| Authorization bypass | Tier 1 | `ensphere verify authz` |
| IDOR/BOLA | Tier 1 | `ensphere verify idor` |
| CORS testing | Tier 1 | `ensphere verify cors` |
| OpenAPI spec parsing | Tier 1 | `ensphere openapi` |
| Payload database | Tier 1 | `ensphere payloads authz` |
| Code scanning | Tier 1 | `ensphere scan` (WHITE_BOX only) |
| Browser interaction | Tier 3 | Playwright MCP (API docs, Swagger UI) |

## Prerequisites

Before starting, read:
- `ensphere-pentest/01-recon/report.md` — API endpoints discovered
- `ensphere-pentest/progress.md` — Technology Profile (framework, auth mechanism)
- `ensphere-pentest/config.md` — credentials and scope

## Phase A: Code Analysis (WHITE_BOX)

### Step 1: API Documentation Exposure

Search for exposed API documentation:

```bash
# Search code for API documentation route definitions
grep -rn "swagger\|openapi\|/api-docs\|/graphql" ./src
```

Manually check code for:
- Swagger/OpenAPI definitions (`swagger.json`, `openapi.yaml`)
- GraphQL playground/voyager enabled in production
- API blueprint files committed to repo
- Debug endpoints (`/debug/`, `/api/docs/`, `/swagger-ui/`)

### Step 2: Mass Assignment Surface

Search for endpoints that bind request body directly to models:

**Django/DRF:** Look for `ModelSerializer` with no `fields` restriction (or `fields = '__all__'`), `serializer.save()` with `**request.data`
**Rails:** Look for `params.permit!` or missing `strong_parameters`
**Express:** Look for `Object.assign(model, req.body)` or `model.update(req.body)`
**Spring:** Look for `@ModelAttribute` without `@InitBinder` field restrictions
**FastAPI:** Look for Pydantic models accepting all fields from request

### Step 3: Rate Limiting Architecture

Search for rate limiting middleware or decorators:
- `@ratelimit`, `@throttle`, `RateLimitMiddleware`
- `express-rate-limit`, `django-ratelimit`, `rack-attack`
- Check if rate limits are applied per-endpoint or globally
- Check if rate limits use proper identifiers (user ID vs IP)

### Step 4: Property-Level Authorization

Search for API responses that might over-expose fields:
- Serializers that include sensitive fields (SSN, salary, internal IDs)
- Different serializer classes for different roles
- Missing field-level permission checks
- GraphQL resolvers that expose all object fields

### Step 5: Pagination Implementation

Search for pagination patterns:
- Offset/limit without maximum page size
- Cursor-based vs offset-based pagination
- Missing pagination on list endpoints
- Page size parameter accepted from user input

### Step 6: Webhook Security

Search for webhook endpoints:
- Signature verification implementation
- URL validation for webhook destinations
- SSRF protections on webhook URLs
- Retry logic and timeout handling

## Phase B: Verification and Session 10 Candidate Selection

Gather API security measurements and identify optional Session 10 candidates.
Do not run destructive API exploitation, broad enumeration, or state-changing
proof beyond authorized test data from Session 08.

### Step 1: API Documentation & Version Discovery

```bash
# Probe common API doc endpoints
for path in /swagger.json /openapi.json /api-docs /swagger-ui/ /redoc /graphql /api/v1/ /api/v2/; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "TARGET${path}"
done

# Version enumeration — try different API versions
for v in v1 v2 v3 v4; do
  curl -s -o /dev/null -w "%{http_code} /api/${v}/\n" "TARGET/api/${v}/"
done
```

Log accessible documentation endpoints to evidence.

### Step 2: Mass Assignment Testing

For each endpoint that accepts POST/PUT/PATCH with JSON body:

1. Send a normal request, capture response fields
2. Resend with extra fields: `{"normal_field": "value", "role": "admin", "is_admin": true}`
3. Compare responses — check if extra fields were accepted

```bash
# Use authz payloads for role escalation via mass assignment
ensphere payloads authz --technique privilege_escalation --surface json_body --max-risk 3
```

### Step 3: Rate Limit Measurement

```bash
# Measure rate limiting on authentication endpoint
ensphere verify ratelimit \
  --url "TARGET/api/login" \
  --method POST \
  --body '{"email":"test@test.com","password":"wrong"}' \
  --burst-count 100 \
  --window-sec 10 \
  --in-scope "SCOPE"

# Measure rate limiting on sensitive data endpoint
ensphere verify ratelimit \
  --url "TARGET/api/users" \
  --method GET \
  --token "AUTH_TOKEN" \
  --burst-count 50 \
  --window-sec 10 \
  --in-scope "SCOPE"
```

Key measurements to record:
- First throttle position (request # where 429 starts)
- Total requests before throttle
- Whether throttle applies per-IP, per-user, or per-endpoint

### Step 4: Property-Level Authorization

```bash
# Compare JSON fields between admin and regular user responses
ensphere verify propertyauthz \
  --url "TARGET/api/users/1" \
  --high-token "ADMIN_TOKEN" \
  --low-token "USER_TOKEN" \
  --watch-fields "ssn,salary,role,permissions,internal_id" \
  --in-scope "SCOPE"

# Test profile endpoint
ensphere verify propertyauthz \
  --url "TARGET/api/me" \
  --high-token "ADMIN_TOKEN" \
  --low-token "USER_TOKEN" \
  --in-scope "SCOPE"
```

Check for:
- Fields present in admin response but also in user response (over-exposure)
- Sensitive fields (PII, financial data) accessible to low-privilege users
- Internal fields (IDs, timestamps, metadata) that leak information

### Step 5: Pagination Abuse

Test pagination parameters for abuse:

```bash
# Bounded overlarge page-size probe; do not attempt a full dataset dump
curl -s "TARGET/api/items?page=1&per_page=101" -H "Authorization: Bearer TOKEN"

# Negative offset — potential for data leak or error
curl -s "TARGET/api/items?offset=-1&limit=10" -H "Authorization: Bearer TOKEN"

# Zero page size — potential for division by zero or all records
curl -s "TARGET/api/items?page=1&per_page=0" -H "Authorization: Bearer TOKEN"

# Cursor manipulation — if cursor-based, try invalid/expired cursors
curl -s "TARGET/api/items?cursor=AAAA&limit=10" -H "Authorization: Bearer TOKEN"
```

### Step 6: GraphQL Mutation Testing

If GraphQL endpoint exists (discovered in recon):

```bash
# Check introspection
ensphere verify graphql --url "TARGET/graphql" --technique introspection --in-scope "SCOPE"

# Test unauthorized mutations
ensphere verify graphql --url "TARGET/graphql" --technique batch_query --token "USER_TOKEN" --in-scope "SCOPE"
```

Then manually test:
- Mutations that should be admin-only but accept user tokens
- Field-level authorization in mutations (e.g., updating own `role` field)
- Batch queries to bypass rate limits

### Step 7: Webhook SSRF

If webhook functionality exists:

```bash
# Test webhook URL with internal addresses
ensphere verify ssrf --url "TARGET/api/webhooks" --param url --in-scope "SCOPE"
```

Test:
- Internal URL injection (`http://169.254.169.254/`, `http://localhost/`)
- URL scheme bypass (`file://`, `gopher://`)
- Signature bypass (if webhook verification is implemented)

## Phase A-BB: Black-Box API Assessment

When no source code is available, replace Phase A with API surface discovery:

### Step 1: API Surface Mapping

```bash
# Discover API endpoints by probing common patterns
for path in /api /api/v1 /api/v2 /graphql /swagger.json /openapi.json /api-docs; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" "TARGET${path}"
done
```

### Step 2: Documentation Discovery

Check for:
- `/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui/`
- `/.well-known/openapi.yaml`
- GraphQL introspection (`__schema` query)
- WADL files

### Step 3: Content-Type Probing

For each endpoint, test different content types:
- `application/json` vs `application/x-www-form-urlencoded`
- `application/xml` (potential XXE)
- `text/plain`

### Step 4: Rate Limit Baseline

Use `ensphere verify ratelimit` on each critical endpoint to establish rate limiting behavior.

### Step 5: Version Enumeration

Probe different API version prefixes (`/api/v1/`, `/api/v2/`) to find deprecated or less-secured versions.

## Evidence Logging

Log all findings to `ensphere-pentest/08-api/evidence.jsonl`:

```bash
ensphere evidence log \
  --probe-type rate_limit \
  --technique rate_limit_bypass \
  --url "TARGET/api/login" \
  --result probe \
  --session 8 \
  --notes "No rate limiting detected: 100 requests in 10s, 0 throttled"
```

## Report Format

Write to `ensphere-pentest/08-api/report.md`:

```markdown
# Session 08: API Security

## Summary
[Brief overview of API security posture]

## Findings

### Rate Limiting
[Per-endpoint rate limit measurements and gaps]

### Property-Level Authorization
[Field exposure analysis — which sensitive fields are accessible to low-priv users]

### Mass Assignment
[Endpoints vulnerable to extra-field injection]

### Pagination
[Abuse scenarios and data exposure risks]

### API Documentation Exposure
[Accessible documentation endpoints and information disclosed]

### Webhook Security
[SSRF risks and signature bypass findings]

## Recommendations
[Prioritized remediation recommendations]
```
