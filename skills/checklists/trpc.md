# tRPC Security Checklist

Attack surface specific to tRPC v10/v11 applications.

## Authentication

- [ ] Procedures missing auth middleware — queries or mutations callable without `protectedProcedure`
  → payloads: manual — enumerate procedures and test without session cookie
  → verify: `ensphere verify authz --technique trpc_unprotected` (Increment 3)

## Input Validation

- [ ] Zod schema validation gaps — `.passthrough()` allows extra fields; missing `.strict()` permits prototype pollution
  → payloads: `ensphere payloads sqli --surface json_body`
  → verify: `ensphere verify sqli --technique zod_passthrough` (Increment 3)

- [ ] Input coercion type confusion — `z.coerce.number()` converts strings to numbers silently; `"0"` and `""` become `0`
  → payloads: manual — send string values where numbers expected, check for NaN/0 coercion
  → verify: `ensphere verify sqli --technique type_coercion` (Increment 3)

## Batching

- [ ] Batch endpoint information aggregation — tRPC batches multiple calls in one HTTP request; combine privileged + unprivileged calls to extract data via timing or error differences
  → payloads: manual — send batch with mixed auth-required and public procedures
  → verify: `ensphere verify authz --technique trpc_batch` (Increment 3)

## Authorization

- [ ] Cross-tenant data in queries — procedures missing `company_id` filter return data across tenants
  → payloads: manual — call procedures with valid session but targeting other tenant's resource IDs
  → verify: `ensphere verify authz --technique cross_tenant` (Increment 3)

- [ ] Subscription enforcement bypass — mutation procedures callable despite expired/canceled subscription
  → payloads: manual — test mutations with expired trial or canceled subscription
  → verify: `ensphere verify authz --technique subscription_bypass` (Increment 3)

## Error Handling

- [ ] Error messages leaking internal details — tRPC wraps errors in `TRPCError`; check that `cause` and stack traces are stripped in production
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: `ensphere verify info_disclosure --technique trpc_error` (Increment 3)

## Rate Limiting

- [ ] Rate limiting gaps on mutation procedures — no rate limiting on sensitive mutations (password reset, login, file upload)
  → payloads: manual — rapid-fire mutations and measure response times / error codes
  → verify: `ensphere verify dos --technique rate_limit` (Increment 3)
