# tRPC Security Checklist

Attack surface specific to tRPC v10/v11 applications.

## Authentication

- [ ] Procedures missing auth middleware — queries or mutations callable without `protectedProcedure`
  → payloads: manual — enumerate procedures and test without session cookie
  → verify: `ensphere verify auth --technique no_token --url <endpoint> --token <valid-jwt> --in-scope <pattern>`

## Input Validation

- [ ] Zod schema validation gaps — `.passthrough()` allows extra fields; missing `.strict()` permits prototype pollution
  → payloads: `ensphere payloads sqli --surface json_body`
  → verify: manual — send JSON body with extra fields through `.passthrough()` validators and observe backend behavior

- [ ] Input coercion type confusion — `z.coerce.number()` converts strings to numbers silently; `"0"` and `""` become `0`
  → payloads: manual — send string values where numbers expected, check for NaN/0 coercion
  → verify: manual — send string values where numbers expected, check for NaN/0 coercion in business logic

## Batching

- [ ] Batch endpoint information aggregation — tRPC batches multiple calls in one HTTP request; combine privileged + unprivileged calls to extract data via timing or error differences
  → payloads: manual — send batch with mixed auth-required and public procedures
  → verify: `ensphere verify authz --url <target>/api/trpc/proc1,proc2 --low-token <user> --high-token <admin> --in-scope <pattern>`

## Authorization

- [ ] Cross-tenant data in queries — procedures missing `company_id` filter return data across tenants
  → payloads: manual — call procedures with valid session but targeting other tenant's resource IDs
  → verify: `ensphere verify idor --url <endpoint>/{id} --id <other-tenant-id> --token <current-tenant-jwt> --in-scope <pattern>`

- [ ] Subscription enforcement bypass — mutation procedures callable despite expired/canceled subscription
  → payloads: manual — test mutations with expired trial or canceled subscription
  → verify: `ensphere verify authz --url <endpoint> --low-token <expired-sub> --high-token <active-sub> --in-scope <pattern>`

## Error Handling

- [ ] Error messages leaking internal details — tRPC wraps errors in `TRPCError`; check that `cause` and stack traces are stripped in production
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: manual — trigger errors in production mode and check that `cause` and stack traces are stripped from TRPCError responses

## Rate Limiting

- [ ] Rate limiting gaps on mutation procedures — no rate limiting on sensitive mutations (password reset, login, file upload)
  → payloads: manual — rapid-fire mutations and measure response times / error codes
  → verify: `ensphere verify ratelimit --url <endpoint> --method POST --in-scope <pattern>`
