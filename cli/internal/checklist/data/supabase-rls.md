# Supabase RLS Security Checklist

Attack surface specific to Supabase (PostgreSQL + PostgREST + GoTrue + Storage).

## Key Exposure

- [ ] RLS bypass via exposed `service_role` key — check client-side JS bundles, `.env` files, git history
  → payloads: manual — search for `eyJ` (JWT prefix) in page source, network requests, public repos
  → verify: manual — search client-side JS bundles and page source for `eyJ` (JWT prefix) indicating exposed service_role key

## PostgREST

- [ ] Direct PostgREST access bypassing app validation — Supabase exposes REST API at `/rest/v1/`; Zod validation only runs in the app
  → payloads: `ensphere payloads sqli --db postgres --surface query`
  → verify: `ensphere verify authz --url <supabase-url>/rest/v1/<table> --low-token <anon-jwt> --high-token <service-role> --in-scope <pattern>`

## RLS Policies

- [ ] Missing RLS policies on new tables — tables created without `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` are open to all
  → payloads: manual — `SELECT tablename FROM pg_tables WHERE NOT rowsecurity`
  → verify: `ensphere verify rls --table <name> --tenant-a <id> --tenant-b <id> ...`

- [ ] RLS `USING` vs `WITH CHECK` mismatch — `USING` controls reads, `WITH CHECK` controls writes; missing either creates gaps
  → payloads: manual — review policies for SELECT-only or INSERT-only rules
  → verify: manual — review RLS policies for USING vs WITH CHECK coverage gaps; query pg_policies for inspection

## JWT & Auth

- [ ] JWT claim manipulation via `requesting_company_id()` — custom claims in JWT used for RLS; verify HMAC signing is enforced
  → payloads: manual — craft JWT with altered `company_id` claim using anon key
  → verify: `ensphere verify rls --jwt-secret <secret> --table <table> --tenant-a <id> --tenant-b <id>`

- [ ] Auth webhook spoofing — if using custom auth hooks, verify webhook origin and signature
  → payloads: `ensphere payloads ssrf --technique webhook_spoof`
  → verify: manual — send forged webhook request without valid signature header, check if accepted

## Functions

- [ ] `SECURITY DEFINER` function exposure — functions running as definer bypass RLS; check for user-controlled input in SQL
  → payloads: `ensphere payloads sqli --db postgres --technique error_based`
  → verify: `ensphere verify sqli --technique error_based --url <fn_endpoint> --param <param> --in-scope <pattern>`

## Storage

- [ ] Storage bucket ACL leakage — public buckets expose all objects; check bucket policies for unintended public access
  → payloads: manual — enumerate `storage/v1/object/public/` paths
  → verify: `ensphere verify authz --url <supabase-url>/storage/v1/object/<bucket>/<key> --low-token <anon-jwt> --high-token <service-role> --in-scope <pattern>`

## Realtime

- [ ] Realtime subscription tenant isolation — Realtime channels may leak data across tenants if RLS isn't enforced on subscriptions
  → payloads: manual — subscribe to channels with different tenant contexts
  → verify: manual — subscribe to Realtime channel with tenant-A JWT, check if tenant-B data is received

## Edge Functions

- [ ] Edge function secrets exposure — secrets available via `Deno.env.get()` may leak in error responses or logs
  → payloads: manual — trigger errors in edge functions and inspect responses
  → verify: manual — trigger errors in edge functions and inspect responses for leaked `Deno.env` values
