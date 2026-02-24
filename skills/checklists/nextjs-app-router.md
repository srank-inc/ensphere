# Next.js App Router Security Checklist

Framework-specific attack surface for Next.js 13+ App Router applications.

## Server Actions

- [ ] Server Actions callable without authentication — missing `requireAuth()` or session check
  → payloads: `ensphere payloads csrf --technique server_action`
  → verify: `ensphere verify csrf --technique server_action` (Increment 3)

- [ ] CSRF on Server Actions — missing Origin header validation, POST-only enforcement
  → payloads: `ensphere payloads csrf --surface form_body`
  → verify: `ensphere verify csrf --surface form_body` (Increment 3)

- [ ] Server Action return value leaks internal data — error messages, stack traces, or DB details in ActionResult
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: `ensphere verify info_disclosure` (Increment 3)

## Middleware

- [ ] Middleware path bypass via `_next/` prefix — requests starting with `_next/` skip middleware
  → payloads: `ensphere payloads ssrf --technique path_traversal`
  → verify: `ensphere verify authz --technique middleware_bypass` (Increment 3)

- [ ] Middleware bypass via trailing slashes or encoded paths (`%2f`, `%252f`)
  → payloads: `ensphere payloads sqli --encoding url`
  → verify: `ensphere verify authz --technique path_encoding` (Increment 3)

- [ ] Edge vs Node runtime mismatch — crypto/auth libraries unavailable in Edge middleware
  → payloads: manual code review
  → verify: `ensphere verify config --technique runtime_mismatch` (Increment 3)

## Data Exposure

- [ ] RSC serialized props leak sensitive data — Server Components pass data to client via JSON stream
  → payloads: manual — inspect `__next_f` script tags in page source
  → verify: `ensphere verify info_disclosure --technique rsc_props` (Increment 3)

- [ ] `cookies()` / `headers()` in cached route handlers — dynamic functions in static-cached routes
  → payloads: manual code review for `export const dynamic = 'force-static'` with auth reads
  → verify: `ensphere verify config --technique cache_mismatch` (Increment 3)

## Routing & Redirects

- [ ] `redirect()` open redirect — user-controlled input passed to `redirect()` without validation
  → payloads: `ensphere payloads ssrf --technique open_redirect`
  → verify: `ensphere verify ssrf --technique open_redirect` (Increment 3)

- [ ] Dynamic route parameter injection — `[...slug]` or `[id]` params used unsanitized in DB queries or file paths
  → payloads: `ensphere payloads sqli --surface path`
  → verify: `ensphere verify sqli --surface path` (Increment 3)

- [ ] `revalidatePath` / `revalidateTag` cache poisoning — attacker triggers revalidation to serve stale or poisoned content
  → payloads: manual — call revalidation endpoints with crafted paths
  → verify: `ensphere verify cache_poisoning` (Increment 3)

## Caching

- [ ] `unstable_cache` with user-controlled keys — cache key collision across tenants
  → payloads: manual code review for `unstable_cache(fn, [userInput])`
  → verify: `ensphere verify authz --technique cache_collision` (Increment 3)

## API Routes

- [ ] API route handler auth bypass — `route.ts` handlers missing auth middleware, accessible directly
  → payloads: `ensphere payloads ssrf --surface path`
  → verify: `ensphere verify authz --technique api_route` (Increment 3)

## Headers & Static Files

- [ ] Missing CSP headers — no Content-Security-Policy in `next.config.js` or middleware
  → payloads: `ensphere payloads xss`
  → verify: `ensphere verify config --technique csp` (Increment 3)

- [ ] `next.config.js` security headers missing — HSTS, X-Frame-Options, X-Content-Type-Options
  → payloads: manual — check response headers
  → verify: `ensphere verify config --technique security_headers` (Increment 3)

- [ ] Static file serving exposes sensitive files — `.env`, `.env.local`, source maps in `public/`
  → payloads: `ensphere payloads ssrf --technique path_traversal`
  → verify: `ensphere verify info_disclosure --technique static_files` (Increment 3)

## Error Handling

- [ ] Error boundary information disclosure — `error.tsx` or `global-error.tsx` renders raw error messages
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: `ensphere verify info_disclosure --technique error_boundary` (Increment 3)
