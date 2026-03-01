# Next.js App Router Security Checklist

Framework-specific attack surface for Next.js 13+ App Router applications.

## Server Actions

- [ ] Server Actions callable without authentication — missing `requireAuth()` or session check
  → payloads: `ensphere payloads csrf --technique server_action`
  → verify: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`

- [ ] CSRF on Server Actions — missing Origin header validation, POST-only enforcement
  → payloads: `ensphere payloads csrf --surface form_body`
  → verify: `ensphere verify csrf --url <endpoint> --method POST --in-scope <pattern>`

- [ ] Server Action return value leaks internal data — error messages, stack traces, or DB details in ActionResult
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: manual — inspect Server Action responses for stack traces, DB errors, or internal paths

## Middleware

- [ ] Middleware path bypass via `_next/` prefix — requests starting with `_next/` skip middleware
  → payloads: `ensphere payloads ssrf --technique path_traversal`
  → verify: `ensphere verify authz --url <target>/_next/../api/protected --low-token <user> --high-token <admin> --in-scope <pattern>`

- [ ] Middleware bypass via trailing slashes or encoded paths (`%2f`, `%252f`)
  → payloads: `ensphere payloads sqli --encoding url`
  → verify: `ensphere verify authz --url <target>/api/protected%2f --low-token <user> --high-token <admin> --in-scope <pattern>`

- [ ] Edge vs Node runtime mismatch — crypto/auth libraries unavailable in Edge middleware
  → payloads: manual code review
  → verify: manual — review middleware imports for Node-only libraries incompatible with Edge runtime

## Data Exposure

- [ ] RSC serialized props leak sensitive data — Server Components pass data to client via JSON stream
  → payloads: manual — inspect `__next_f` script tags in page source
  → verify: manual — inspect `__next_f` script tags in page source for leaked props

- [ ] `cookies()` / `headers()` in cached route handlers — dynamic functions in static-cached routes
  → payloads: manual code review for `export const dynamic = 'force-static'` with auth reads
  → verify: manual — review route segments for `force-static` combined with `cookies()` or `headers()` calls

## Routing & Redirects

- [ ] `redirect()` open redirect — user-controlled input passed to `redirect()` without validation
  → payloads: `ensphere payloads ssrf --technique open_redirect`
  → verify: `ensphere verify redirect --url <endpoint> --param next --in-scope <pattern>`

- [ ] Dynamic route parameter injection — `[...slug]` or `[id]` params used unsanitized in DB queries or file paths
  → payloads: `ensphere payloads sqli --surface path`
  → verify: `ensphere verify sqli --technique error_based --url <endpoint>/[slug] --param slug --in-scope <pattern>`

- [ ] `revalidatePath` / `revalidateTag` cache poisoning — attacker triggers revalidation to serve stale or poisoned content
  → payloads: manual — call revalidation endpoints with crafted paths
  → verify: `ensphere verify cachepoisoning` (Increment 3)

## Caching

- [ ] `unstable_cache` with user-controlled keys — cache key collision across tenants
  → payloads: manual code review for `unstable_cache(fn, [userInput])`
  → verify: manual — request same URL with two tenant tokens, compare cached vs fresh responses for data leakage

## API Routes

- [ ] API route handler auth bypass — `route.ts` handlers missing auth middleware, accessible directly
  → payloads: `ensphere payloads ssrf --surface path`
  → verify: `ensphere verify auth --technique no_token --url <target>/api/<route> --token <valid-jwt> --in-scope <pattern>`

## Headers & Static Files

- [ ] Missing CSP headers — no Content-Security-Policy in `next.config.js` or middleware
  → payloads: `ensphere payloads xss`
  → verify: manual — check response headers for Content-Security-Policy presence and script-src directives

- [ ] `next.config.js` security headers missing — HSTS, X-Frame-Options, X-Content-Type-Options
  → payloads: manual — check response headers
  → verify: manual — check response headers for HSTS, X-Frame-Options, X-Content-Type-Options

- [ ] Static file serving exposes sensitive files — `.env`, `.env.local`, source maps in `public/`
  → payloads: `ensphere payloads ssrf --technique path_traversal`
  → verify: `ensphere verify auth --technique no_token --url <target>/.env --token <valid-jwt> --in-scope <pattern>`

## Error Handling

- [ ] Error boundary information disclosure — `error.tsx` or `global-error.tsx` renders raw error messages
  → payloads: `ensphere payloads sqli --technique error_based`
  → verify: manual — trigger errors and inspect rendered error boundary for raw error messages or stack traces
