# Laravel Security Checklist

Attack surface specific to Laravel PHP applications.

## Mass Assignment

- [ ] Mass assignment via `$fillable` / `$guarded` misconfiguration — missing `$fillable` whitelist or empty `$guarded = []` allows setting arbitrary model attributes including `is_admin`, `role`
  -> payloads: manual — POST/PUT with additional fields (`is_admin: 1`, `role: admin`)
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

## Eloquent Injection

- [ ] SQL injection via Eloquent raw methods — `whereRaw()`, `orderByRaw()`, `selectRaw()`, `havingRaw()`, or `DB::raw()` with unsanitized user input
  -> payloads: `ensphere payloads sqli --db mysql --technique error_based`
  -> verify: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./app --category sqli`

## Blade XSS

- [ ] Unescaped Blade output — `{!! $variable !!}` renders raw HTML; user-controlled data rendered without escaping leads to stored or reflected XSS
  -> payloads: `ensphere payloads xss --technique reflected`
  -> verify: `ensphere verify xss --url <endpoint> --param <param> --payload "<script>alert(1)</script>" --in-scope <pattern>`
  -> scan: `ensphere scan ./resources --category xss`

## Debug Mode

- [ ] `APP_DEBUG=true` in production — exposes full stack traces, environment variables, database credentials, and application secrets via Ignition error page
  -> payloads: manual — trigger an error and inspect response for Ignition error page or stack trace
  -> verify: manual — check response for `APP_KEY`, database credentials, or Ignition markup

## CSRF Protection

- [ ] CSRF middleware excluded on routes — routes in `$except` array of `VerifyCsrfToken` middleware or API routes without alternative token validation
  -> payloads: `ensphere payloads csrf --technique form_auto_submit`
  -> verify: `ensphere verify csrf --url <endpoint> --in-scope <pattern>`

## File Upload

- [ ] File upload validation bypass — missing MIME type validation, relying only on extension, or storing uploads in publicly accessible `storage/app/public` without sanitization
  -> payloads: `ensphere payloads file_upload --technique mime_bypass`
  -> verify: manual — upload PHP file with image extension, check if it executes

## Route Model Binding

- [ ] Route model binding authorization bypass — implicit model binding resolves any model by ID without checking ownership; missing `Gate::authorize()` or policy check
  -> payloads: `ensphere payloads idor --technique idor_numeric`
  -> verify: `ensphere verify idor --url <endpoint>/{id} --id <victim-id> --token <attacker-jwt> --in-scope <pattern>`

## Queue Deserialization

- [ ] Job/queue deserialization attacks — serialized job payloads (Redis, database, SQS) containing user-controlled data can trigger unsafe deserialization chains
  -> payloads: `ensphere payloads deserialization --runtime php --technique deserialization_rce`
  -> verify: `ensphere verify deserialization --technique time_based --url <endpoint> --param <param> --in-scope <pattern>`

## Auth Gate/Policy Bypass

- [ ] Authorization gate and policy bypass — missing `$this->authorize()` in controllers, or policies with logic errors returning `true` for unauthorized users
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

## Environment File Exposure

- [ ] `.env` file accessible via web — misconfigured web server serves `.env` containing `APP_KEY`, database credentials, API keys, and mail credentials
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique no_token --url <target>/.env --token <valid-jwt> --in-scope <pattern>`
