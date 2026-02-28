# Ruby on Rails Security Checklist

Attack surface specific to Ruby on Rails applications.

## Mass Assignment

- [ ] Strong parameters bypass — `params.permit!` or missing `require().permit()` allows setting arbitrary model attributes including `admin`, `role`
  -> payloads: manual — POST/PUT with additional fields (`admin: true`, `role: superadmin`)
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

## ActiveRecord Injection

- [ ] SQL injection via ActiveRecord — user input in `where()`, `order()`, `pluck()`, `group()`, or `having()` clauses passed as raw strings
  -> payloads: `ensphere payloads sqli --db postgres --technique error_based`
  -> verify: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./app --category sqli`

## SQL Injection via Arel

- [ ] SQL injection through Arel nodes — `Arel.sql(user_input)` or raw SQL fragments in Arel queries bypass parameterization
  -> payloads: `ensphere payloads sqli --db postgres --technique union`
  -> verify: `ensphere verify sqli --technique blind_time --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./app --category sqli`

## Marshal Deserialization

- [ ] Insecure deserialization via `Marshal.load` — deserialization of untrusted data leads to arbitrary code execution
  -> payloads: `ensphere payloads deserialization --runtime ruby --technique deserialization_rce`
  -> verify: `ensphere verify deserialization --technique dns_oob --url <endpoint> --param <param> --in-scope <pattern>`

## Open Redirect

- [ ] `redirect_to` with user-controlled input — missing host validation allows redirecting to attacker-controlled domains
  -> payloads: `ensphere payloads redirect --technique open_redirect_param`
  -> verify: `ensphere verify redirect --technique open_redirect_param --url <endpoint> --param <param> --in-scope <pattern>`

## CSRF

- [ ] Missing CSRF token validation — `skip_before_action :verify_authenticity_token` or `protect_from_forgery with: :null_session` on state-changing endpoints
  -> payloads: `ensphere payloads csrf --technique form_auto_submit`
  -> verify: `ensphere verify csrf --url <endpoint> --in-scope <pattern>`

## Authentication

- [ ] Devise auth bypass — custom authentication logic bypassing Devise guards, or missing `authenticate_user!` before_action on controllers
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique no_token --url <endpoint> --in-scope <pattern>`

## Secret Key Base

- [ ] `secret_key_base` exposure — hardcoded in `secrets.yml`, `credentials.yml.enc` with committed master key, or environment variable leaking via error pages
  -> payloads: manual — search git history, `config/secrets.yml`, `config/credentials.yml.enc`, `config/master.key`
  -> scan: `ensphere scan ./config --category secrets`

## Content Security Policy

- [ ] Missing or weak CSP — no `content_security_policy` block in initializer, or overly permissive `unsafe-inline`, `unsafe-eval` directives
  -> payloads: `ensphere payloads xss --technique reflected`
  -> verify: `ensphere verify xss --technique reflected --url <endpoint> --param <param> --in-scope <pattern>`

## File Upload

- [ ] Active Storage upload validation — missing content-type validation or file size limits on `has_one_attached` / `has_many_attached`
  -> payloads: `ensphere payloads file_upload --technique extension_bypass`
  -> verify: manual — upload executable or HTML file and check if it is served with original content-type

## Session Fixation

- [ ] Session fixation via `reset_session` omission — session ID not regenerated after authentication, allowing attacker to fixate session before login
  -> payloads: `ensphere payloads auth_bypass --technique session_fixation`
  -> verify: `ensphere verify auth --technique session_fixation --url <login_endpoint> --in-scope <pattern>`

## Insecure Cookie Settings

- [ ] Missing `secure`, `httponly`, or `samesite` flags on session cookie — session cookie transmitted over HTTP or accessible via JavaScript
  -> payloads: manual — inspect `Set-Cookie` headers for missing flags
  -> verify: `ensphere verify cors --url <endpoint> --in-scope <pattern>`
