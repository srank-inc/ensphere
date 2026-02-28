# Django / DRF Security Checklist

Attack surface specific to Django and Django REST Framework applications.

## ORM Injection

- [ ] SQL injection via `raw()`, `extra()`, or `RawSQL` — user input passed directly into raw SQL bypasses ORM escaping
  -> payloads: `ensphere payloads sqli --db postgres --technique error_based`
  -> verify: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category sqli`

## Deserialization

- [ ] Pickle deserialization via session backend — Django's `PickleSerializer` allows RCE if `SECRET_KEY` is compromised or session data is attacker-controlled
  -> payloads: `ensphere payloads deserialization --runtime python --technique deserialization_rce`
  -> verify: `ensphere verify deserialization --technique time_based --url <endpoint> --param <param> --in-scope <pattern>`

## CSRF

- [ ] `@csrf_exempt` on sensitive views — decorator disables Django's built-in CSRF protection on individual views
  -> payloads: `ensphere payloads csrf --technique form_auto_submit`
  -> verify: `ensphere verify csrf --url <endpoint> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category csrf`

## Admin Exposure

- [ ] Django admin endpoint accessible in production — `/admin/` exposed without IP restriction or 2FA
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique forced_browsing --url <target>/admin/ --in-scope <pattern>`

## CORS

- [ ] Misconfigured `django-cors-headers` — `CORS_ALLOW_ALL_ORIGINS = True` or overly permissive `CORS_ALLOWED_ORIGINS` in settings
  -> payloads: manual — send request with `Origin: https://attacker.com` and check `Access-Control-Allow-Origin`
  -> verify: `ensphere verify cors --url <endpoint> --in-scope <pattern>`

## Debug Mode

- [ ] `DEBUG = True` in production — exposes full stack traces, settings, SQL queries, and installed apps via error pages
  -> payloads: manual — trigger a 404 or 500 error and inspect response for debug toolbar or stack trace
  -> verify: manual — check response for `Traceback`, `INSTALLED_APPS`, or Djdt toolbar markup

## Secret Key Exposure

- [ ] `SECRET_KEY` hardcoded or committed to version control — compromises session signing, CSRF tokens, and password reset tokens
  -> payloads: manual — search git history, `.env` files, `settings.py` for `SECRET_KEY`
  -> scan: `ensphere scan ./src --category secrets`

## Mass Assignment

- [ ] DRF serializer mass assignment — `fields = '__all__'` or missing `read_only_fields` allows setting `is_staff`, `is_superuser`, or other privileged fields
  -> payloads: manual — POST/PUT request with additional fields (`is_staff: true`, `role: admin`)
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

## File Upload

- [ ] Unrestricted file upload via `FileField` / `ImageField` — missing content-type validation, file size limits, or filename sanitization
  -> payloads: `ensphere payloads file_upload --technique extension_bypass`
  -> verify: `ensphere verify sqli --technique error_based --url <upload_endpoint> --param file --in-scope <pattern>`

## Template Injection

- [ ] Server-side template injection via Django templates — user input rendered with `Template(user_input).render()` instead of passed as context variable
  -> payloads: `ensphere payloads ssti --runtime python --technique expression_eval`
  -> verify: `ensphere verify ssti --technique expression_eval --url <endpoint> --param <param> --in-scope <pattern>`
