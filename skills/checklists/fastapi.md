# FastAPI Security Checklist

Attack surface specific to FastAPI and Python async web applications.

## Auth Middleware Gaps

- [ ] Missing `Depends()` auth dependency on endpoints — path operations without `Depends(get_current_user)` or custom auth dependency are publicly accessible
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique no_token --url <endpoint> --in-scope <pattern>`

## Pydantic Validation Bypass

- [ ] Pydantic model validation gaps — `model_config = ConfigDict(extra="allow")` or `Extra.allow` passes unvalidated fields through; type coercion converts strings silently
  -> payloads: manual — POST with unexpected fields (`is_admin: true`, `role: admin`) or type-confused values
  -> verify: `ensphere verify authz --url <endpoint> --in-scope <pattern>`

## CORS Configuration

- [ ] Overly permissive `CORSMiddleware` — `allow_origins=["*"]` with `allow_credentials=True` exposes authenticated endpoints to cross-origin requests
  -> payloads: manual — send request with `Origin: https://attacker.com` and inspect CORS headers
  -> verify: `ensphere verify cors --url <endpoint> --in-scope <pattern>`

## OpenAPI/Swagger Exposure

- [ ] OpenAPI schema and Swagger UI in production — `/docs`, `/redoc`, and `/openapi.json` expose all endpoints, parameters, and response schemas to attackers
  -> payloads: `ensphere payloads auth_bypass --technique forced_browsing`
  -> verify: `ensphere verify auth --technique forced_browsing --url <target>/docs --in-scope <pattern>`

## SQL Injection

- [ ] Raw SQL via SQLAlchemy — `text()`, `execute()`, or f-string interpolation in SQLAlchemy queries bypasses ORM parameterization
  -> payloads: `ensphere payloads sqli --db postgres --technique error_based`
  -> verify: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category sqli`

## File Upload

- [ ] `UploadFile` validation missing — no content-type check, file size limit, or filename sanitization on `UploadFile` parameters allows oversized or malicious uploads
  -> payloads: `ensphere payloads file_upload --technique extension_bypass`
  -> verify: manual — upload files with dangerous extensions, oversized payloads, or path traversal filenames

## Rate Limiting

- [ ] No rate limiting middleware — FastAPI has no built-in rate limiting; missing `slowapi` or custom limiter on auth endpoints enables brute force attacks
  -> payloads: manual — rapid-fire requests to login/registration endpoints
  -> verify: `ensphere verify ratelimit --url <endpoint> --in-scope <pattern>`

## JWT Implementation

- [ ] Insecure JWT handling — missing `algorithms` parameter in `jose.jwt.decode()` or `PyJWT`, accepting `none` algorithm, or symmetric secret in asymmetric flow
  -> payloads: `ensphere payloads jwt --technique alg_none`
  -> verify: `ensphere verify jwt --technique alg_none --url <endpoint> --in-scope <pattern>`

## Path Operation Security

- [ ] Path parameter injection — user-controlled path parameters used in file operations (`Path(...)` to file reads) or database queries without sanitization
  -> payloads: `ensphere payloads lfi --technique directory_traversal`
  -> verify: `ensphere verify lfi --technique directory_traversal --url <endpoint> --param <param> --in-scope <pattern>`

## Background Task Injection

- [ ] Background task with unsanitized input — `BackgroundTasks.add_task()` executing shell commands or file operations with user-controlled arguments
  -> payloads: `ensphere payloads cmdi --technique command_injection`
  -> verify: `ensphere verify cmdi --technique command_injection --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category cmdi`
