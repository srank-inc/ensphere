# Express.js Security Checklist

Attack surface specific to Express.js and Node.js web applications.

## NoSQL Injection

- [ ] MongoDB operator injection — user input passed to Mongoose/MongoDB queries without sanitization allows `$gt`, `$ne`, `$regex` operators in JSON body
  -> payloads: `ensphere payloads nosql --technique operator_injection`
  -> verify: `ensphere verify nosql --technique operator_injection --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category nosql`

## Prototype Pollution

- [ ] Prototype pollution via `merge`, `extend`, or `defaultsDeep` — user-controlled JSON with `__proto__` or `constructor.prototype` keys poisons `Object.prototype`
  -> payloads: `ensphere payloads prototype_pollution --technique proto_assignment`
  -> verify: `ensphere verify protopollution --technique proto_assignment --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category prototype_pollution`

## Path Traversal

- [ ] Path traversal via `express.static` or `res.sendFile` — user-controlled path segments resolve to files outside intended directory
  -> payloads: `ensphere payloads lfi --technique directory_traversal`
  -> verify: `ensphere verify lfi --url <endpoint> --param <param> --in-scope <pattern>`

## JWT Implementation

- [ ] Insecure `jsonwebtoken` usage — missing `algorithms` whitelist in `jwt.verify()` allows algorithm confusion (RS256 to HS256) or `none` algorithm bypass
  -> payloads: `ensphere payloads jwt --technique alg_none`
  -> verify: `ensphere verify jwt --technique alg_none --url <endpoint> --in-scope <pattern>`

## Security Headers

- [ ] Missing Helmet middleware — no `helmet()` middleware or individual headers (`X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS`) not configured
  -> payloads: manual — inspect response headers for missing security headers
  -> verify: `ensphere verify clickjacking --url <endpoint> --in-scope <pattern>`

## CORS Configuration

- [ ] Overly permissive `cors()` middleware — `origin: true` or `origin: '*'` with `credentials: true` allows cross-origin credential theft
  -> payloads: manual — send request with `Origin: https://attacker.com` and inspect CORS headers
  -> verify: `ensphere verify cors --url <endpoint> --in-scope <pattern>`

## Rate Limiting

- [ ] Missing rate limiting on auth endpoints — no `express-rate-limit` on `/login`, `/register`, `/forgot-password` enables brute force and credential stuffing
  -> payloads: manual — rapid-fire requests to auth endpoints and observe response patterns
  -> verify: `ensphere verify ratelimit --url <endpoint> --in-scope <pattern>`

## Session Management

- [ ] Insecure `express-session` configuration — default `MemoryStore` in production, missing `secure`, `httpOnly`, `sameSite` flags, or weak session secret
  -> payloads: `ensphere payloads auth_bypass --technique session_fixation`
  -> verify: manual — set session cookie before login, authenticate, check if same session ID persists post-auth

## File Upload

- [ ] Unrestricted multer upload — missing `fileFilter`, `limits.fileSize`, or filename sanitization allows oversized files, path traversal in filenames, or executable uploads
  -> payloads: `ensphere payloads file_upload --technique extension_bypass`
  -> verify: manual — upload files with double extensions (`.php.jpg`), oversized payloads, or path traversal filenames

## Template Injection

- [ ] Server-side template injection in EJS or Pug — user input interpolated into template strings or passed as template options enables code execution
  -> payloads: `ensphere payloads ssti --runtime node --technique expression_eval`
  -> verify: `ensphere verify ssti --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category ssti`

## SQL Injection

- [ ] Raw SQL in Knex or Sequelize — `knex.raw(userInput)`, `sequelize.query(userInput)`, or string interpolation in query builders bypasses parameterization
  -> payloads: `ensphere payloads sqli --technique error_based`
  -> verify: `ensphere verify sqli --technique error_based --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category sqli`

## SSRF

- [ ] SSRF via `axios`, `node-fetch`, or `got` — user-controlled URLs passed to HTTP clients without validation reach internal services, cloud metadata, or localhost
  -> payloads: `ensphere payloads ssrf --technique metadata_access`
  -> verify: `ensphere verify ssrf --url <endpoint> --param <param> --in-scope <pattern>`
  -> scan: `ensphere scan ./src --category ssrf`
