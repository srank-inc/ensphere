# Cloudflare R2 Security Checklist

Attack surface specific to Cloudflare R2 object storage.

## Presigned URLs

- [ ] Presigned URL scope too broad — missing path prefix, content-type, or content-length constraints on presigned PUT URLs
  → payloads: manual — use presigned URL to upload to unexpected paths or with unexpected content types
  → verify: `ensphere verify authz --technique presign_scope` (Increment 3)

## Bucket Configuration

- [ ] Public bucket misconfiguration — R2 bucket set to public when it should be private; all objects accessible without auth
  → payloads: manual — attempt to access `https://<bucket>.r2.dev/<key>` without credentials
  → verify: `ensphere verify authz --technique public_bucket` (Increment 3)

- [ ] CORS misconfiguration on bucket — overly permissive `Access-Control-Allow-Origin` allows cross-origin reads
  → payloads: manual — send cross-origin requests from attacker domain and check CORS headers
  → verify: `ensphere verify config --technique r2_cors` (Increment 3)

## Upload Validation

- [ ] Missing content-type validation on upload — server accepts presign request without validating MIME type against allowlist
  → payloads: manual — request presigned URL for `application/x-executable` or `text/html`
  → verify: `ensphere verify config --technique upload_mime` (Increment 3)

## Encryption

- [ ] SSE-C encryption key management — customer-provided encryption keys stored insecurely or reused across tenants
  → payloads: manual — review key derivation, storage, and rotation logic
  → verify: `ensphere verify config --technique ssec_keys` (Increment 3)

## Enumeration

- [ ] Object listing/enumeration via `ListObjects` — if Workers or API expose list operations, attacker can enumerate all stored objects
  → payloads: manual — call `ListObjectsV2` with empty prefix to enumerate bucket contents
  → verify: `ensphere verify authz --technique r2_enumeration` (Increment 3)
