# Cloudflare R2 Security Checklist

Attack surface specific to Cloudflare R2 object storage.

## Presigned URLs

- [ ] Presigned URL scope too broad — missing path prefix, content-type, or content-length constraints on presigned PUT URLs
  → payloads: manual — use presigned URL to upload to unexpected paths or with unexpected content types
  → verify: manual — use presigned PUT URL to upload to unexpected path or content type and check acceptance

## Bucket Configuration

- [ ] Public bucket misconfiguration — R2 bucket set to public when it should be private; all objects accessible without auth
  → payloads: manual — attempt to access `https://<bucket>.r2.dev/<key>` without credentials
  → verify: `ensphere verify auth --technique no_token --url https://<bucket>.r2.dev/<key> --token <valid-jwt> --in-scope <pattern>`

- [ ] CORS misconfiguration on bucket — overly permissive `Access-Control-Allow-Origin` allows cross-origin reads
  → payloads: manual — send cross-origin requests from attacker domain and check CORS headers
  → verify: `ensphere verify cors --url <bucket-url> --in-scope <pattern>`

## Upload Validation

- [ ] Missing content-type validation on upload — server accepts presign request without validating MIME type against allowlist
  → payloads: manual — request presigned URL for `application/x-executable` or `text/html`
  → verify: `ensphere verify fileupload --url <upload-endpoint> --filename <test-file> --technique content_type_mismatch --in-scope <pattern>`

## Encryption

- [ ] SSE-C encryption key management — customer-provided encryption keys stored insecurely or reused across tenants
  → payloads: manual — review key derivation, storage, and rotation logic
  → verify: manual — review key derivation, storage, and rotation logic for SSE-C encryption keys

## Enumeration

- [ ] Object listing/enumeration via `ListObjects` — if Workers or API expose list operations, attacker can enumerate all stored objects
  → payloads: manual — call `ListObjectsV2` with empty prefix to enumerate bucket contents
  → verify: manual — call ListObjectsV2 API with empty prefix using least-privileged credentials
