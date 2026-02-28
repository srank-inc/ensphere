# AWS S3 Security Checklist

Attack surface specific to Amazon S3 bucket configuration and access controls.

## Public Access Blocks

- [ ] Missing S3 Block Public Access — account-level or bucket-level `PublicAccessBlockConfiguration` not set; buckets can be made public via ACL or policy changes
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Bucket Encryption

- [ ] Missing default encryption — bucket lacks `ServerSideEncryptionConfiguration` (SSE-S3 or SSE-KMS); objects stored unencrypted at rest
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Versioning

- [ ] Versioning disabled — bucket versioning not enabled; deleted or overwritten objects are irrecoverable, and MFA Delete cannot be enforced
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Logging

- [ ] Server access logging disabled — no `LoggingConfiguration` on bucket; access patterns, unauthorized requests, and data exfiltration are unauditable
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Lifecycle Policies

- [ ] Missing lifecycle policies — no rules for transitioning to Glacier, expiring incomplete multipart uploads, or deleting old versions; increases storage cost and data exposure window
  -> verify: manual — `aws s3api get-bucket-lifecycle-configuration --bucket <bucket>`

## CORS Configuration

- [ ] Overly permissive CORS — `AllowedOrigins: ["*"]` or `AllowedMethods: ["*"]` on bucket CORS configuration enables cross-origin reads from any domain
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Presigned URL Scope

- [ ] Presigned URLs with excessive scope — presigned URLs generated with long expiry, no content-type restriction, or broad path prefix allow abuse after leak
  -> payloads: manual — generate presigned URL and test uploading unexpected content types or to unexpected paths
  -> verify: manual — review presign generation code for expiry duration, conditions, and path constraints

## Bucket Policy Wildcards

- [ ] Wildcard principals in bucket policy — `"Principal": "*"` or `"Principal": {"AWS": "*"}` without condition keys grants public access regardless of Block Public Access
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## ACL Grants

- [ ] Legacy ACL grants — `AllUsers` or `AuthenticatedUsers` grantee in bucket or object ACL provides public read/write access outside of policy controls
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## Object Lock

- [ ] Object Lock not configured — compliance-sensitive buckets lack Object Lock (WORM); objects can be deleted or overwritten, violating retention requirements
  -> verify: manual — `aws s3api get-object-lock-configuration --bucket <bucket>`

## Cross-Account Access

- [ ] Unintended cross-account access — bucket policy grants `s3:GetObject` or `s3:PutObject` to external account ARNs without condition keys (`aws:PrincipalOrgID`, `aws:SourceVpc`)
  -> verify: `ensphere cloud storage --provider aws --bucket <bucket> --in-scope "aws://<account_id>"`

## MFA Delete

- [ ] MFA Delete not enabled — versioned buckets without MFA Delete allow permanent deletion of object versions without multi-factor authentication
  -> verify: manual — `aws s3api get-bucket-versioning --bucket <bucket>` and check `MFADelete` status
