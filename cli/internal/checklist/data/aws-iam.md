# AWS IAM Security Checklist

Attack surface specific to AWS Identity and Access Management configuration.

## Least Privilege Policies

- [ ] Overly permissive IAM policies — `"Action": "*"` or `"Resource": "*"` in attached policies grant full access; check for `AdministratorAccess` on non-admin users/roles
  -> verify: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`

## MFA Enforcement

- [ ] MFA not enforced — IAM users without MFA can access console and API; no SCP or IAM policy denying actions without `aws:MultiFactorAuthPresent`
  -> verify: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`

## Access Key Rotation

- [ ] Stale access keys — IAM user access keys older than 90 days not rotated; long-lived credentials increase blast radius of key compromise
  -> verify: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`

## Role Trust Policies

- [ ] Overly broad trust policies — `"Principal": {"AWS": "*"}` or missing condition keys (`sts:ExternalId`, `aws:PrincipalOrgID`) in role trust policy allow cross-account assumption
  -> verify: `ensphere cloud iam --provider aws --principal <role_arn> --in-scope "aws://<account_id>"`

## Permission Boundaries

- [ ] Missing permission boundaries — delegated admin roles without permission boundaries can escalate privileges by creating new users/roles with full access
  -> verify: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`

## Access Analyzer

- [ ] IAM Access Analyzer not enabled — no analyzer configured for the account/org; external access grants to resources go undetected
  -> verify: manual — `aws accessanalyzer list-analyzers --region <region>` and check for active analyzers

## Root Account Usage

- [ ] Root account active usage — root account has access keys, lacks MFA, or shows recent API activity; root should only be used for account-level operations
  -> verify: manual — `aws iam get-account-summary` and check `AccountAccessKeysPresent`, `AccountMFAEnabled`

## Password Policy

- [ ] Weak password policy — IAM password policy allows short passwords, no uppercase/symbol requirements, or does not enforce rotation
  -> verify: manual — `aws iam get-account-password-policy` and check minimum length, complexity, and max age

## Service Control Policies

- [ ] Missing or permissive SCPs — AWS Organizations without SCPs restricting dangerous services (`iam:CreateUser`, `sts:AssumeRole` to external accounts, region restrictions)
  -> verify: manual — `aws organizations list-policies --filter SERVICE_CONTROL_POLICY` and review attached SCPs

## Cross-Account Roles

- [ ] Unaudited cross-account roles — roles assumable by external accounts without logging or alerting; no CloudTrail monitoring for `AssumeRole` events from external principals
  -> verify: `ensphere cloud iam --provider aws --principal <role_arn> --in-scope "aws://<account_id>"`

## Unused Credentials

- [ ] Unused IAM users and roles — users with no console/API activity in 90+ days and roles never assumed; dormant credentials are targets for compromise
  -> verify: manual — `aws iam generate-credential-report` and review `password_last_used`, `access_key_last_used`

## Inline vs Managed Policies

- [ ] Excessive inline policies — inline policies attached directly to users/roles are harder to audit and lack version control; prefer managed policies for centralized governance
  -> verify: `ensphere cloud iam --provider aws --principal <arn> --in-scope "aws://<account_id>"`
