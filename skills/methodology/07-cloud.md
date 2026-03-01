# Session 07: Cloud Security

Covers: Cloud configuration auditing (AWS, Azure, GCP, Kubernetes), infrastructure-as-code scanning, and cloud-specific exploitation.

## Tool Selection

| Need | Tier | Tool |
|------|------|------|
| Cloud configuration audit (AWS, Azure, GCP, K8s) | Tier 1 | `prowler` — primary multi-cloud auditor |
| IaC misconfiguration scanning | Tier 1 | `trivy config` / `trivy image` |
| CVSS scoring | Tier 1 | `ensphere cvss` |
| Compliance mapping | Tier 1 | `ensphere compliance cloud_iam/cloud_storage/cloud_network/...` |
| Evidence logging | Tier 1 | `ensphere evidence log` |
| Custom cloud queries, verification | Tier 2 | `aws` / `gcloud` / `az` / `kubectl` CLI |
| Not applicable | Tier 3 | No browser testing during cloud auditing |

**Decision flow:**
1. Run `prowler` for automated multi-cloud configuration auditing (hundreds of checks per provider)
2. Run `trivy config` for IaC scanning when source code is available (white-box only)
3. Use native CLIs (`aws`, `gcloud`, `az`, `kubectl`) for custom verification of Prowler findings and edge-case queries
4. Never use Playwright — cloud auditing is API/CLI-based, not browser-based

**Assessment mode note:** Cloud configuration auditing always requires account-level credentials — there is no black-box vs white-box distinction for Phases 0, A, and B. The only white-box-only phase is Phase A-IaC (IaC scanning requires source code). If assessment mode is BLACK_BOX, skip Phase A-IaC and proceed through all other phases normally.

## Prerequisites

Before starting any cloud work, check all tool dependencies at once. Do NOT silently skip — the user should know what's missing and decide whether to install.

### Step 1 — Check All Tools

```bash
echo "=== Cloud Session Tool Check ==="
prowler --version 2>/dev/null && echo "Prowler: installed" || echo "Prowler: MISSING"
trivy --version 2>/dev/null && echo "Trivy: installed" || echo "Trivy: MISSING"
aws --version 2>/dev/null && echo "AWS CLI: installed" || echo "AWS CLI: MISSING"
gcloud --version 2>/dev/null | head -1 && echo "gcloud: installed" || echo "gcloud: MISSING"
az --version 2>/dev/null | head -1 && echo "Azure CLI: installed" || echo "Azure CLI: MISSING"
kubectl version --client 2>/dev/null && echo "kubectl: installed" || echo "kubectl: MISSING"
```

### Step 2 — Present Results and Offer Installation

Present a table to the user showing what's installed vs missing, and which phases each tool enables:

| Tool | Status | Enables | Install command |
|------|--------|---------|-----------------|
| `prowler` | Installed/MISSING | Phase A (multi-cloud audit — primary value) | `brew install prowler` or `pip install prowler` |
| `trivy` | Installed/MISSING | Phase A-IaC (IaC + container scanning) | `brew install trivy` |
| `aws` | Installed/MISSING | Phase B AWS verification | `brew install awscli` |
| `gcloud` | Installed/MISSING | Phase B GCP verification | `brew install google-cloud-sdk` |
| `az` | Installed/MISSING | Phase B Azure verification | `brew install azure-cli` |
| `kubectl` | Installed/MISSING | Phase B K8s verification | `brew install kubectl` |

**If tools are missing, ask the user:**
> "These tools are needed for cloud security auditing. Want me to install the missing ones via Homebrew? (I'll only install what's missing.)"

- **User says yes** → Install missing tools via `brew install`, verify installation, then proceed
- **User says no** → Proceed with available tools only; skip phases that require missing tools, document gaps in the report
- **Homebrew not available** → Show manual install instructions and let the user handle it

**Important:** Never install tools without explicit user confirmation. Never use `sudo` for installations. If `brew` is not installed, do not attempt to install it — inform the user and provide alternative install methods (pip, direct download).

### Step 3 — Document Tool Availability

Record which tools are available for the report's "Skipped Checks" section:

| Tool | Available | Impact if Missing |
|------|-----------|-------------------|
| Prowler | Yes/No | No automated multi-cloud audit — Phase A skipped entirely, must rely on manual CLI queries in Phase B |
| Trivy | Yes/No | No IaC scanning — Phase A-IaC skipped, misconfigurations in Terraform/CloudFormation/Docker not detected |
| Native CLIs | Yes/No per provider | Cannot verify Prowler findings or run custom queries for that provider |

## Phase 0: Cloud Provider Detection

Read `ensphere-pentest/config.md` for target cloud provider information (check the "Cloud" field).
Read `ensphere-pentest/01-recon/report.md` for infrastructure clues discovered during reconnaissance.

**Skip-session check:** If ALL of the following are true, skip this session entirely:
1. `config.md` "Cloud" field is "none" or absent
2. No cloud CLI credentials are available (Step 1 below finds nothing)
3. No IaC files are present in the source code (Step 2 below finds nothing, or assessment is BLACK_BOX)

If skipping: write a brief report to `ensphere-pentest/07-cloud/report.md` stating "No cloud infrastructure in scope — session skipped", mark session SKIPPED in `progress.md`, and proceed to Session 09.

### Step 1 — Detect Cloud Providers

Check which cloud providers are in scope by testing for CLI credentials and configuration:

```bash
# AWS
aws sts get-caller-identity 2>/dev/null && echo "AWS: authenticated" || echo "AWS: no credentials"

# GCP
gcloud auth list 2>/dev/null && echo "GCP: authenticated" || echo "GCP: no credentials"

# Azure
az account show 2>/dev/null && echo "Azure: authenticated" || echo "Azure: no credentials"

# Kubernetes
kubectl cluster-info 2>/dev/null && echo "K8s: connected" || echo "K8s: no context"
```

Record which providers have valid credentials. Only audit providers where credentials are available and in scope.

### Step 2 — Detect IaC Files (White-Box Only)

If assessment mode is WHITE_BOX, scan the source code for infrastructure-as-code files:

| Pattern | IaC Type |
|---------|----------|
| `*.tf`, `*.tfvars` | Terraform |
| `template.yaml`, `template.json`, `*.cfn.yaml` | CloudFormation |
| `Dockerfile`, `docker-compose.yml` | Docker |
| `*.yaml` / `*.yml` in `charts/`, `helm/` | Helm |
| `*.bicep`, `azuredeploy.json` | ARM / Bicep |
| `serverless.yml` | Serverless Framework |
| `pulumi.*`, `Pulumi.yaml` | Pulumi |

Record all IaC files found — these feed Phase A-IaC.

### Step 3 — Build Provider Summary

Create a summary table for the report:

| Provider | Credentials | Account/Project | Regions | In Scope |
|----------|-------------|-----------------|---------|----------|
| AWS | Yes/No | [account-id] | [regions] | Yes/No |
| GCP | Yes/No | [project-id] | [regions] | Yes/No |
| Azure | Yes/No | [subscription-id] | [regions] | Yes/No |
| Kubernetes | Yes/No | [cluster-name] | N/A | Yes/No |

## Phase A: Cloud Configuration Audit (Prowler)

For each cloud provider with valid credentials and in scope, run Prowler with JSON output.

**Prerequisite check:**
```bash
prowler --version 2>/dev/null || echo "Prowler not installed — skip Phase A"
```

If Prowler is not installed, skip to Phase B and use native CLIs directly for manual checks.

### Step 1 — Run Prowler per Provider

```bash
# AWS — full audit with JSON-OCSF output
prowler aws -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/

# Azure — full audit
prowler azure -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/

# GCP — full audit
prowler gcp -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/

# Kubernetes — full audit
prowler kubernetes -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/
```

**Note:** Do NOT pre-filter by severity — capture all findings and triage in Step 2. This is consistent with Ensphere's design principle: produce all facts, let the AI apply judgment.

**Prowler output parsing:** Read the JSON-OCSF output files. For each finding with status FAIL, extract:
- Check identifier and title
- Status (`PASS`, `FAIL`, `MANUAL`)
- Severity (`critical`, `high`, `medium`, `low`, `informational`)
- Resource identifier (ARN, resource ID, or resource name)
- Status description (human-readable explanation of the finding)
- Compliance mappings (CIS benchmark controls, if present)

Field names vary by Prowler version and output format. Parse the actual JSON structure rather than assuming fixed field names.

### Step 2 — Triage by Severity

Parse Prowler JSON results and organize findings by severity:

| Priority | Severity | Action |
|----------|----------|--------|
| 1 | Critical | Investigate immediately — likely exploitable |
| 2 | High | Investigate — significant risk |
| 3 | Medium | Document — remediation recommended |
| 4 | Low | Document — best practice improvement |

Focus investigation time on critical and high findings first. Medium and low findings are documented but not deeply verified unless they chain with other findings.

### Step 3 — Compliance-Specific Scans

Run compliance-focused scans for specific benchmarks when relevant.

First, discover available compliance frameworks for each provider:
```bash
prowler <provider> --list-compliance
```

Then run the applicable CIS benchmark (framework identifiers follow the pattern `cis_X.Y_provider`):
```bash
# Example: CIS AWS Foundations Benchmark (use latest version from --list-compliance)
prowler aws --compliance cis_5.0_aws -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/

# Example: CIS GCP Foundations Benchmark
prowler gcp --compliance cis_2.0_gcp -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/

# Example: CIS Kubernetes Benchmark
prowler kubernetes --compliance cis_1.8_kubernetes -M json-ocsf -o ./ensphere-pentest/07-cloud/prowler/
```

**Note:** Compliance framework identifiers change across Prowler versions. Always use `--list-compliance` to discover the exact identifiers available in the installed version.

## Phase A-IaC: Infrastructure-as-Code Review (White-Box Only)

When assessment mode is WHITE_BOX and IaC files were detected in Phase 0, run static analysis.

**Prerequisite check:**
```bash
trivy --version 2>/dev/null || echo "Trivy not installed — skip Phase A-IaC"
```

If Trivy is not installed, skip this phase with a warning in the report.

### Step 1 — Trivy Config Scan

Scan IaC directories for misconfigurations:

```bash
# Scan Terraform files
trivy config --format json --output ./ensphere-pentest/07-cloud/trivy-config.json ./path/to/terraform/

# Scan CloudFormation templates
trivy config --format json --output ./ensphere-pentest/07-cloud/trivy-cfn.json ./path/to/cloudformation/

# Scan Dockerfiles
trivy config --format json --output ./ensphere-pentest/07-cloud/trivy-docker.json ./path/to/dockerfiles/

# Scan Helm charts
trivy config --format json --output ./ensphere-pentest/07-cloud/trivy-helm.json ./path/to/helm/
```

**Trivy config output parsing:** For each misconfiguration in the `Results[].Misconfigurations[]` array, extract:
- `ID` (or `AVDID`), `Title`, `Description`
- `Severity` (CRITICAL, HIGH, MEDIUM, LOW)
- `Resolution` (recommended fix)
- `Target` (file path)

### Step 2 — Trivy Container Image Scan

If Dockerfiles are present, scan the built images for vulnerabilities:

```bash
# Scan container images
trivy image --format json --output ./ensphere-pentest/07-cloud/trivy-image.json <image-name>:<tag>
```

Focus on:
- Critical/high CVEs in base images
- Outdated packages with known exploits
- Secrets embedded in image layers

### Step 3 — Triage IaC Findings

Organize IaC findings by category:

| Category | Examples | Impact |
|----------|----------|--------|
| Secrets in code | Hardcoded AWS keys, database passwords in tfvars | Credential exposure |
| Overprivileged IAM | Wildcard `*` actions, `AdministratorAccess` policies | Privilege escalation |
| Public exposure | Public S3 buckets, open security groups `0.0.0.0/0` | Data breach |
| Missing encryption | Unencrypted RDS, S3 without SSE, EBS without encryption | Data at rest exposure |
| Logging disabled | CloudTrail off, VPC flow logs missing, access logging off | Audit gap |
| Network misconfig | Overly permissive security groups, missing NACLs | Lateral movement |

## Provider Deep Dives

Based on providers detected in Phase 0, read the relevant sub-file(s) below before proceeding to Phase B. These provide provider-specific attack surfaces and Ensphere CLI commands:

| Provider | Sub-file | Content |
|----------|----------|---------|
| AWS | [methodology/07a-aws.md](methodology/07a-aws.md) | Lambda, API Gateway, DynamoDB, SQS/SNS, Cognito, S3 advanced, IAM escalation, ECS/EKS, RDS |
| GCP | [methodology/07b-gcp.md](methodology/07b-gcp.md) | Cloud Functions, Cloud Run, Firestore, Pub/Sub, Identity Platform, GCS, IAM, GKE |
| Azure | [methodology/07c-azure.md](methodology/07c-azure.md) | Azure Functions, App Service, Cosmos DB, Service Bus, Azure AD B2C, Blob Storage, RBAC, AKS |
| Kubernetes | [methodology/07d-k8s.md](methodology/07d-k8s.md) | RBAC, pod security standards, network policies, service mesh, secrets, etcd, admission controllers |

### Using Ensphere Cloud Probes

```bash
# Storage security audit
ensphere cloud storage --provider aws --bucket BUCKET --in-scope "aws://ACCOUNT_ID"

# IAM configuration audit
ensphere cloud iam --provider aws --principal ARN --in-scope "aws://ACCOUNT_ID"

# Network security audit
ensphere cloud network --provider aws --in-scope "aws://ACCOUNT_ID"

# Compute (Lambda/Functions) security audit
ensphere cloud compute --provider aws --in-scope "aws://ACCOUNT_ID"

# Logging (CloudTrail/sinks) audit
ensphere cloud logging --provider aws --in-scope "aws://ACCOUNT_ID"

# Secrets management audit
ensphere cloud secrets --provider aws --in-scope "aws://ACCOUNT_ID"

# Parse Prowler/Trivy output into Ensphere vuln types
ensphere cloud parse-prowler ./prowler-output.json --evidence ./evidence.jsonl
ensphere cloud parse-trivy ./trivy-results.json --evidence ./evidence.jsonl
```

## Phase B: Verification & Exploitation

Validate critical findings from Prowler and Trivy with native CLI commands. This phase confirms automated scanner results and tests for exploitability.

### Step 1 — Validate Critical Prowler Findings

For each critical/high Prowler finding, verify with the native CLI:

**AWS verification examples:**
```bash
# Verify public S3 bucket
aws s3api get-bucket-policy-status --bucket BUCKET_NAME
aws s3api get-public-access-block --bucket BUCKET_NAME

# Verify IAM overprivilege
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy-version --policy-arn POLICY_ARN --version-id VERSION

# Verify CloudTrail status
aws cloudtrail get-trail-status --name TRAIL_NAME

# Verify security group rules
aws ec2 describe-security-groups --group-ids SG_ID --query 'SecurityGroups[*].IpPermissions'

# Verify IMDSv1 (allows SSRF → credential theft)
aws ec2 describe-instances --query 'Reservations[*].Instances[*].MetadataOptions'
```

**GCP verification examples:**
```bash
# Verify public storage bucket
gcloud storage buckets describe gs://BUCKET_NAME --format=json | grep -i 'iamConfiguration\|publicAccessPrevention'

# Verify IAM bindings
gcloud projects get-iam-policy PROJECT_ID --format=json

# Verify audit logging (Data Access logs)
gcloud projects get-iam-policy PROJECT_ID --format=json | grep -A10 'auditConfigs'

# Verify firewall rules
gcloud compute firewall-rules list --project=PROJECT_ID --format=json --filter="direction=INGRESS AND allowed[0].IPProtocol=tcp"
```

**Azure verification examples:**
```bash
# Verify storage account access
az storage account show --name ACCOUNT_NAME --query '{publicAccess:allowBlobPublicAccess,httpsOnly:enableHttpsTrafficOnly}'

# Verify NSG rules
az network nsg list --query '[].{name:name,rules:securityRules[?access==`Allow` && direction==`Inbound`]}'

# Verify diagnostic settings (logging)
az monitor diagnostic-settings list --resource RESOURCE_ID
```

**Kubernetes verification examples:**
```bash
# Verify RBAC — overprivileged service accounts
kubectl get clusterrolebindings -o json | grep -A5 'cluster-admin'

# Verify privileged pods
kubectl get pods --all-namespaces -o json | grep -c '"privileged": true'

# Verify network policies
kubectl get networkpolicies --all-namespaces

# Verify exposed dashboards/services
kubectl get services --all-namespaces --field-selector spec.type=LoadBalancer
```

### Step 2 — Test Storage Access

For each cloud storage resource flagged as public or permissive:

```bash
# AWS: attempt anonymous access
aws s3 ls s3://BUCKET_NAME --no-sign-request 2>/dev/null && echo "PUBLIC: anonymous list succeeded"
aws s3 cp s3://BUCKET_NAME/test-file /dev/null --no-sign-request 2>/dev/null && echo "PUBLIC: anonymous read succeeded"

# GCP: attempt anonymous access
curl -s "https://storage.googleapis.com/BUCKET_NAME/" | head -20

# Azure: attempt anonymous access
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list" | head -20
```

Log evidence for any successful anonymous access using `ensphere evidence log`.

### Step 3 — Test IAM Escalation Paths

For each overprivileged IAM entity identified:

**AWS:**
```bash
# Check for iam:PassRole + lambda:CreateFunction (privilege escalation path)
aws iam simulate-principal-policy --policy-source-arn ARN --action-names iam:PassRole lambda:CreateFunction

# Check for sts:AssumeRole to higher-privilege roles
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS]]'
```

**GCP:**
```bash
# Check for setIamPolicy permission (self-escalation)
gcloud projects get-iam-policy PROJECT_ID --format=json | grep -B2 'setIamPolicy'

# Check for service account impersonation
gcloud iam service-accounts list --format=json
```

### Step 4 — Serverless and Data Service Verification

Prowler has limited coverage of serverless and managed database configurations. Use native CLIs to check these critical areas:

**AWS Serverless:**
```bash
# Lambda functions with public access or overprivileged roles
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Role:Role,Runtime:Runtime}'
aws lambda get-policy --function-name FUNCTION_NAME 2>/dev/null  # check resource-based policy

# API Gateway — check for missing authorization
aws apigateway get-rest-apis --query 'items[*].{id:id,name:name}'
```

**Managed Databases:**
```bash
# AWS: RDS public accessibility, encryption, snapshot sharing
aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Public:PubliclyAccessible,Encrypted:StorageEncrypted,Engine:Engine}'
aws rds describe-db-snapshots --query 'DBSnapshots[?contains(DBSnapshotAttributes[].AttributeName,`restore`)]'

# GCP: Cloud SQL public IP, SSL enforcement
gcloud sql instances list --format=json --project=PROJECT_ID

# Azure: SQL server firewall rules (0.0.0.0 = allow all Azure)
az sql server firewall-rule list --server SERVER_NAME --resource-group RG_NAME
```

**Secrets and KMS:**
```bash
# AWS: KMS key policies, unrotated keys, Secrets Manager rotation
aws kms list-keys --query 'Keys[*].KeyId'
aws kms get-key-rotation-status --key-id KEY_ID
aws secretsmanager list-secrets --query 'SecretList[*].{Name:Name,RotationEnabled:RotationEnabled,LastRotated:LastRotatedDate}'

# GCP: KMS key rotation, Secret Manager rotation
gcloud kms keys list --location=LOCATION --keyring=KEYRING --format=json
gcloud secrets list --format=json --project=PROJECT_ID

# Azure: Key Vault soft delete, purge protection
az keyvault list --query '[].{name:name,softDelete:properties.enableSoftDelete,purgeProtection:properties.enablePurgeProtection}'
```

### Step 5 — Cross-Correlate with Web Findings

**This is one of the highest-value steps in the cloud session.** Cross-reference cloud findings with vulnerabilities from web sessions 01-06:

| Web Finding | Cloud Finding | Chained Impact |
|-------------|--------------|----------------|
| SSRF (Session 06) | IMDSv1 enabled (EC2) | SSRF → metadata → IAM credentials → account takeover |
| SSRF (Session 06) | Metadata service accessible | SSRF → cloud credential theft |
| LFI (Session 02) | AWS credentials in env vars | LFI → `.env` read → AWS key extraction |
| Injection (Session 02) | Database in public subnet | SQLi → RDS credential extraction → direct DB access |
| Auth bypass (Session 03) | Overprivileged app IAM role | Auth bypass → application role → cloud resource access |

Read evidence from:
- `ensphere-pentest/06-ssrf/report.md` — SSRF findings that may chain with cloud metadata
- `ensphere-pentest/02-injection/report.md` — injection findings that may expose cloud credentials
- `ensphere-pentest/03-auth/report.md` — auth findings that may escalate via cloud IAM

### Step 6 — Test Credential Exposure

Check for cloud credentials exposed through various vectors:

```bash
# Environment variables (if application access is available)
# Look for: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GOOGLE_APPLICATION_CREDENTIALS, AZURE_CLIENT_SECRET
# These may have been discovered in Sessions 01-02

# Metadata service (if SSRF was confirmed in Session 06)
# IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/
# IMDSv2 requires token — test if PUT to /latest/api/token works

# Secrets manager audit
aws secretsmanager list-secrets --query 'SecretList[*].{Name:Name,LastAccessed:LastAccessedDate}'
gcloud secrets list --format=json
az keyvault list --query '[].{name:name,location:location}'
```

### Compliance Mapping

For each cloud finding, look up compliance mappings using the cloud-specific vuln types:

```bash
ensphere compliance cloud_iam        # IAM overprivilege, missing MFA, unused credentials
ensphere compliance cloud_storage    # public buckets, missing encryption, permissive ACLs
ensphere compliance cloud_network    # open security groups, public subnets, missing flow logs
ensphere compliance cloud_compute    # IMDSv1, public instances, missing patching
ensphere compliance cloud_logging    # disabled audit logs, missing alerting
ensphere compliance cloud_k8s        # RBAC misconfig, privileged pods, missing network policies
ensphere compliance cloud_secrets    # hardcoded keys, missing rotation
ensphere compliance iac_misconfig    # IaC template misconfigurations
```

Include the affected framework controls (OWASP Top 10, PCI-DSS, SOC 2, ISO 27001) in each finding.

### Evidence Logging

Log all cloud findings to evidence using `ensphere evidence log`:

```bash
ensphere evidence log \
  --probe-type cloud_config \
  --technique prowler_audit \
  --url "aws://account-id/resource-arn" \
  --result confirmed \
  --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "S3 bucket publicly accessible — anonymous list/read confirmed"
```

Use `probe-type` values: `cloud_config`, `cloud_iam`, `cloud_storage`, `cloud_network`, `cloud_compute`, `cloud_logging`, `iac_misconfig`, `cloud_k8s`.
Use `technique` values: `prowler_audit`, `trivy_scan`, `cli_verification`, `anonymous_access`, `iam_escalation`, `metadata_access`, `credential_exposure`.

## Report Format

Write to `ensphere-pentest/07-cloud/report.md`:

### Provider Summary
Table: Provider | Account/Project | Regions Audited | Tools Used | Checks Run | Findings (Critical/High/Medium/Low)

### Critical Findings
For each critical/high finding:
- Finding ID, provider, resource, severity
- Prowler/Trivy check ID
- Verification method and result
- Business impact
- Cross-correlation with web findings (if applicable)
- Remediation recommendation

### IAM Findings
- Overprivileged roles/users/service accounts
- Unused credentials
- Missing MFA
- Escalation paths identified

### Storage Findings
- Public buckets/containers/blobs
- Missing encryption (at rest, in transit)
- Permissive ACLs
- Sensitive data exposure risk

### Network Findings
- Open security groups / firewall rules
- Public subnets with sensitive resources
- Missing VPC flow logs
- Exposed management interfaces

### Compute Findings
- IMDSv1 enabled (SSRF → credential theft risk)
- Public instances
- Missing patching / outdated AMIs
- Overprivileged instance profiles

### Serverless Findings
- Lambda/Cloud Functions with public invocation policies
- Overprivileged execution roles
- API Gateway missing authorization
- Event source mapping hijack risk

### Data Service Findings
- Publicly accessible RDS/Cloud SQL/Azure SQL instances
- Shared snapshots (publicly accessible RDS snapshots)
- Missing encryption at rest
- Missing SSL/TLS enforcement

### Secrets & Encryption Findings
- KMS keys with overly permissive policies
- Missing key rotation
- Secrets Manager entries without rotation enabled
- Hardcoded credentials in Lambda environment variables

### Logging & Monitoring Findings
- Disabled CloudTrail / audit logs
- Missing alerting
- Insufficient log retention
- Gaps in monitoring coverage

### Kubernetes Findings (if applicable)
- RBAC misconfigurations
- Privileged containers
- Missing network policies
- Exposed dashboards/services
- Pod security violations

### IaC Findings (White-Box Only)
- Hardcoded secrets
- Misconfigured resources in templates
- Drift between IaC and deployed state
- Missing security controls in templates

### Chained Findings
- Web + Cloud attack paths (SSRF → metadata, LFI → credentials, injection → DB access)
- Multi-step escalation chains

### Secure by Design
Table: Category | Check | Provider | Defense Mechanism | Verdict

### Skipped Checks
Table: Tool | Reason | Impact on Coverage
