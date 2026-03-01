# AWS Deep Dive — Session 07 Sub-file

Provider-specific attack surfaces, verification commands, and Ensphere integration for Amazon Web Services. Read from Session 07 (Cloud Security) when AWS is in scope.

---

## Lambda

### Attack Surface

Lambda functions may expose unauthenticated endpoints through function URLs or misconfigured API Gateway integrations. Environment variables frequently contain database credentials, API keys, and third-party secrets in plaintext. Resource-based policies can grant cross-account invocation. Lambda layers may introduce supply-chain risk when sourced from untrusted publishers.

### Verification Commands

```bash
# List all Lambda functions with runtime, role, and memory
aws lambda list-functions \
  --query 'Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role,Timeout:Timeout,Memory:MemorySize}'

# Check for function URLs (unauthenticated by default if AuthType=NONE)
aws lambda list-function-url-configs --function-name FUNCTION_NAME

# Dump environment variables (may contain secrets)
aws lambda get-function-configuration --function-name FUNCTION_NAME \
  --query '{Env:Environment.Variables,KMSKey:KMSKeyArn}'

# Check resource-based policy (cross-account invocation, wildcard principals)
aws lambda get-policy --function-name FUNCTION_NAME 2>/dev/null

# List layers (supply-chain risk)
aws lambda list-layers --query 'Layers[*].{Name:LayerName,Version:LatestMatchingVersion.Version}'
aws lambda get-layer-version --layer-name LAYER_NAME --version-number VERSION
```

### Ensphere Integration

```bash
# IAM audit for Lambda execution role
ensphere cloud iam --provider aws \
  --principal arn:aws:iam::ACCOUNT_ID:role/LAMBDA_ROLE \
  --in-scope "aws://ACCOUNT_ID"

# Serverless compute audit (Lambda functions, public URLs, env var secret patterns)
ensphere cloud compute --provider aws --in-scope "aws://ACCOUNT_ID"

# Audit logging (CloudTrail trails, multi-region, log validation)
ensphere cloud logging --provider aws --in-scope "aws://ACCOUNT_ID"

# Secrets management (Secrets Manager rotation, KMS key usage)
ensphere cloud secrets --provider aws --in-scope "aws://ACCOUNT_ID"

# Evidence logging
ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "aws://ACCOUNT_ID/lambda/FUNCTION_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Lambda function URL with AuthType=NONE — unauthenticated invocation"
```

---

## API Gateway

### Attack Surface

API Gateway endpoints may lack authorizer configuration on individual methods, allowing unauthenticated access even when an authorizer exists on other routes. Stage variables can leak internal hostnames or credentials. WAF associations may be missing, leaving APIs exposed to injection and abuse. API keys alone do not constitute authorization and are trivially leaked.

### Verification Commands

```bash
# List all REST APIs
aws apigateway get-rest-apis --query 'items[*].{id:id,name:name,endpoint:endpointConfiguration.types}'

# Get resources and methods for an API (look for missing authorization)
aws apigateway get-resources --rest-api-id API_ID \
  --query 'items[*].{path:path,methods:resourceMethods}'

# Check method authorization type (NONE = unauthenticated)
aws apigateway get-method --rest-api-id API_ID --resource-id RESOURCE_ID --http-method GET

# Check stage variables (may contain secrets)
aws apigateway get-stage --rest-api-id API_ID --stage-name prod \
  --query '{variables:variables,logging:methodSettings}'

# Check WAF association
aws wafv2 get-web-acl-for-resource \
  --resource-arn arn:aws:apigateway:REGION::/restapis/API_ID/stages/prod 2>/dev/null

# List HTTP APIs (API Gateway v2)
aws apigatewayv2 get-apis --query 'Items[*].{ApiId:ApiId,Name:Name,Protocol:ProtocolType}'

# Check routes on HTTP API for missing authorization
aws apigatewayv2 get-routes --api-id API_ID \
  --query 'Items[*].{Key:RouteKey,AuthType:AuthorizationType}'
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_network --technique cli_verification \
  --url "aws://ACCOUNT_ID/apigateway/API_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "API Gateway method GET /admin has AuthorizationType=NONE"
```

---

## DynamoDB

### Attack Surface

DynamoDB tables with overpermissive IAM policies allow full table scans, exposing all data. Backups and exports may be accessible to unauthorized principals. Point-in-time recovery (PITR) if disabled means ransomware or accidental deletion is unrecoverable. Tables without encryption use AWS-owned keys, preventing audit of key access.

### Verification Commands

```bash
# List all tables
aws dynamodb list-tables

# Describe table encryption and PITR status
aws dynamodb describe-table --table-name TABLE_NAME \
  --query '{SSE:Table.SSEDescription,PITR:Table.PointInTimeRecoveryDescription}'

# Check continuous backups (PITR)
aws dynamodb describe-continuous-backups --table-name TABLE_NAME

# List backups (check for exposed exports)
aws dynamodb list-backups --table-name TABLE_NAME

# Check if table allows full scan (test with IAM simulation)
aws iam simulate-principal-policy \
  --policy-source-arn ARN \
  --action-names dynamodb:Scan dynamodb:GetItem dynamodb:Query

# List global tables (cross-region replication)
aws dynamodb list-global-tables
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique cli_verification \
  --url "aws://ACCOUNT_ID/dynamodb/TABLE_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "DynamoDB table uses AWS-owned CMK, PITR disabled"
```

---

## SQS / SNS

### Attack Surface

SQS queue policies with wildcard principals (`"*"`) allow any AWS account to send or receive messages. SNS topics with open subscription policies enable message injection or information disclosure. Cross-account access without condition keys permits unauthorized subscribe/publish. Dead-letter queues may accumulate sensitive messages without encryption.

### Verification Commands

```bash
# List all SQS queues
aws sqs list-queues

# Check queue policy for wildcard principals
aws sqs get-queue-attributes --queue-url QUEUE_URL \
  --attribute-names Policy RedrivePolicy KmsMasterKeyId

# List all SNS topics
aws sns list-topics

# Check topic policy
aws sns get-topic-attributes --topic-arn TOPIC_ARN \
  --query '{Policy:Attributes.Policy,KmsMasterKeyId:Attributes.KmsMasterKeyId}'

# List subscriptions for a topic (cross-account endpoints)
aws sns list-subscriptions-by-topic --topic-arn TOPIC_ARN

# Check for unencrypted queues (no KMS key = server-side encryption only with SQS-owned key)
aws sqs get-queue-attributes --queue-url QUEUE_URL --attribute-names SqsManagedSseEnabled KmsMasterKeyId
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_network --technique cli_verification \
  --url "aws://ACCOUNT_ID/sqs/QUEUE_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "SQS queue policy allows Principal:* with no condition restrictions"
```

---

## Cognito

### Attack Surface

Cognito user pools may allow self-signup when the application expects admin-only registration. Username enumeration is possible through sign-up and forgot-password flows when `PreventUserExistenceErrors` is not set to `ENABLED`. Custom auth challenge Lambda triggers may contain logic flaws. ID token claims may not be validated server-side, allowing attribute manipulation.

### Verification Commands

```bash
# List user pools
aws cognito-idp list-user-pools --max-results 60

# Describe user pool settings
aws cognito-idp describe-user-pool --user-pool-id POOL_ID \
  --query '{SelfSignUp:UserPoolAddOns,MFA:MfaConfiguration,Policies:Policies,Lambda:LambdaConfig,PreventEnumeration:UserPoolAddOns}'

# Check app client settings (implicit grant, allowed scopes)
aws cognito-idp list-user-pool-clients --user-pool-id POOL_ID
aws cognito-idp describe-user-pool-client --user-pool-id POOL_ID --client-id CLIENT_ID \
  --query '{AllowedFlows:ExplicitAuthFlows,Scopes:AllowedOAuthScopes,CallbackURLs:CallbackURLs}'

# List identity pools (federated identities)
aws cognito-identity list-identity-pools --max-results 60

# Check identity pool roles (unauthenticated role may be overprivileged)
aws cognito-identity get-identity-pool-roles --identity-pool-id POOL_ID
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique cli_verification \
  --url "aws://ACCOUNT_ID/cognito/POOL_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Cognito identity pool unauthenticated role has s3:GetObject on sensitive bucket"
```

---

## S3 Advanced

### Attack Surface

Beyond basic public bucket checks (covered by Prowler), advanced S3 risks include pre-signed URL generation with excessive TTL, bucket policies with wildcard actions, object-level ACLs granting public-read on individual objects even when block public access is set at account level, and permissive CORS configurations enabling credential-bearing cross-origin reads.

### Verification Commands

```bash
# Comprehensive bucket security check
ensphere cloud storage --provider aws --bucket BUCKET_NAME --in-scope "aws://ACCOUNT_ID"

# Check bucket policy for wildcard actions or principals
aws s3api get-bucket-policy --bucket BUCKET_NAME 2>/dev/null

# Check account-level public access block
aws s3control get-public-access-block --account-id ACCOUNT_ID

# Check bucket-level public access block
aws s3api get-public-access-block --bucket BUCKET_NAME

# Check CORS configuration
aws s3api get-bucket-cors --bucket BUCKET_NAME 2>/dev/null

# Check object-level ACLs on specific objects
aws s3api get-object-acl --bucket BUCKET_NAME --key KEY_NAME

# Check bucket versioning (tampering/deletion risk if disabled)
aws s3api get-bucket-versioning --bucket BUCKET_NAME

# Check bucket encryption (default SSE)
aws s3api get-bucket-encryption --bucket BUCKET_NAME

# Check access logging
aws s3api get-bucket-logging --bucket BUCKET_NAME

# Test anonymous access
aws s3 ls s3://BUCKET_NAME --no-sign-request 2>/dev/null && echo "PUBLIC: list succeeded"
aws s3 cp s3://BUCKET_NAME/index.html /dev/null --no-sign-request 2>/dev/null && echo "PUBLIC: read succeeded"
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique anonymous_access \
  --url "aws://ACCOUNT_ID/s3/BUCKET_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "S3 bucket allows anonymous ListBucket via --no-sign-request"
```

---

## IAM Escalation Paths

### Attack Surface

AWS IAM privilege escalation exploits legitimate permissions in unintended combinations. An attacker with `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` can execute code as any role. `iam:CreatePolicyVersion` allows writing a new policy version with `AdministratorAccess`. `iam:AttachUserPolicy` enables self-granting admin. `sts:AssumeRole` chains can traverse trust boundaries across accounts.

### Verification Commands

```bash
# Audit IAM principal for escalation paths
ensphere cloud iam --provider aws \
  --principal arn:aws:iam::ACCOUNT_ID:user/USERNAME \
  --in-scope "aws://ACCOUNT_ID"

# PassRole + Lambda escalation
aws iam simulate-principal-policy --policy-source-arn USER_ARN \
  --action-names iam:PassRole lambda:CreateFunction lambda:InvokeFunction

# CreatePolicyVersion escalation
aws iam simulate-principal-policy --policy-source-arn USER_ARN \
  --action-names iam:CreatePolicyVersion

# AttachUserPolicy / AttachRolePolicy escalation
aws iam simulate-principal-policy --policy-source-arn USER_ARN \
  --action-names iam:AttachUserPolicy iam:AttachRolePolicy iam:PutUserPolicy iam:PutRolePolicy

# AssumeRole chain analysis
aws iam list-roles --query 'Roles[*].{Name:RoleName,Trust:AssumeRolePolicyDocument}' | head -100

# Check for wildcard resource in policies
aws iam get-policy-version --policy-arn POLICY_ARN --version-id VERSION_ID \
  --query 'PolicyVersion.Document'

# Check for unused credentials (access keys not rotated, console password not used)
aws iam generate-credential-report
aws iam get-credential-report --output text --query 'Content' | base64 -d | head -20

# Check for MFA status
aws iam list-users --query 'Users[*].{User:UserName,Created:CreateDate}'
aws iam list-mfa-devices --user-name USERNAME
```

### Known Escalation Combinations

| Permissions | Escalation Path |
|------------|-----------------|
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin role, invoke it |
| `iam:CreatePolicyVersion` | Write new policy version with `*:*` |
| `iam:AttachUserPolicy` or `iam:AttachRolePolicy` | Attach `AdministratorAccess` to self |
| `iam:PutUserPolicy` or `iam:PutRolePolicy` | Write inline policy with `*:*` |
| `sts:AssumeRole` (cross-account trust) | Pivot to higher-privilege account |
| `iam:CreateAccessKey` | Create new access key for another user |
| `iam:UpdateLoginProfile` | Reset another user console password |
| `lambda:UpdateFunctionCode` + existing admin-role Lambda | Replace code, invoke to escalate |
| `ec2:RunInstances` + `iam:PassRole` | Launch instance with admin instance profile |
| `glue:CreateDevEndpoint` + `iam:PassRole` | Create Glue endpoint with admin role |

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique iam_escalation \
  --url "aws://ACCOUNT_ID/iam/user/USERNAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "User has iam:PassRole + lambda:CreateFunction — escalation to any Lambda-assumable role"
```

---

## ECS / EKS

### Attack Surface

ECS task definitions may embed secrets in environment variables rather than using Secrets Manager references. Task IAM roles may be overprivileged. ECS Exec access (if enabled) allows interactive shell into running containers. EKS pod identity and IRSA (IAM Roles for Service Accounts) misconfigurations can grant cluster workloads excessive AWS permissions.

### Verification Commands

```bash
# List ECS clusters
aws ecs list-clusters

# List task definitions (check for secrets in environment)
aws ecs list-task-definitions --sort DESC --max-items 20
aws ecs describe-task-definition --task-definition TASK_DEF \
  --query '{Containers:taskDefinition.containerDefinitions[*].{Name:name,Env:environment,Secrets:secrets},TaskRole:taskDefinition.taskRoleArn,ExecRole:taskDefinition.executionRoleArn}'

# Check if ECS Exec is enabled (interactive shell access)
aws ecs describe-services --cluster CLUSTER --services SERVICE \
  --query 'services[*].{Name:serviceName,ExecEnabled:enableExecuteCommand}'

# List EKS clusters
aws eks list-clusters

# Check EKS cluster endpoint access (public vs private)
aws eks describe-cluster --name CLUSTER_NAME \
  --query '{Endpoint:cluster.endpoint,Access:cluster.resourcesVpcConfig.{Public:endpointPublicAccess,Private:endpointPrivateAccess,PublicCIDRs:publicAccessCidrs},Logging:cluster.logging,Encryption:cluster.encryptionConfig}'

# Check EKS node groups for instance types and AMI
aws eks list-nodegroups --cluster-name CLUSTER_NAME
aws eks describe-nodegroup --cluster-name CLUSTER --nodegroup-name NODEGROUP \
  --query '{InstanceTypes:nodegroup.instanceTypes,AmiType:nodegroup.amiType,RemoteAccess:nodegroup.remoteAccess}'

# Check IRSA (IAM Roles for Service Accounts) OIDC provider
aws eks describe-cluster --name CLUSTER_NAME --query 'cluster.identity.oidc'
aws iam list-open-id-connect-providers
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "aws://ACCOUNT_ID/ecs/CLUSTER/SERVICE" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "ECS task definition contains plaintext DB_PASSWORD in environment variables"
```

---

## RDS

### Attack Surface

RDS instances marked `PubliclyAccessible=true` with permissive security groups are directly reachable from the internet. Public DB snapshots can be copied by any AWS account. IAM database authentication may not be enabled, relying solely on password-based access. Parameter groups may have `log_statement` disabled, preventing audit of queries.

### Verification Commands

```bash
# List RDS instances with security posture
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,Engine:Engine,Public:PubliclyAccessible,Encrypted:StorageEncrypted,MultiAZ:MultiAZ,IAMAuth:IAMDatabaseAuthenticationEnabled,Endpoint:Endpoint.Address}'

# Check for public snapshots
aws rds describe-db-snapshots --snapshot-type public 2>/dev/null
aws rds describe-db-snapshot-attributes --db-snapshot-identifier SNAPSHOT_ID \
  --query 'DBSnapshotAttributesResult.DBSnapshotAttributes'

# Check automated backups retention
aws rds describe-db-instances \
  --query 'DBInstances[*].{ID:DBInstanceIdentifier,BackupRetention:BackupRetentionPeriod}'

# Check parameter group settings (logging, SSL)
aws rds describe-db-parameters --db-parameter-group-name PARAM_GROUP \
  --query 'Parameters[?ParameterName==`log_statement` || ParameterName==`rds.force_ssl`].{Name:ParameterName,Value:ParameterValue}'

# Check security group attached to RDS
aws rds describe-db-instances --db-instance-identifier INSTANCE_ID \
  --query 'DBInstances[0].VpcSecurityGroups[*].VpcSecurityGroupId'
# Then check each security group for open ingress
aws ec2 describe-security-groups --group-ids SG_ID \
  --query 'SecurityGroups[*].IpPermissions[?FromPort==`5432` || FromPort==`3306`]'

# Check SSL enforcement
aws rds describe-db-instances --db-instance-identifier INSTANCE_ID \
  --query 'DBInstances[0].{CACert:CACertificateIdentifier}'
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique cli_verification \
  --url "aws://ACCOUNT_ID/rds/INSTANCE_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "RDS instance publicly accessible with security group allowing 0.0.0.0/0 on port 5432"
```

---

## Cross-Correlation with Web Findings

AWS-specific attack chains that combine web vulnerabilities (Sessions 01-06) with cloud misconfiguration:

| Web Finding | AWS Finding | Combined Attack |
|-------------|-------------|-----------------|
| SSRF (Session 06) | IMDSv1 on EC2 | SSRF to `169.254.169.254/latest/meta-data/iam/security-credentials/ROLE` to steal temporary credentials |
| SSRF (Session 06) | ECS task metadata | SSRF to `169.254.170.2/v2/credentials/GUID` to steal task credentials |
| LFI (Session 02) | Lambda env vars | LFI to read `/proc/self/environ` to extract AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY |
| SQLi (Session 02) | RDS in public subnet | SQLi to extract connection strings, then direct DB access from internet |
| Auth bypass (Session 03) | Overprivileged app role | Auth bypass grants access to application that uses admin-level IAM role |
| XSS (Session 05) | Cognito tokens in JS | XSS to steal Cognito ID/access tokens from localStorage/sessionStorage |

### IMDSv1 Verification

```bash
# Check all EC2 instances for IMDSv1 (HttpTokens != required means v1 is enabled)
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name,IMDS:MetadataOptions.{HttpTokens:HttpTokens,HttpEndpoint:HttpEndpoint}}'
```

If SSRF was confirmed in Session 06 and IMDSv1 is enabled, this is a critical chained finding.

```bash
ensphere evidence log \
  --probe-type cloud_compute --technique metadata_access \
  --url "aws://ACCOUNT_ID/ec2/INSTANCE_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "IMDSv1 enabled on instance hosting SSRF-vulnerable application — credential theft confirmed"
```

---

## Compliance Mapping

For each AWS finding, use Ensphere to look up applicable compliance controls:

```bash
ensphere compliance cloud_iam        # IAM overprivilege, MFA, credential rotation
ensphere compliance cloud_storage    # S3 public access, encryption, ACLs
ensphere compliance cloud_network    # Security groups, VPC flow logs, NACLs
ensphere compliance cloud_compute    # IMDSv1, patching, instance profiles
ensphere compliance cloud_logging    # CloudTrail, Config, GuardDuty
ensphere compliance cloud_secrets    # Secrets Manager rotation, KMS key policies
```
