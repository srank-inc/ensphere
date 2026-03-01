# GCP Deep Dive — Session 07 Sub-file

Provider-specific attack surfaces, verification commands, and Ensphere integration for Google Cloud Platform. Read from Session 07 (Cloud Security) when GCP is in scope.

---

## Cloud Functions

### Attack Surface

Cloud Functions (1st and 2nd gen) may allow unauthenticated invocation when the `allUsers` or `allAuthenticatedUsers` member is granted the `roles/cloudfunctions.invoker` role. Environment variables and build-time secrets may contain service account keys, database credentials, or API tokens. Functions running with the default compute service account inherit broad project-level permissions.

### Verification Commands

```bash
# List all Cloud Functions (2nd gen / Cloud Run-backed)
gcloud functions list --format=json --project=PROJECT_ID

# Check IAM policy on a function (look for allUsers invoker binding)
gcloud functions get-iam-policy FUNCTION_NAME --region=REGION --gen2 \
  --format=json --project=PROJECT_ID

# Describe function configuration (runtime, env vars, service account)
gcloud functions describe FUNCTION_NAME --region=REGION --gen2 \
  --format=json --project=PROJECT_ID

# Check environment variables specifically
gcloud functions describe FUNCTION_NAME --region=REGION --gen2 \
  --format='value(serviceConfig.environmentVariables)' --project=PROJECT_ID

# Check which service account the function uses
gcloud functions describe FUNCTION_NAME --region=REGION --gen2 \
  --format='value(serviceConfig.serviceAccountEmail)' --project=PROJECT_ID
```

### Ensphere Integration

```bash
ensphere cloud iam --provider gcp \
  --principal FUNCTION_SA@PROJECT_ID.iam.gserviceaccount.com \
  --in-scope "gcp://PROJECT_ID"

# Serverless compute audit (Cloud Functions + Cloud Run, public URLs)
ensphere cloud compute --provider gcp --in-scope "gcp://PROJECT_ID"

# Audit logging (logging sinks, active/disabled status)
ensphere cloud logging --provider gcp --in-scope "gcp://PROJECT_ID"

# Secrets management (Secret Manager, rotation policy)
ensphere cloud secrets --provider gcp --in-scope "gcp://PROJECT_ID"

ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "gcp://PROJECT_ID/functions/FUNCTION_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Cloud Function allows allUsers invocation — unauthenticated access"
```

---

## Cloud Run

### Attack Surface

Cloud Run services may allow unauthenticated ingress. Services running with the default compute service account have broad permissions. Revision environment variables may embed secrets. VPC connector misconfigurations can expose internal resources. Binary authorization may not be enforced, allowing deployment of unverified container images.

### Verification Commands

```bash
# List all Cloud Run services
gcloud run services list --format=json --project=PROJECT_ID

# Check IAM policy (allUsers = unauthenticated)
gcloud run services get-iam-policy SERVICE_NAME --region=REGION \
  --format=json --project=PROJECT_ID

# Describe service (env vars, service account, ingress settings)
gcloud run services describe SERVICE_NAME --region=REGION \
  --format=json --project=PROJECT_ID

# Check ingress settings (all, internal, internal-and-cloud-load-balancing)
gcloud run services describe SERVICE_NAME --region=REGION \
  --format='value(spec.template.metadata.annotations["run.googleapis.com/ingress"])' \
  --project=PROJECT_ID

# Check VPC connector
gcloud run services describe SERVICE_NAME --region=REGION \
  --format='value(spec.template.metadata.annotations["run.googleapis.com/vpc-access-connector"])' \
  --project=PROJECT_ID

# Check binary authorization policy
gcloud container binauthz policy export --project=PROJECT_ID
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "gcp://PROJECT_ID/run/SERVICE_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Cloud Run service allows allUsers invocation with ingress=all"
```

---

## Firestore

### Attack Surface

Firestore security rules are the sole access control mechanism for client-side access. Overly permissive rules (e.g., `allow read, write: if true`) expose all data to any authenticated or unauthenticated user. Rules that check only `request.auth != null` without validating specific user IDs or claims allow any authenticated user to read/modify any document. Firestore exports to GCS may be publicly accessible.

### Verification Commands

```bash
# List Firestore databases
gcloud firestore databases list --project=PROJECT_ID --format=json

# Export security rules (requires Firebase CLI or REST API)
# Firestore rules are not directly accessible via gcloud — use the Firebase REST API
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://firebaserules.googleapis.com/v1/projects/PROJECT_ID/rulesets" | head -50

# Check Firestore indexes (information disclosure about data structure)
gcloud firestore indexes composite list --project=PROJECT_ID --format=json

# Check Firestore export operations (backup exposure)
gcloud firestore operations list --project=PROJECT_ID --format=json 2>/dev/null
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique cli_verification \
  --url "gcp://PROJECT_ID/firestore" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Firestore rules allow any authenticated user to read all collections"
```

---

## Pub/Sub

### Attack Surface

Pub/Sub topics with permissive IAM policies allow cross-project publish or subscribe. Subscriptions without message encryption expose data in transit within GCP. Dead-letter topics may accumulate sensitive messages. Push subscriptions to HTTP endpoints may be intercepted if not using HTTPS with authentication tokens.

### Verification Commands

```bash
# List all topics
gcloud pubsub topics list --format=json --project=PROJECT_ID

# Check topic IAM policy (look for allUsers or allAuthenticatedUsers)
gcloud pubsub topics get-iam-policy TOPIC_NAME --format=json --project=PROJECT_ID

# List subscriptions
gcloud pubsub subscriptions list --format=json --project=PROJECT_ID

# Check subscription configuration (push endpoint, dead letter, expiry)
gcloud pubsub subscriptions describe SUBSCRIPTION_NAME \
  --format=json --project=PROJECT_ID

# Check for push subscriptions to HTTP (non-HTTPS) endpoints
gcloud pubsub subscriptions list \
  --format='table(name,pushConfig.pushEndpoint)' --project=PROJECT_ID
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_network --technique cli_verification \
  --url "gcp://PROJECT_ID/pubsub/TOPIC_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Pub/Sub topic grants allAuthenticatedUsers roles/pubsub.publisher"
```

---

## Identity Platform

### Attack Surface

Identity Platform (Firebase Auth) may allow self-registration when the application assumes admin-controlled provisioning. Email enumeration is possible through the sign-up and password reset flows. Multi-tenancy misconfigurations can allow cross-tenant access. Custom token generation without proper claims validation enables privilege escalation. Anonymous auth, if enabled, may grant access to Firestore or Cloud Storage resources.

### Verification Commands

```bash
# List Identity Platform tenants
gcloud identity-platform tenants list --project=PROJECT_ID --format=json 2>/dev/null

# Check Identity Platform configuration
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://identitytoolkit.googleapis.com/v2/projects/PROJECT_ID/config"

# Check allowed sign-in providers
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://identitytoolkit.googleapis.com/v2/projects/PROJECT_ID/defaultSupportedIdpConfigs"

# Check if anonymous auth is enabled
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://identitytoolkit.googleapis.com/admin/v2/projects/PROJECT_ID/config" \
  | grep -i anonymous
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique cli_verification \
  --url "gcp://PROJECT_ID/identity-platform" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Identity Platform allows anonymous auth — anonymous users can access Firestore"
```

---

## GCS (Google Cloud Storage)

### Attack Surface

GCS buckets may allow `allUsers` or `allAuthenticatedUsers` access through IAM bindings or legacy ACLs. Uniform bucket-level access may not be enabled, leaving object-level ACLs as a secondary attack surface. CORS configurations may allow credential-bearing cross-origin requests. Signed URLs with excessive duration expose data beyond intended sharing windows. Bucket lock and retention policies may be absent, allowing evidence tampering.

### Verification Commands

```bash
# Comprehensive bucket security check
ensphere cloud storage --provider gcp --bucket BUCKET_NAME --in-scope "gcp://PROJECT_ID"

# Check bucket IAM policy
gcloud storage buckets get-iam-policy gs://BUCKET_NAME --format=json

# Check bucket metadata (location, storage class, public access prevention)
gcloud storage buckets describe gs://BUCKET_NAME --format=json

# Check uniform bucket-level access
gcloud storage buckets describe gs://BUCKET_NAME \
  --format='value(iamConfiguration.uniformBucketLevelAccess.enabled)'

# Check public access prevention
gcloud storage buckets describe gs://BUCKET_NAME \
  --format='value(iamConfiguration.publicAccessPrevention)'

# Check CORS configuration
gcloud storage buckets describe gs://BUCKET_NAME --format='value(cors_config)'

# Check default encryption (CMEK vs Google-managed)
gcloud storage buckets describe gs://BUCKET_NAME --format='value(default_kms_key)'

# Test anonymous access
curl -s "https://storage.googleapis.com/BUCKET_NAME/" | head -20
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/BUCKET_NAME/index.html"

# Check retention policy and bucket lock
gcloud storage buckets describe gs://BUCKET_NAME \
  --format='value(retention_policy)'
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique anonymous_access \
  --url "gcp://PROJECT_ID/gcs/BUCKET_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "GCS bucket grants allUsers roles/storage.objectViewer — anonymous read confirmed"
```

---

## IAM Bindings

### Attack Surface

GCP IAM uses a binding model where roles are granted to members on resources. Dangerous patterns include `setIamPolicy` permission on projects or organizations (self-escalation), service account impersonation via `iam.serviceAccounts.actAs`, service account key creation, and primitive roles (`roles/editor`, `roles/owner`) that grant broad access. The `allUsers` and `allAuthenticatedUsers` special members, when bound at the project level, expose all resources.

### Verification Commands

```bash
# Audit a service account
ensphere cloud iam --provider gcp \
  --principal SA_EMAIL@PROJECT_ID.iam.gserviceaccount.com \
  --in-scope "gcp://PROJECT_ID"

# Get project-level IAM policy (all bindings)
gcloud projects get-iam-policy PROJECT_ID --format=json

# Check for overprivileged bindings (primitive roles)
gcloud projects get-iam-policy PROJECT_ID --format=json \
  --flatten='bindings[].members' \
  --filter='bindings.role:(roles/owner OR roles/editor)'

# Check for allUsers or allAuthenticatedUsers bindings
gcloud projects get-iam-policy PROJECT_ID --format=json \
  --flatten='bindings[].members' \
  --filter='bindings.members:(allUsers OR allAuthenticatedUsers)'

# List service accounts
gcloud iam service-accounts list --format=json --project=PROJECT_ID

# Check service account keys (user-managed keys are high risk)
gcloud iam service-accounts keys list --iam-account=SA_EMAIL --format=json

# Check for setIamPolicy permission (self-escalation)
gcloud projects get-iam-policy PROJECT_ID --format=json \
  --flatten='bindings[].members' \
  --filter='bindings.role:(roles/resourcemanager.projectIamAdmin OR roles/owner)'

# Check for service account impersonation permissions
gcloud iam service-accounts get-iam-policy SA_EMAIL --format=json

# Check organization-level policies (if org access available)
gcloud organizations get-iam-policy ORG_ID --format=json 2>/dev/null
```

### Known Escalation Combinations

| Permission | Escalation Path |
|-----------|-----------------|
| `resourcemanager.projects.setIamPolicy` | Grant self Owner role on project |
| `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` | Deploy function as privileged SA |
| `iam.serviceAccounts.getAccessToken` | Impersonate any SA directly |
| `iam.serviceAccountKeys.create` | Create persistent key for any SA |
| `compute.instances.create` + `iam.serviceAccounts.actAs` | Launch VM with privileged SA |
| `deploymentmanager.deployments.create` | Deploy resources as project SA |
| `cloudbuild.builds.create` | Execute builds as Cloud Build SA |

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique iam_escalation \
  --url "gcp://PROJECT_ID/iam/SA_EMAIL" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Service account has iam.serviceAccountKeys.create on project — can create keys for any SA"
```

---

## GKE

### Attack Surface

GKE clusters with legacy ABAC authorization enabled bypass RBAC entirely. The default compute service account on nodes may have `Editor` role on the project. Workload Identity misconfigurations allow pods to access the node service account via the metadata server. Public cluster endpoints without authorized networks are accessible from the internet. Shielded GKE nodes may not be enabled, allowing boot-level attacks.

### Verification Commands

```bash
# Describe cluster security configuration
gcloud container clusters describe CLUSTER_NAME --zone=ZONE --format=json --project=PROJECT_ID \
  | grep -E '"legacyAbac|workloadIdentityConfig|shieldedNodes|masterAuthorizedNetworks|privateCluster|networkPolicy'

# Check if legacy ABAC is enabled
gcloud container clusters describe CLUSTER_NAME --zone=ZONE \
  --format='value(legacyAbac.enabled)' --project=PROJECT_ID

# Check Workload Identity
gcloud container clusters describe CLUSTER_NAME --zone=ZONE \
  --format='value(workloadIdentityConfig.workloadPool)' --project=PROJECT_ID

# Check master authorized networks
gcloud container clusters describe CLUSTER_NAME --zone=ZONE \
  --format='value(masterAuthorizedNetworksConfig)' --project=PROJECT_ID

# Check node pool configuration
gcloud container node-pools list --cluster=CLUSTER_NAME --zone=ZONE \
  --format=json --project=PROJECT_ID

# Check node service account
gcloud container node-pools describe NODE_POOL --cluster=CLUSTER_NAME --zone=ZONE \
  --format='value(config.serviceAccount)' --project=PROJECT_ID

# Check Binary Authorization policy
gcloud container binauthz policy export --project=PROJECT_ID
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_k8s --technique cli_verification \
  --url "gcp://PROJECT_ID/gke/CLUSTER_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "GKE cluster has legacy ABAC enabled — RBAC policies are not enforced"
```

---

## Cross-Correlation with Web Findings

GCP-specific attack chains combining web vulnerabilities with cloud misconfiguration:

| Web Finding | GCP Finding | Combined Attack |
|-------------|-------------|-----------------|
| SSRF (Session 06) | Metadata server accessible | SSRF to `metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (requires `Metadata-Flavor: Google` header, but proxied SSRF may bypass) |
| SSRF (Session 06) | GKE without Workload Identity | SSRF to node metadata to steal node SA token |
| LFI (Session 02) | Cloud Function env vars | LFI to `/proc/self/environ` to extract service account credentials |
| Auth bypass (Session 03) | App SA with Editor role | Auth bypass grants access to application running as Editor SA |
| XSS (Session 05) | Identity Platform tokens in JS | XSS to steal Firebase Auth tokens from client-side storage |

### Metadata Server Verification

```bash
# Check if instances use the default compute SA (overprivileged)
gcloud compute instances list --format='table(name,serviceAccounts[].email)' --project=PROJECT_ID

# Verify Workload Identity on GKE (if not configured, pods can reach node metadata)
gcloud container clusters describe CLUSTER_NAME --zone=ZONE \
  --format='value(workloadIdentityConfig.workloadPool)' --project=PROJECT_ID
```

---

## Compliance Mapping

```bash
ensphere compliance cloud_iam        # IAM bindings, primitive roles, SA key management
ensphere compliance cloud_storage    # GCS public access, encryption, uniform access
ensphere compliance cloud_network    # Firewall rules, VPC, private access
ensphere compliance cloud_compute    # Metadata protection, Shielded VMs, OS patching
ensphere compliance cloud_logging    # Data Access logs, audit log sinks, retention
ensphere compliance cloud_secrets    # Secret Manager, KMS key rotation
ensphere compliance cloud_k8s        # GKE RBAC, Workload Identity, network policy
```
