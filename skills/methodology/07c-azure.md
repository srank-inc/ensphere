# Azure Deep Dive — Session 07 Sub-file

Provider-specific attack surfaces, verification commands, and Ensphere integration for Microsoft Azure. Read from Session 07 (Cloud Security) when Azure is in scope.

---

## Azure Functions

### Attack Surface

Azure Functions may expose HTTP-triggered endpoints with `authLevel: anonymous`, allowing unauthenticated invocation. Application settings (environment variables) frequently contain connection strings, storage account keys, and third-party API credentials in plaintext. Function apps running with a system-assigned managed identity may have excessive RBAC assignments. Deployment credentials and SCM access may be enabled without IP restrictions.

### Verification Commands

```bash
# List all Function Apps
az functionapp list --query '[].{Name:name,RG:resourceGroup,Runtime:siteConfig.linuxFxVersion,State:state}' -o table

# Check authentication settings (EasyAuth)
az functionapp auth show --name FUNCTION_APP --resource-group RG

# Check application settings (may contain secrets)
az functionapp config appsettings list --name FUNCTION_APP --resource-group RG -o json

# Check managed identity
az functionapp identity show --name FUNCTION_APP --resource-group RG

# Check RBAC assignments for the managed identity
az role assignment list --assignee PRINCIPAL_ID --all -o json

# Check function-level auth keys (host keys, function keys)
az functionapp keys list --name FUNCTION_APP --resource-group RG 2>/dev/null

# Check SCM (Kudu) access restrictions
az functionapp config access-restriction show --name FUNCTION_APP --resource-group RG --scm-site

# Check HTTPS-only enforcement
az functionapp show --name FUNCTION_APP --resource-group RG \
  --query '{HttpsOnly:httpsOnly,MinTLS:siteConfig.minTlsVersion,FtpsState:siteConfig.ftpsState}'
```

### Ensphere Integration

```bash
ensphere cloud iam --provider azure \
  --principal MANAGED_IDENTITY_PRINCIPAL_ID \
  --in-scope "azure://SUBSCRIPTION_ID"

# Serverless compute audit (Function Apps, public hostnames)
ensphere cloud compute --provider azure --in-scope "azure://SUBSCRIPTION_ID"

# Audit logging (diagnostic settings, active log status)
ensphere cloud logging --provider azure --in-scope "azure://SUBSCRIPTION_ID"

# Secrets management (Key Vault, soft-delete, purge protection)
ensphere cloud secrets --provider azure --in-scope "azure://SUBSCRIPTION_ID"

ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/functionapp/FUNCTION_APP" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Azure Function HTTP trigger has authLevel=anonymous — unauthenticated invocation"
```

---

## App Service

### Attack Surface

App Service may have authentication disabled (no EasyAuth) or misconfigured (allowing token bypass). Deployment slots may expose staging environments with weaker security configurations. Remote debugging, WebSocket, or FTP access may be enabled unnecessarily. Managed identity RBAC assignments may be overprivileged. IP restrictions may be missing or too broad.

### Verification Commands

```bash
# List all App Services
az webapp list --query '[].{Name:name,RG:resourceGroup,State:state,HTTPS:httpsOnly}' -o table

# Check authentication (EasyAuth)
az webapp auth show --name APP_NAME --resource-group RG

# Check access restrictions (IP whitelisting)
az webapp config access-restriction show --name APP_NAME --resource-group RG

# Check site configuration (remote debugging, FTP, min TLS)
az webapp config show --name APP_NAME --resource-group RG \
  --query '{RemoteDebug:remoteDebuggingEnabled,FTP:ftpsState,MinTLS:minTlsVersion,Http20:http20Enabled,AlwaysOn:alwaysOn}'

# Check managed identity assignments
az webapp identity show --name APP_NAME --resource-group RG
az role assignment list --assignee PRINCIPAL_ID --all -o json

# Check deployment slots
az webapp deployment slot list --name APP_NAME --resource-group RG -o json

# Check application settings for secrets
az webapp config appsettings list --name APP_NAME --resource-group RG -o json

# Check connection strings
az webapp config connection-string list --name APP_NAME --resource-group RG -o json

# Check CORS settings
az webapp cors show --name APP_NAME --resource-group RG
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_compute --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/webapp/APP_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "App Service has remote debugging enabled and no IP access restrictions"
```

---

## Cosmos DB

### Attack Surface

Cosmos DB accounts with firewall set to "Accept connections from within public Azure datacenters" (`0.0.0.0`) allow access from any Azure-hosted resource. Primary/secondary keys grant full account access and cannot be scoped to individual databases or containers. RBAC data-plane access may not be enforced, falling back to key-based auth. Diagnostic settings may not capture data-plane operations.

### Verification Commands

```bash
# List Cosmos DB accounts
az cosmosdb list --query '[].{Name:name,RG:resourceGroup,Kind:kind,PublicAccess:publicNetworkAccess}' -o table

# Check firewall rules (ipRules and virtualNetworkRules)
az cosmosdb show --name ACCOUNT_NAME --resource-group RG \
  --query '{PublicAccess:publicNetworkAccess,IPRules:ipRules,VNetRules:virtualNetworkRules,Firewall:isVirtualNetworkFilterEnabled}'

# Check if local (key-based) auth is disabled
az cosmosdb show --name ACCOUNT_NAME --resource-group RG \
  --query '{DisableLocalAuth:disableLocalAuth,DisableKeyBasedMetadataWriteAccess:disableKeyBasedMetadataWriteAccess}'

# Check encryption (customer-managed key)
az cosmosdb show --name ACCOUNT_NAME --resource-group RG \
  --query '{KeyVaultKeyUri:keyVaultKeyUri}'

# Check diagnostic settings
az monitor diagnostic-settings list --resource "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.DocumentDB/databaseAccounts/ACCOUNT_NAME" -o json

# Check CORS policy
az cosmosdb show --name ACCOUNT_NAME --resource-group RG --query 'cors'

# List databases
az cosmosdb sql database list --account-name ACCOUNT_NAME --resource-group RG -o json
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/cosmosdb/ACCOUNT_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Cosmos DB allows connections from all Azure datacenters (0.0.0.0 in IP rules)"
```

---

## Service Bus

### Attack Surface

Service Bus namespaces with Shared Access Policies using `Manage` claim grant full control over all queues and topics. Default authorization rules may be left with `RootManageSharedAccessKey`. Public network access may be unrestricted. Dead-letter queues may accumulate sensitive messages without monitoring. Cross-namespace forwarding may expose messages to unauthorized consumers.

### Verification Commands

```bash
# List Service Bus namespaces
az servicebus namespace list --query '[].{Name:name,RG:resourceGroup,SKU:sku.name}' -o table

# Check network rules
az servicebus namespace network-rule-set show --namespace-name NAMESPACE --resource-group RG

# Check authorization rules (Shared Access Policies)
az servicebus namespace authorization-rule list --namespace-name NAMESPACE --resource-group RG -o json

# Check specific authorization rule (look for Manage claim)
az servicebus namespace authorization-rule show --namespace-name NAMESPACE --resource-group RG \
  --name RootManageSharedAccessKey --query '{Rights:rights}'

# List queues
az servicebus queue list --namespace-name NAMESPACE --resource-group RG \
  --query '[].{Name:name,DeadLettering:deadLetteringOnMessageExpiration,MaxSize:maxSizeInMegabytes}'

# List topics and subscriptions
az servicebus topic list --namespace-name NAMESPACE --resource-group RG -o json

# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.ServiceBus/namespaces/NAMESPACE" -o json
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_network --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/servicebus/NAMESPACE" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Service Bus namespace has RootManageSharedAccessKey with public network access enabled"
```

---

## Azure AD B2C

### Attack Surface

Azure AD B2C custom policies may contain logic flaws in user journeys that allow authentication bypass. Self-service sign-up flows may not validate email domain restrictions. Token configuration may include excessive claims or long-lived tokens. User flow endpoints may be enumerable. Custom API connectors may call HTTP endpoints without TLS or proper authentication.

### Verification Commands

```bash
# List B2C tenants (requires specific tenant context)
az account list --query '[?tenantId==`B2C_TENANT_ID`]'

# Check registered applications
az ad app list --filter "publisherDomain eq 'TENANT.onmicrosoft.com'" \
  --query '[].{AppId:appId,Name:displayName,SignInAudience:signInAudience}' -o table

# Check application credentials (client secrets, certificates)
az ad app credential list --id APP_OBJECT_ID -o json

# Check redirect URIs (look for localhost, HTTP, or wildcard)
az ad app show --id APP_ID --query '{Web:web.redirectUris,SPA:spa.redirectUris}'

# Check API permissions
az ad app show --id APP_ID --query 'requiredResourceAccess'

# Check token configuration (optional claims)
az ad app show --id APP_ID --query 'optionalClaims'

# Check service principals and their assignments
az ad sp list --filter "appId eq 'APP_ID'" --query '[].{Name:displayName,AppRoles:appRoles}'
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/b2c/APP_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Azure AD B2C application has localhost redirect URI registered in production"
```

---

## Blob Storage

### Attack Surface

Storage accounts with `AllowBlobPublicAccess` enabled permit container-level or blob-level anonymous access. Shared Access Signatures (SAS) with overly broad permissions, excessive duration, or missing IP restrictions provide uncontrolled data access. Account keys are all-or-nothing and cannot be scoped. Storage accounts without HTTPS-only enforcement allow credential interception. Soft delete may not be enabled, preventing data recovery after ransomware.

### Verification Commands

```bash
# Comprehensive storage security check
ensphere cloud storage --provider azure --bucket CONTAINER_NAME --in-scope "azure://SUBSCRIPTION_ID"

# Check storage account security settings
az storage account show --name ACCOUNT_NAME --query '{PublicAccess:allowBlobPublicAccess,HttpsOnly:enableHttpsTrafficOnly,MinTLS:minimumTlsVersion,KeyAccess:allowSharedKeyAccess,NetworkRules:networkRuleSet}'

# Check network rules (default action, IP rules, VNet rules)
az storage account show --name ACCOUNT_NAME --query 'networkRuleSet.{Default:defaultAction,IPRules:ipRules,VNetRules:virtualNetworkRules}'

# List containers and their public access level
az storage container list --account-name ACCOUNT_NAME --auth-mode login \
  --query '[].{Name:name,PublicAccess:properties.publicAccess}'

# Check blob service properties (soft delete, versioning)
az storage account blob-service-properties show --account-name ACCOUNT_NAME \
  --query '{SoftDelete:deleteRetentionPolicy,Versioning:isVersioningEnabled,ChangeFeed:changeFeed}'

# Check encryption (customer-managed key)
az storage account show --name ACCOUNT_NAME --query 'encryption'

# Check access keys rotation
az storage account show --name ACCOUNT_NAME --query 'keyCreationTime'

# Test anonymous access
curl -s -o /dev/null -w "%{http_code}" \
  "https://ACCOUNT_NAME.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# Check diagnostic settings
az monitor diagnostic-settings list \
  --resource "/subscriptions/SUB_ID/resourceGroups/RG/providers/Microsoft.Storage/storageAccounts/ACCOUNT_NAME" -o json
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_storage --technique anonymous_access \
  --url "azure://SUBSCRIPTION_ID/storage/ACCOUNT_NAME/CONTAINER" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Blob container allows anonymous list — 200 response on unauthenticated container listing"
```

---

## RBAC

### Attack Surface

Azure RBAC misconfigurations include custom roles with wildcard actions (`*`), `Owner` role assignments at subscription or management group scope, classic co-administrator assignments that bypass RBAC, and service principal credentials with no expiry. Privileged Identity Management (PIM) may not be enabled, leaving permanent standing access for high-privilege roles.

### Verification Commands

```bash
# Audit a specific principal
ensphere cloud iam --provider azure \
  --principal PRINCIPAL_ID \
  --in-scope "azure://SUBSCRIPTION_ID"

# List all role assignments at subscription scope
az role assignment list --all --query '[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}' -o table

# Check for Owner/Contributor at subscription level
az role assignment list --all \
  --query '[?roleDefinitionName==`Owner` || roleDefinitionName==`Contributor`].{Principal:principalName,Role:roleDefinitionName,Scope:scope}'

# List custom role definitions (check for wildcard actions)
az role definition list --custom-role-only true \
  --query '[].{Name:roleName,Actions:permissions[0].actions,NotActions:permissions[0].notActions}'

# Check for classic administrators
az role assignment list --include-classic-administrators \
  --query '[?principalType==`ServiceAdministrator` || principalType==`CoAdministrator`]'

# List service principals with credentials
az ad sp list --all --query '[?passwordCredentials || keyCredentials].{Name:displayName,AppId:appId}'

# Check service principal credential expiry
az ad app credential list --id APP_OBJECT_ID \
  --query '[].{KeyId:keyId,Type:type,EndDate:endDateTime}'

# Check Azure AD Privileged Identity Management (PIM) eligible assignments
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/SUB_ID/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01" 2>/dev/null
```

### Known Escalation Combinations

| Permission | Escalation Path |
|-----------|-----------------|
| `Owner` at subscription scope | Full control including RBAC management |
| `User Access Administrator` | Grant self any role on any resource |
| `Contributor` + managed identity | Deploy resources with managed identity, access their tokens |
| `Virtual Machine Contributor` | Run commands on VMs via Run Command extension |
| `Automation Contributor` | Execute runbooks as automation account identity |
| `Logic App Contributor` | Deploy logic apps with managed identity connections |

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_iam --technique iam_escalation \
  --url "azure://SUBSCRIPTION_ID/rbac/PRINCIPAL_ID" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "Service principal has User Access Administrator at subscription scope — can grant itself Owner"
```

---

## AKS

### Attack Surface

AKS clusters with API server accessible from public internet without authorized IP ranges allow unauthenticated reconnaissance. Clusters using Azure AD integration but without Conditional Access may accept tokens from compromised accounts. Node pools with public IPs expose container hosts directly. Pod identity (legacy) vs Workload Identity misconfigurations can grant pods excessive Azure permissions. Kubernetes dashboard (if deployed) may be accessible without authentication.

### Verification Commands

```bash
# List AKS clusters
az aks list --query '[].{Name:name,RG:resourceGroup,K8sVersion:kubernetesVersion,RBAC:enableRbac}' -o table

# Check cluster security configuration
az aks show --name CLUSTER_NAME --resource-group RG \
  --query '{RBAC:enableRbac,AADIntegration:aadProfile,AuthorizedIPs:apiServerAccessProfile.authorizedIpRanges,PrivateCluster:apiServerAccessProfile.enablePrivateCluster,NetworkPolicy:networkProfile.networkPolicy,PodPolicy:podSecurityProfile}'

# Check node pool configuration
az aks nodepool list --cluster-name CLUSTER_NAME --resource-group RG \
  --query '[].{Name:name,VMSize:vmSize,NodeCount:count,PublicIPs:enableNodePublicIp,Mode:mode}'

# Check managed identity
az aks show --name CLUSTER_NAME --resource-group RG --query 'identity'

# Check RBAC role assignments for the cluster identity
az role assignment list --assignee $(az aks show --name CLUSTER_NAME --resource-group RG --query 'identity.principalId' -o tsv) --all -o json

# Check Azure Policy for AKS (Azure Policy Add-on)
az aks show --name CLUSTER_NAME --resource-group RG \
  --query 'addonProfiles.azurepolicy'

# Check monitoring (Container Insights)
az aks show --name CLUSTER_NAME --resource-group RG \
  --query 'addonProfiles.omsagent'

# Get credentials and check cluster-level RBAC
az aks get-credentials --name CLUSTER_NAME --resource-group RG
kubectl get clusterrolebindings -o json | grep -B2 -A5 'cluster-admin'
```

### Evidence Logging

```bash
ensphere evidence log \
  --probe-type cloud_k8s --technique cli_verification \
  --url "azure://SUBSCRIPTION_ID/aks/CLUSTER_NAME" \
  --result confirmed --session 7 \
  --file ./ensphere-pentest/07-cloud/evidence.jsonl \
  --notes "AKS cluster API server publicly accessible with no authorized IP ranges configured"
```

---

## Cross-Correlation with Web Findings

Azure-specific attack chains combining web vulnerabilities with cloud misconfiguration:

| Web Finding | Azure Finding | Combined Attack |
|-------------|--------------|-----------------|
| SSRF (Session 06) | IMDS accessible | SSRF to `169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com/&api-version=2018-02-01` with `Metadata: true` header to steal managed identity tokens |
| SSRF (Session 06) | AKS without Workload Identity | SSRF to node IMDS to steal kubelet identity token |
| LFI (Session 02) | App Service env vars | LFI to read `/proc/self/environ` or App Service environment to extract connection strings |
| SQLi (Session 02) | Azure SQL public endpoint | SQLi to extract connection strings, then direct database access from internet |
| Auth bypass (Session 03) | Overprivileged managed identity | Auth bypass grants access to application with Contributor managed identity |
| XSS (Session 05) | Azure AD B2C tokens in JS | XSS to steal MSAL tokens from browser storage |

### IMDS Verification

```bash
# Check if VMs use managed identity (potential SSRF target)
az vm list --query '[].{Name:name,Identity:identity.type}' -o table

# Check IMDS accessibility (from within an Azure VM or via SSRF)
# Azure IMDS requires Metadata:true header and uses 169.254.169.254
```

---

## Compliance Mapping

```bash
ensphere compliance cloud_iam        # RBAC assignments, service principal credentials, PIM
ensphere compliance cloud_storage    # Blob public access, encryption, SAS policies
ensphere compliance cloud_network    # NSG rules, private endpoints, firewall settings
ensphere compliance cloud_compute    # IMDS, managed identity, patching, extensions
ensphere compliance cloud_logging    # Diagnostic settings, activity log, Azure Monitor
ensphere compliance cloud_secrets    # Key Vault access policies, key rotation, soft delete
ensphere compliance cloud_k8s        # AKS RBAC, network policy, authorized IPs
```
