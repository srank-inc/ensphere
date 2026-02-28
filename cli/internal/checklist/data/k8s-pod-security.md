# Kubernetes Pod Security Checklist

Attack surface specific to Kubernetes pod and container security configuration.

## Privileged Containers

- [ ] Containers running in privileged mode — `securityContext.privileged: true` grants full host access, device access, and capability to escape container namespace
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext.privileged'`
  -> scan: `ensphere scan ./k8s --category iac_misconfig`

## Host Namespace Sharing

- [ ] Host network, PID, or IPC namespaces enabled — `hostNetwork: true`, `hostPID: true`, or `hostIPC: true` allows container to access host processes, network stack, and shared memory
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec | {hostNetwork, hostPID, hostIPC}'`
  -> scan: `ensphere scan ./k8s --category iac_misconfig`

## Root User

- [ ] Containers running as root — missing `runAsNonRoot: true` or `runAsUser: 0` allows process to run as UID 0 inside container; increases impact of container escape
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext.runAsUser'`
  -> scan: `ensphere scan ./k8s --category iac_misconfig`

## Read-Only Root Filesystem

- [ ] Writable root filesystem — missing `readOnlyRootFilesystem: true` allows attackers to write binaries, modify configs, or plant persistence mechanisms inside container
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext.readOnlyRootFilesystem'`

## Capabilities

- [ ] Excessive Linux capabilities — missing `drop: ["ALL"]` or explicitly added dangerous capabilities (`SYS_ADMIN`, `NET_RAW`, `SYS_PTRACE`) enable privilege escalation
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.containers[].securityContext.capabilities'`
  -> scan: `ensphere scan ./k8s --category iac_misconfig`

## Seccomp Profiles

- [ ] Missing seccomp profile — no `seccompProfile.type: RuntimeDefault` or custom profile; unconfined seccomp allows all syscalls including those useful for escape
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.securityContext.seccompProfile'`

## Network Policies

- [ ] Missing network policies — no `NetworkPolicy` resources in namespace; all pod-to-pod traffic is allowed by default, enabling lateral movement after compromise
  -> verify: manual — `kubectl get networkpolicies -A` and check for default-deny ingress/egress policies per namespace
  -> verify: `ensphere cloud network --provider aws --in-scope "aws://<account_id>"` (for underlying cloud network)

## Service Account Tokens

- [ ] Auto-mounted service account tokens — `automountServiceAccountToken` not set to `false`; compromised pods can use mounted token to query Kubernetes API
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.automountServiceAccountToken'`

## Resource Limits

- [ ] Missing resource limits — no `resources.limits.cpu` or `resources.limits.memory` allows pod to consume unbounded resources; enables DoS against node and co-located workloads
  -> verify: manual — `kubectl get pods -A -o json | jq '.items[].spec.containers[].resources.limits'`

## Pod Security Standards

- [ ] Pod Security Admission not enforced — namespace missing `pod-security.kubernetes.io/enforce` label; no enforcement of `baseline` or `restricted` security standard
  -> verify: manual — `kubectl get namespaces -o json | jq '.items[] | {name: .metadata.name, labels: .metadata.labels}'` and check for `pod-security.kubernetes.io` labels
