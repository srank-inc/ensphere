# Session 01: Reconnaissance

## Objective

Build a provenance-backed inventory of the selected target. Recon establishes
what later sessions may assess; it does not confirm vulnerabilities.

Read the shared workflow and evidence standards first.

## Preflight

Confirm and record:

- authorization and selected deployable target;
- environment, base URLs, source path, and target type;
- explicit scope and exclusions, including third parties;
- available test identities, roles, tenants, and owned/synthetic data;
- cloud accounts/projects/subscriptions/clusters in scope;
- live/source availability and collection limits.

If a repository contains multiple apps or services, identify the selected
deployable unit and its dependencies. Do not silently treat the whole monorepo
as one target.

## Required Inventories

Build these tables with a provenance reference for every row:

1. **Deployable components** — app/service, runtime, base URL, source path,
   environment, owner/trust boundary.
2. **Endpoints and operations** — protocol, method/operation, route, auth state,
   roles, content types, source or traffic reference.
3. **Inputs** — path/query/header/cookie/body/file/message fields, parser/type,
   validation layer, destination or sink candidate.
4. **Identity and roles** — login/session/token/API-key/OAuth flows, roles,
   tenants, account transitions, supplied test identities.
5. **Objects and workflows** — resource identifiers, ownership boundaries,
   sensitive state transitions, business invariants.
6. **Render contexts** — server templates, client DOM sinks, markdown/HTML
   renderers, email/PDF/export contexts, encoding/sanitization facts.
7. **Outbound fetchers** — webhooks, importers, previews, callbacks, remote
   media, document renderers, redirect behavior, allow/deny policy facts.
8. **Cloud and infrastructure** — provider identifiers, regions, storage,
   identities, network boundaries, serverless/container/Kubernetes/IaC assets.
9. **Trust and data flows** — component-to-component flows, guards, sensitive
   data classes, third-party boundaries.

Use the coverage state `observed`, `inferred`, `unresolved`, or
`not_applicable` for inventory rows. Inference must name its basis and must not
be presented as observed behavior.

## White-Box Collection

- Identify actual entry points and deployment configuration before searching
  for sinks.
- Extract routes, schemas, RPC handlers, message consumers, auth middleware,
  role checks, serializers, renderers, outbound clients, and cloud/IaC assets.
- Trace only enough source flow to identify later-session candidates. A pattern
  match is a lead, not a finding.
- Record exact file and line references and whether code is reachable in the
  selected deployment.
- Compare source inventory with observed traffic or runtime routes when a live
  target exists. Record drift rather than choosing one silently.

## Black-Box Collection

- Use passive application navigation, supplied documentation/specifications,
  browser/network observations, and targeted requests to selected known paths.
- Fingerprint technologies only when the response supports the inference;
  preserve uncertainty and avoid version claims from generic headers alone.
- Exercise supplied public and authenticated flows with authorized accounts.
- Do not brute-force directories, enumerate subdomains, scan ports, or probe
  unrelated infrastructure unless those activities are separately authorized.
- A missing response does not prove a surface is absent. Record the inventory
  gap and its downstream impact.

## Target Profile

Write `01-recon/target-profile.yaml` using the canonical runner schema:

```yaml
target:
  type: web_app
  source_mode: white_box
  coverage_label: partial
  classification_confidence: high
  rationale:
    - "Observed browser UI and JSON API in the selected deployment"
  evidence_refs:
    - "01-recon/report.md#deployable-components"
backend_inventory:
  - name: primary-api
    base_url: "https://test.example.invalid/api"
    kind: api_backend
    source: browser_traffic
    evidence_refs:
      - "01-recon/report.md#endpoints-and-operations"
signals:
  browser_ui: true
  api_surface: true
  server_side_surface: true
  authentication: true
  authorization_boundaries: true
  outbound_fetch_surface: false
  cloud_surface: false
  client_only: false
  monorepo_ambiguous: false
client_exposure_review: []
```

Use only runner-supported target types and source modes. Classification
confidence describes target classification, not security confidence.

## Completeness Gate

Before marking Session 01 `DONE`, verify that:

- the selected target and scope boundary are unambiguous;
- every required inventory has provenance or an explicit coverage gap;
- source/live discrepancies are recorded;
- accounts, roles, tenants, regions, protocols, and missing credentials are
  listed;
- target-profile signals agree with the inventories;
- downstream session candidates reference inventory row IDs;
- no candidate has been promoted to a finding during recon.

If these conditions fail, mark the session `BLOCKED` or coverage `partial` and
state which planning decisions cannot yet be made.

## Report

Write `01-recon/report.md` with:

1. authorization, target, mode, and scope;
2. coverage and collection limitations;
3. deployable components;
4. endpoint/operation and input inventories;
5. identity, role, object, and workflow inventories;
6. render and outbound-fetch inventories;
7. cloud/infrastructure and trust/data-flow inventories;
8. source/live drift and unresolved ambiguities;
9. later-session candidate index with provenance;
10. evidence and artifact index.

Then proceed to Session 01.5. Do not skip the planning gate.
