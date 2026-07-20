# Session 04: Authorization

## Objective

Assess object-level, function-level, property-level, tenant, and workflow
authorization using explicitly supplied identities and owned test objects.

## Preflight and Coverage

Create an authorization matrix:

| Identity/role | Tenant | Object owner | Operation | Property/state | Expected result | Coverage |
|---------------|--------|--------------|-----------|----------------|-----------------|----------|

Include reads and writes, privileged functions, indirect references, list and
search endpoints, bulk operations, exports, background jobs, and material
workflow transitions only when present in recon.

Use two or more controlled accounts/tenants and paired owned test objects when
the boundary requires them. If these fixtures are unavailable, do not substitute
real users' identifiers; mark the affected rows blocked.

## Candidate Generation

White-box review traces authorization from entry point through middleware,
service, data access, serializers, and async consumers. Record whether checks
bind subject, tenant, object, operation, state, and property.

Black-box candidates come from the inventory and expected-access matrix. Do not
discover targets by enumerating sequential or guessed identifiers.

## Controlled Validation

For each candidate:

1. Verify the control identity can access its own test object or permitted
   function (positive control).
2. Replay the same operation with one boundary changed: object owner, tenant,
   role, operation, property, or workflow state.
3. Use a negative control such as a nonexistent owned identifier or disallowed
   state to distinguish authorization behavior from generic errors.
4. Compare status, response body, side effects, audit events, and persistent
   state as applicable.
5. For writes, mutate only a benign canary field on owned fixtures and restore
   it. Verify cleanup.

Do not enumerate other users' objects, read sensitive fields for proof, modify
unauthorized records, invoke destructive business actions, or chain into
account takeover. A differing status or body length alone is not proof; verify
whether protected data or state was actually exposed within the controlled
fixture.

## Interpretation and Stop Rules

- Distinguish object existence leakage from unauthorized object access.
- Distinguish UI hiding from server-side enforcement.
- Distinguish stale/cached responses and invalid object state from a policy
  decision.
- Treat source-only missing checks as candidates unless reachability and
  enforcement outcome are established.
- Stop after the narrow subject-object-operation claim is resolved. Do not
  broaden to unrelated roles or objects merely to strengthen proof.

## Report

Write `04-authz/report.md` with the tested authorization matrix, fixture and
cleanup record, resolved findings, tested defenses, unresolved boundaries,
baseline/probe/control evidence, root causes, impact, remediation and validation
criteria, and citations. State exactly which roles/tenants were and were not
covered.
