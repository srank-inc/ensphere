# Methodology Index

All sessions inherit the scope, controlled-validation, stop, and reporting
rules in [../shared/workflow-contract.md](../shared/workflow-contract.md) and
[../shared/evidence-standards.md](../shared/evidence-standards.md).

| Session | Methodology | Primary artifact |
|---------|-------------|------------------|
| 01 | [Recon](01-recon.md) | Provenance-backed inventories and target profile |
| 01.5 | [Session plan](01.5-session-plan.md) | Validated applicability/coverage plan |
| 02 | [Injection](02-injection.md) | Resolved injection claims |
| 03 | [Authentication](03-auth.md) | Resolved identity/session claims |
| 04 | [Authorization](04-authz.md) | Tested subject-object-operation matrix |
| 05 | [XSS](05-xss.md) | Tested render-context matrix |
| 06 | [SSRF](06-ssrf.md) | Tested outbound-fetch policy matrix |
| 07 | [Cloud](07-cloud.md) | Read-only cloud/IaC findings and coverage |
| 08 | [API](08-api.md) | API-control findings and coverage |
| 09 | [Assessment report](09-report.md) | Complete report, registry, and evidence appendix |
| 10 | [Human-authorized impact validation](10-impact-validation.md) | Optional selected-finding outcomes |
| 11 | [Validation-aware report](11-final-report.md) | Optional derived report preserving Session 09 status |

Sessions 01–09 form the complete assessment. Session 10 must be explicitly
enabled and selected, requires exact human authorization, names either the
human or AI as executor, and cannot be entered automatically. Session 11 exists
only to report valid Session 10 outcomes as a separate dimension.

Runner gates:

- `ensphere run plan` validates the Session 01.5 plan.
- `ensphere run report` validates readiness and the Session 09 registry.
- `ensphere run validate-impact --finding ID` prepares the optional handoff;
  execution remains paused until the exact plan revision and executor are
  human-authorized.
- `ensphere run final` validates outcomes and derives the Session 11 registry.
