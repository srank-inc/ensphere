# Ensphere Methodology Index

Last updated: 2026-06-07

Run one methodology session at a time. Session 01, Session 01.5, and Session 09
are always part of the workflow. Sessions 02-08 depend on the adaptive
assessment plan. Session 10 and Session 11 are optional and gated.

## Session Map

| Session | File | Category | Output |
|---------|------|----------|--------|
| 01 | [01-recon.md](01-recon.md) | Recon | Target profile, attack surface, technology profile |
| 01.5 | [01.5-session-plan.md](01.5-session-plan.md) | Session Plan | `assessment-plan.yaml` decisions and coverage labels |
| 02 | [02-injection.md](02-injection.md) | Injection | SQLi, command injection, LFI, SSTI, deserialization evidence |
| 03 | [03-auth.md](03-auth.md) | Authentication | Auth/session/token evidence and Session 10 candidates |
| 04 | [04-authz.md](04-authz.md) | Authorization | IDOR, privilege, role, workflow evidence |
| 05 | [05-xss.md](05-xss.md) | XSS | Reflected, stored, DOM, source/sink evidence |
| 06 | [06-ssrf.md](06-ssrf.md) | SSRF | Direct, blind, semi-blind, callback evidence |
| 07 | [07-cloud.md](07-cloud.md) | Cloud | Cloud/IaC/scanner-ingestion evidence |
| 08 | [08-api.md](08-api.md) | API | Rate limit, property authz, mass assignment, OpenAPI evidence |
| 09 | [09-report.md](09-report.md) | Assessment Report | Evidence-backed report and finding registry |
| 10 | [10-exploitation.md](10-exploitation.md) | Optional Exploitation | Selected finding exploit attempts and outcomes |
| 11 | [11-final-report.md](11-final-report.md) | Optional Final Report | Exploit-verified final registry and report |

## Cloud Subfiles

| File | Provider |
|------|----------|
| [07a-aws.md](07a-aws.md) | AWS |
| [07b-gcp.md](07b-gcp.md) | GCP |
| [07c-azure.md](07c-azure.md) | Azure |
| [07d-k8s.md](07d-k8s.md) | Kubernetes |

## Gate Summary

| Gate | Command | Rule |
|------|---------|------|
| Plan gate | `ensphere run plan` | Drafts or validates `assessment-plan.yaml`; Session 01.5 owns final applicability decisions. |
| Report gate | `ensphere run report` | Blocks Session 09 readiness on missing reports, invalid evidence chains, invalid registry contracts, or unsafe paths. |
| Exploit handoff | `ensphere run exploit --finding <ID>` | Requires Session 09 `DONE`, exploitation enabled, and selected IDs from the Session 09 registry. |
| Final gate | `ensphere run final` | Requires Session 10 `DONE`, selected findings, outcomes, cleanup status, proof citations, and safe paths. |

## Required Shared Docs

Read [../shared/workflow-contract.md](../shared/workflow-contract.md) for
decision values, evidence categories, coverage labels, and report honesty rules.
Read [../shared/evidence-standards.md](../shared/evidence-standards.md) before
writing evidence rows or reports.
