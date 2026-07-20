# Ensphere CLI Reference

This document is the full command reference for the `ensphere` Go CLI. Commands emit structured JSON where applicable and are designed to produce measurements rather than security judgments.

## Build and Install

```bash
make build        # build ./bin/ensphere
make install      # install binary to /usr/local/bin/ensphere
make install-all  # install binary and skill files
```

You can also run directly from source:

```bash
cd cli
go run . --help
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command completed |
| 1 | Generic command failure or scan matches found |
| 2 | Usage or scope error |
| 3 | Runtime probe failure |

## Payloads

Query the embedded payload database.

```bash
ensphere payloads sqli --db postgres --technique blind_time
ensphere payloads ssrf --max-risk 2
ensphere payloads csv_injection
ensphere payloads sqli --tag pg_sleep --limit 5
```

Output includes `query`, `count`, and `results[]` with payload, placeholders, evidence type, risk, notes, and tags. Invalid filters return valid values.

## Run

Create and inspect the `ensphere-pentest/` workspace used by the agent
workflow. The runner writes deterministic workspace files, `next-action.md`,
and `agent-prompt.md`; it does not run AI reasoning. Session 10 is disabled by
default and requires human authorization for the exact plan and named executor.

```bash
ensphere run init \
  --target "https://staging.example.com" \
  --source yes \
  --target-type api_backend \
  --in-scope staging.example.com

ensphere run status
ensphere run plan
ensphere run next
ensphere run report

# Only after Session 09 is DONE, impact validation is enabled, and findings are selected:
ensphere run validate-impact --finding VULN-001 --finding VULN-004

# Only after writing a strict plan and recording approval of its exact SHA-256:
ensphere run impact-ready \
  --finding VULN-001 \
  --authorization 10-impact-validation/authorizations/VULN-001-agent.yaml

# Only after Session 10 writes impact-validation outcomes:
ensphere run final
```

Common flags:

```text
--workspace              Workspace directory, default ensphere-pentest
--target                 Target URL for run init
--source                 Source availability: yes or no
--target-type            auto, web_app, api_backend, static_site, mobile_client_remote_backend, mobile_client_offline, desktop_or_extension_client, cloud_only, library_or_cli
--cloud                  none, aws, gcp, azure, kubernetes, or comma-separated
--impact-validation-enabled   Write config with optional Session 10 enabled
--force                  For run plan, overwrite an existing assessment plan from config
--finding                Finding ID for run validate-impact, repeatable
--authorization          Workspace-relative authorization YAML for run impact-ready
```

`run plan` writes `assessment-plan.yaml` and mirrors it to
`01.5-session-plan/assessment-plan.yaml` when no plan exists. Existing plans are
validated, copied to the Session 01.5 mirror, and not overwritten unless
`--force` is set. The generated plan is deterministic. It starts from
`config.md` and, when present, incorporates
`01-recon/target-profile.yaml` for Recon-generated target type, backend
inventory, client-only limitations, and session applicability signals.

`run init` refuses to overwrite a workspace that already contains `config.md`
or `progress.md`; use `run status` or `run next` to resume an initialized
assessment.

`run report` writes `09-report/report-gate.yaml` and
`09-report/report-gate.md`. It blocks report readiness when required session
reports are missing, sessions 01, 01.5, or 02-08 are not terminal,
`assessment-plan.yaml` is missing or invalid, evidence hash-chain verification
fails, or an existing finding registry contains uncited findings, missing
required finding fields, invalid statuses (`confirmed`, `likely`,
`informational`, `not_supported`, `not_tested`), inconsistent evidence strength,
missing CVSS v4 vectors for vulnerability findings, invalid confidence/severity/
priority values, invalid evidence categories, invalid coverage labels, missing
or unsafe transcript/artifact/cleanup paths, or an incomplete final report and
evidence appendix.

Runner-generated state, plans, recon profiles, report artifacts, Session 10
handoffs/outcomes, and derived registries use one canonical schema. Unknown
fields are rejected rather than ignored.

`run validate-impact` validates and prepares selected finding files for Session 10. It
refuses to run unless impact validation is explicitly enabled in the current
`assessment-plan.yaml` (the init/config flag feeds plan generation), Session 09 is marked `DONE`, its report/appendix and
finding registry are valid, and every selected
finding ID exists in that registry. It writes
`10-impact-validation/selected-findings.yaml` with `max_risk`, allowed actions,
forbidden actions, cleanup requirements, required authorization/environment/
plan gates, permitted executors (`human`, `agent`), and workspace-relative
evidence paths, including a dedicated authorization directory. It prepares the
handoff but does not autonomously execute it.
For each selected finding, `run impact-ready` validates the machine-readable
plan, its current SHA-256, the separate human-authorization record, ordered
action IDs, executor, environment, identity/role, exact target/operation,
action/time/risk limits, stop and rollback rules, and evidence paths. It sends
no request, writes a hash-bound readiness attestation, and must report
`ready: true` before either executor acts.
`run next` exposes Session 10 only after that handoff file exists and resolves
against the valid Session 09 registry. It never starts or offers Session 11;
the human must explicitly invoke `run final` after Session 10 is `DONE`.

`run final` validates `10-impact-validation/impact-validation-outcomes.yaml` against the
Session 09 finding registry and Session 10 selected-finding handoff. It blocks
when a selected finding has no outcome, exact-plan authorization is missing,
the separate authorization file does not match the plan SHA-256, the executor
or environment differs, performed actions or elapsed time exceed authorization,
executor-specific evidence is invalid, an `objective_achieved` outcome lacks
proof citations, the readiness attestation predates authorization, changed, or
postdates execution,
Session 10 evidence IDs do not resolve through a valid hash chain, cleanup proof
is missing, or citation paths are missing/unsafe.
On success it writes a derived
`11-final-report/finding-registry.yaml` plus evidence appendix. It preserves the
Session 09 `status` and records the optional result in
`impact_validation_outcome_status`; it does not modify Session 09 artifacts.

## Verify

All verify commands require `--in-scope`. Output is measurement-only JSON. No verify command emits CLI-owned vulnerability status, confidence, or exploitability.

Common flags include:

```text
--in-scope       Required scope guard
--evidence       Evidence JSONL path
--throttle       Delay between probe rounds in milliseconds
--timeout        Request timeout in seconds
--max-risk       Maximum payload/probe risk allowed
--header         Additional HTTP header, repeatable as key:value
```

Representative commands:

```bash
ensphere verify sqli --url "https://target/search?id=1" --param id --technique blind_time --in-scope target
ensphere verify xss --url "https://target/search" --param q --payload "<script>alert(1)</script>" --in-scope target
ensphere verify idor --url "https://target/api/items/{id}" --id "victim-id" --token "attacker-token" --in-scope target
ensphere verify ssrf --url "https://target/fetch" --param url --callback-url "https://callback.example" --in-scope target
ensphere verify auth --url "https://target/api/admin" --token "valid-token" --technique alg_none --in-scope target
ensphere verify authz --url "https://target/api/admin" --low-token "user-token" --high-token "admin-token" --in-scope target
ensphere verify csrf --url "https://target/api/action" --method POST --in-scope target
ensphere verify cors --url "https://target/api/data" --in-scope target
ensphere verify jwt --url "https://target/api/me" --token "jwt" --technique alg_none --in-scope target
ensphere verify ratelimit --url "https://target/api/login" --method POST --burst-count 10 --window-sec 10 --in-scope target
```

Supported probe families:

```text
auth, authz, cachepoisoning, clickjacking, cmdi, cors, csrf,
csvinjection, deserialization, fileupload, graphql, grpc,
headerinjection, idor, jwt, ldap, lfi, massassignment, nosql,
propertyauthz, protopollution, race, ratelimit, redirect, rls,
smuggling, sqli, ssrf, ssti, websocket, xpath, xss, xxe
```

## Evidence

Write, query, and verify hash-chained JSONL evidence.

```bash
ensphere evidence log \
  --probe-type sqli \
  --technique blind_time \
  --url "https://target/api" \
  --result manual_note \
  --session 2

ensphere evidence query --file ./evidence.jsonl --summary
ensphere evidence query --file ./evidence.jsonl --result probe --limit 10
ensphere evidence verify --file ./evidence.jsonl
```

New entries receive stable `EVID-XXX` IDs at write time. The `result` field is a factual stage only:

```text
baseline, probe, payload, control, callback, manual_note
```

## Scan

Scan source code for regex-based sink candidates.

```bash
ensphere scan ./src
ensphere scan ./src --category sqli,xss
ensphere scan ./src --exclude "test/**"
ensphere scan ./src --context-lines 0
ensphere scan ./src --exit-zero
```

Scan output includes `analysis_depth: "pattern_match"`. Matches are review leads, not confirmed vulnerabilities. Context is bounded and redacted by default.

## OpenAPI

Parse OpenAPI or Swagger specifications into endpoint inventory.

```bash
ensphere openapi --file ./openapi.yaml
ensphere openapi --url "https://target/api/docs/openapi.json"
```

## Callback

Run an out-of-band callback listener for blind SSRF, XXE, and similar probes.

```bash
ensphere callback --port 8888 --wait 30 --external-url "https://callback.example" --evidence ./evidence.jsonl
```

## Cloud

Run cloud checks through provider CLIs and parse third-party cloud scanner output.

```bash
ensphere cloud storage --provider aws --bucket my-bucket --in-scope "aws://123456789012"
ensphere cloud iam --provider aws --principal arn:aws:iam::123:user/alice --in-scope "aws://123456789012"
ensphere cloud network --provider aws --vpc-id vpc-abc123 --in-scope "aws://123456789012"
ensphere cloud compute --provider aws --in-scope "aws://123456789012"
ensphere cloud logging --provider aws --in-scope "aws://123456789012"
ensphere cloud secrets --provider aws --in-scope "aws://123456789012"
ensphere cloud parse-prowler ./prowler-output.json --evidence ./evidence.jsonl
ensphere cloud parse-trivy ./trivy-results.json --evidence ./evidence.jsonl
```

Parsed severities from Prowler and Trivy are labeled as source-provided.

## Templates

List, print, or materialize reproducible Python 3 proof-of-concept templates.

```bash
ensphere template --list
ensphere template idor-uuid
ensphere template sqli-time-postgres --out ./poc/sqli
```

Available templates:

```text
auth-header-replay, cmdi-reverse-check, deserialization-java,
idor-uuid, jwt-forge, lfi-to-rce, nosql-extraction,
sqli-time-postgres, ssrf-probe, ssti-rce, upload-polyglot-check,
xss-reflected-poc, xxe-oob-extract
```

## CVSS

Calculate a CVSS 4.0 score from explicitly supplied metrics.

```bash
ensphere cvss --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H
```

CVSS severity is deterministic from supplied metrics. It is not inferred by Ensphere.

## Sinks

List sink categories and embedded regex patterns.

```bash
ensphere sinks
ensphere sinks sqli
```

## Compliance

Map vulnerability types to compliance frameworks.

```bash
ensphere compliance --list
ensphere compliance sqli
```

Supported frameworks include OWASP Top 10 2025, OWASP API Security Top 10 2023, PCI-DSS v4.0.1, SOC 2, and ISO 27001.

## Checklists

List or print framework and platform-specific security checklists.

```bash
ensphere checklist
ensphere checklist --list
ensphere checklist supabase-rls
```

Checklist files are embedded from `skills/checklists/`.
