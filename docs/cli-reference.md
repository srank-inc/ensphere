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

## Verify

All verify commands require `--in-scope`. Output is JSON schema v2 with measurements only. No verify command emits CLI-owned vulnerability status, confidence, or exploitability.

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
ensphere verify ratelimit --url "https://target/api/login" --method POST --burst-count 100 --window-sec 10 --in-scope target
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

Calculate CVSS v3.1 or v4.0 scores from explicitly supplied metrics.

```bash
ensphere cvss --version 3.1 --av N --ac L --pr N --ui N --s U --c H --i H --a H
ensphere cvss --version 4.0 --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H
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
