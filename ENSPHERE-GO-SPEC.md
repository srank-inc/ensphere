# Ensphere Go CLI — Technical Specification

The Go CLI is the deterministic measurement and workspace layer under
Ensphere's evidence-first autonomous assessment workflow. It executes scoped
measurements, writes factual evidence, prepares agent handoffs, validates report
contracts, and never assigns vulnerability status, confidence, exploitability,
or business impact.

## Architecture: 6 Layers

### Layer 1 — Payload Database

1206 curated payloads across 27 vuln types, compiled from YAML seeds to embedded SQLite. Agent queries `ensphere payloads <vuln_type> [filters]` for deterministic, context-indexed payloads instead of generating from training data.

Payloads indexed by **context**, not framework:
- **SQLi**: db_engine (postgres/mysql/mssql/sqlite/oracle), technique, injection_surface, encoding, string_boundary
- **XSS**: rendering context (reflected/stored/dom), not "React vs Vue"
- **SSRF**: runtime (node/jvm/python/ruby/go), target (metadata/internal_service)
- Other types: cmdi, lfi, ssti, deserialization, xxe, idor, authz, csrf, nosql, auth_bypass, jwt, graphql, cors, redirect, csv_injection, prototype_pollution, race_condition, request_smuggling, cache_poisoning

### Layer 2 — Native Measurement Probes

Custom Go HTTP and protocol probes (not wrappers around external tools). An
agent calls `ensphere verify sqli --url ... --param ...` to capture
deterministic measurements that can later support a human or AI judgment.

- Pure Go implementations at protocol level
- Returns structured JSON (schema v2): `{schema_version, vuln_type, technique, started_at, probe_count, duration, measurements}` — measurement-only output, no status/confidence classification
- Safety: mandatory `--in-scope` scoping, rate throttling (default 500ms), max-risk gate (default 3)
- Evidence auto-logged to JSONL with secret redaction
- Probes: sqli, xss, idor, ssrf, auth, rls, cmdi, lfi, ssti, xxe, deserialization, csrf, nosql, jwt, cors, protopollution, graphql, race, smuggling, cachepoisoning, redirect, csvinjection, authz, clickjacking, headerinjection, websocket, grpc, ratelimit, propertyauthz, ldap, xpath, fileupload, massassignment (33 total)

### Layer 3 — Exploit Templates

13 pre-built Python 3 stdlib-only exploit scripts. Agent calls `ensphere template <name> [--out dir]`.

Templates: idor-uuid, sqli-time-postgres, ssrf-probe, auth-header-replay, upload-polyglot-check, xss-reflected-poc, nosql-extraction, jwt-forge, cmdi-reverse-check, deserialization-java, ssti-rce, lfi-to-rce, xxe-oob-extract. Each includes exploit.py + template.json + README.md.

### Layer 4 — Framework Checklists

13 security checklists (markdown): nextjs-app-router (17 items), supabase-rls (10), trpc (8), cloudflare-r2 (6), django (10), rails (12), spring-boot (12), express-js (12), laravel (10), fastapi (10), aws-s3 (12), aws-iam (12), k8s-pod-security (10).

### Layer 5 — Runner and Workspace Gates

`ensphere run` creates and inspects the `ensphere-pentest/` workspace used by
the skill workflow. It writes deterministic files and handoff prompts; it does
not run the AI and does not execute exploit attempts.

- `run init`: create `config.md` and initial progress files
- `run plan`: draft or validate `assessment-plan.yaml` and mirror Session 01.5
- `run status`: summarize workspace state and next work
- `run next`: write `next-action.md` and `agent-prompt.md`
- `run report`: validate Session 09 readiness and finding-registry contracts
- `run exploit`: validate selected Session 09 finding IDs and write the Session 10 handoff
- `run final`: validate Session 10 outcomes and derive the Session 11 registry

### Layer 6 — Imported Leads and Report Contracts

The CLI currently parses Prowler and Trivy outputs through cloud commands.
Roadmap importers such as Nmap, Nuclei, SARIF, ZAP/Burp, and SQLMap must record
source tool, source file, rule/template ID, source severity, and raw matched
evidence as source-provided leads. Imported leads are not Ensphere-confirmed
findings; finding status and severity belong in reports and registries.

---

## Go Module Structure

```
cli/
  main.go                         # entry point → cmd.Execute()
  go.mod                          # github.com/srank/ensphere, go 1.26.4
  cmd/
    root.go                       # Cobra root command
    payloads.go                   # ensphere payloads <vuln_type>
    verify.go                     # parent: ensphere verify
    verify_sqli.go                # ensphere verify sqli
    verify_xss.go                 # ensphere verify xss
    verify_idor.go                # ensphere verify idor
    verify_ssrf.go                # ensphere verify ssrf
    verify_auth.go                # ensphere verify auth
    verify_rls.go                 # ensphere verify rls
    verify_cmdi.go                # ensphere verify cmdi
    verify_lfi.go                 # ensphere verify lfi
    verify_ssti.go                # ensphere verify ssti
    verify_xxe.go                 # ensphere verify xxe
    verify_deserialization.go     # ensphere verify deserialization
    verify_csrf.go                # ensphere verify csrf
    verify_nosql.go               # ensphere verify nosql
    verify_jwt.go                 # ensphere verify jwt
    verify_cors.go                # ensphere verify cors
    verify_protopollution.go      # ensphere verify protopollution
    verify_graphql.go             # ensphere verify graphql
    verify_race.go                # ensphere verify race
    verify_smuggling.go           # ensphere verify smuggling
    verify_cachepoisoning.go      # ensphere verify cachepoisoning
    verify_redirect.go            # ensphere verify redirect
    verify_csvinjection.go        # ensphere verify csvinjection
    verify_authz.go               # ensphere verify authz
    verify_clickjacking.go        # ensphere verify clickjacking
    verify_headerinjection.go     # ensphere verify headerinjection
    verify_websocket.go           # ensphere verify websocket
    verify_grpc.go                # ensphere verify grpc
    verify_ratelimit.go           # ensphere verify ratelimit
    verify_propertyauthz.go       # ensphere verify propertyauthz
    verify_ldap.go                # ensphere verify ldap
    verify_xpath.go               # ensphere verify xpath
    verify_fileupload.go          # ensphere verify fileupload
    verify_massassignment.go      # ensphere verify massassignment
    callback.go                   # ensphere callback (OOB listener)
    cloud.go                      # parent: ensphere cloud
    cloud_storage.go              # ensphere cloud storage
    cloud_iam.go                  # ensphere cloud iam
    cloud_network.go              # ensphere cloud network
    cloud_compute.go              # ensphere cloud compute
    cloud_logging.go              # ensphere cloud logging
    cloud_secrets.go              # ensphere cloud secrets
    cloud_parse.go                # ensphere cloud parse-prowler / parse-trivy
    openapi.go                    # ensphere openapi
    scan.go                       # ensphere scan <dir>
    template.go                   # ensphere template [name]
    evidence.go                   # parent: ensphere evidence
    evidence_log.go               # ensphere evidence log
    evidence_query.go             # ensphere evidence query
    evidence_verify.go            # ensphere evidence verify
    run.go                        # ensphere run init/status/plan/next/report/exploit/final
    checklist.go                  # ensphere checklist [name]
    compliance.go                 # ensphere compliance [vuln_type]
    cvss.go                       # ensphere cvss
    sinks.go                      # ensphere sinks [category]
  internal/
    payloads/
      store.go                    # go:embed payloads.sqlite, extract to temp file (mode=ro)
      query.go                    # SQL query builder with rank/fallback logic
      model.go                    # Payload, PayloadFilter, QueryOutput, PayloadResult structs
      payloads.sqlite             # embedded DB (generated by seedgen)
    verify/
      sqli.go                     # SQLi probes (blind_time, blind_boolean, error_based)
      xss.go                      # XSS reflection check
      idor.go                     # IDOR with {id} placeholder
      ssrf.go                     # SSRF internal URL + metadata probes
      auth.go                     # Auth bypass (no_token, expired, alg_none, method_override)
      rls.go                      # Supabase RLS cross-tenant (builds JWTs with company_id)
      cmdi.go                     # Command injection (time-based blind)
      lfi.go                      # Local file inclusion (path traversal + signature detection)
      ssti.go                     # Server-side template injection (multi-engine)
      xxe.go                      # XML external entity (file_read, ssrf, oob)
      deserialization.go          # Insecure deserialization (time-based blind)
      csrf.go                     # CSRF (Origin validation + SameSite checks)
      nosql.go                    # NoSQL injection (operator injection, $where timing)
      jwt.go                      # JWT manipulation (alg_none, kid_injection)
      cors.go                     # CORS misconfiguration (origin reflection)
      protopollution.go           # Prototype pollution (__proto__, constructor)
      graphql.go                  # GraphQL abuse (introspection, batch, nested DoS)
      race.go                     # Race conditions (concurrent bursts)
      smuggling.go                # Request smuggling (CL-TE, TE-CL, TE-TE)
      cachepoisoning.go           # Cache poisoning (unkeyed headers/cookies)
      redirect.go                 # Open redirect (Location header inspection)
      csvinjection.go             # CSV injection (formula in exports)
      authz.go                    # Authorization bypass (privilege level comparison)
      clickjacking.go             # Clickjacking protection (X-Frame-Options, CSP)
      headerinjection.go          # CRLF header injection
      websocket.go                # WebSocket security measurements
      grpc.go                     # gRPC security measurements
      ratelimit.go                # Rate limit burst measurement
      propertyauthz.go            # Field-level authorization comparison
      ldap.go                     # LDAP injection (filter, blind boolean, blind error)
      xpath.go                    # XPath injection (classic, blind boolean, blind error)
      fileupload.go               # File upload (extension, MIME, polyglot bypass)
      massassignment.go           # Mass assignment (3-step: GET/mutate/verify)
      probe.go                    # HTTPProbe + MultipartHTTPProbe shared request logic + CheckMaxRisk
      scope.go                    # CheckScope hostname + CheckCloudScope provider validation
      model.go                    # Result/config structs (33 measurement types)
      throttle.go                 # Rate limiting between probes
    evidence/
      writer.go                   # JSONL append writer
      reader.go                   # JSONL reader with filtering
      model.go                    # Entry struct (ID, hashes, timing, result)
      redaction.go                # Secret stripping from URLs/logs
    runner/
      workspace.go                # Init/status/next-action and Session 10 selected-finding handoff
      plan.go                     # Deterministic assessment-plan drafting and validation
      report.go                   # Session 09 readiness, evidence, and finding-registry gates
      final.go                    # Session 11 outcome validation and derived registry
      model.go                    # Workspace, plan, progress, registry, and handoff models
      workspace_test.go           # Runner workspace/gate tests
    callback/
      server.go                   # OOB callback HTTP listener with token routing
    cloud/
      exec.go                     # Cloud CLI execution helper (RunCLI, CheckCLIInstalled)
      storage.go                  # S3/GCS/Blob storage security probe
      iam.go                      # IAM policy and permission analysis
      network.go                  # Security group / firewall rule analysis
      compute.go                  # Serverless/compute security probe
      logging.go                  # Audit logging/trail security probe
      secrets.go                  # Secrets management security probe
      parser.go                   # Prowler/Trivy output parser
    openapi/
      model.go                    # Spec, Endpoint, Parameter data models
      parser.go                   # OpenAPI v3 JSON/YAML parser
      parser_test.go              # Parser unit tests
    templates/
      data/                       # 13 template dirs (exploit.py + template.json + README.md)
      embed.go                    # go:embed data/*
      list.go                     # ListTemplates
      materialize.go              # write template to directory
      model.go                    # Template metadata struct
    checklist/
      data/                       # 13 checklist markdown files
      embed.go                    # go:embed data/*
      list.go                     # ListChecklists
      model.go                    # Checklist metadata struct
    compliance/
      data/mappings.yaml          # OWASP Top 10 2025, PCI-DSS v4.0.1, SOC 2, ISO 27001, OWASP API Security Top 10 2023
      embed.go                    # go:embed data/*
      query.go                    # query mappings by vuln_type
      model.go                    # Mapping struct
    cvss/
      v31.go                      # CVSS v3.1 base score calculator
      v40.go                      # CVSS v4.0 base score calculator
      v40_lookup.go               # v4.0 lookup tables
      model.go                    # CVSSResult struct
    scan/
      scanner.go                  # Multi-worker source code scanner
      model.go                    # ScanResult, Match structs
    sinks/
      data/sinks.yaml             # 22 categories: cmdi, cors, csrf, deserialization, file_upload, header_injection, idor, jwt, ldap, lfi, nosql, redirect, sqli, ssrf, ssti, xpath, xss, xxe, iac_terraform, iac_cloudformation, iac_dockerfile, iac_kubernetes
      embed.go                    # go:embed data/*
      query.go                    # query by category
      model.go                    # Sink pattern struct
    enums/
      enums.go                    # Validation maps for all enum fields
  tools/
    seedgen/main.go               # YAML seeds → SQLite compiler (validates enums at build)
assets/seeds/                     # 30 YAML seed files (includes authz.yaml, mass-assignment.yaml)
skills/                           # Portable AI-agent skill files
  SKILL.md                        # /ensphere entry point
  methodology/                    # 01-recon through 11-final-report, with 01.5 planning and 07a-d cloud sub-files
  checklists/                     # 13 security checklists (4 web framework + 6 web framework + 3 cloud)
```

## Build Pipeline

```bash
make seeds       # go run ./tools/seedgen → YAML seeds → payloads.sqlite
make checklists  # cp skills/checklists/*.md → cli/internal/checklist/data/
make build       # seeds + checklists + go build → bin/ensphere
```

Embed mechanism: `//go:embed payloads.sqlite` in `cli/internal/payloads/store.go`. At runtime, extracted to read-only temp file opened with `?mode=ro&_journal_mode=OFF`.

## SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS payloads (
  id                TEXT PRIMARY KEY,
  vuln_type         TEXT NOT NULL,
  db_engine         TEXT,
  runtime           TEXT,
  technique         TEXT NOT NULL,
  injection_surface TEXT NOT NULL,
  content_type      TEXT,
  encoding          TEXT NOT NULL,
  string_boundary   TEXT,
  evidence_type     TEXT NOT NULL,
  risk              INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 5),
  payload           TEXT NOT NULL,
  placeholders      TEXT NOT NULL DEFAULT '[]',
  notes             TEXT NOT NULL DEFAULT '',
  source            TEXT NOT NULL DEFAULT '',
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_payloads_lookup ON payloads(
  vuln_type, db_engine, runtime, technique,
  injection_surface, content_type, encoding, string_boundary, risk
);

CREATE TABLE IF NOT EXISTS payload_tags (
  payload_id TEXT NOT NULL,
  tag        TEXT NOT NULL,
  PRIMARY KEY (payload_id, tag),
  FOREIGN KEY (payload_id) REFERENCES payloads(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_payload_tags_tag ON payload_tags(tag);
```

Seedgen sets `journal_mode=WAL` during compilation, then `journal_mode=DELETE` after.

## Enum Vocabulary

All validated at build time by `enums.ValidateSeedPayload()` in seedgen.

| Field | Values |
|-------|--------|
| vuln_type | sqli, xss, ssrf, csv_injection, cmdi, lfi, ssti, deserialization, xxe, idor, authz, redirect, csrf, nosql, auth_bypass, prototype_pollution, graphql, jwt, cors, race_condition, request_smuggling, cache_poisoning, ldap, xpath, header_injection, file_upload, clickjacking, property_authz, api_inventory, websocket, grpc, rate_limit, cloud_iam, cloud_storage, cloud_network, cloud_compute, cloud_logging, cloud_k8s, cloud_secrets, iac_misconfig, error_handling (cloud_*, iac_*, error_handling, property_authz, api_inventory, rate_limit, websocket, grpc have no payloads — probe-only, compliance mapping, and evidence logging) |
| db_engine | postgres, mysql, mssql, sqlite, oracle |
| runtime | node, jvm, python, php, dotnet, ruby, go |
| technique | blind_time, blind_boolean, error_based, union, dns, oob, metadata_access, internal_service, protocol_smuggling, port_scan, cross_tenant, formula_injection, open_redirect, path_traversal, server_action, webhook_spoof, rls_bypass, reflected, stored, dom, polyglot, command_injection, command_chaining, argument_injection, nosql_injection, operator_injection, js_injection, where_time, directory_traversal, null_byte, wrapper, sandbox_escape, expression_eval, xxe_file_read, xxe_ssrf, xxe_oob, xxe_dos, open_redirect_param, open_redirect_path, deserialization_rce, deserialization_read, time_based, dns_oob, jwt_manipulation, default_credential, forced_browsing, auth_bypass, session_fixation, idor_numeric, idor_uuid, idor_path, bola, privilege_escalation, form_auto_submit, xhr_cross_origin, fetch_cross_origin, image_tag, origin_validation, proto_assignment, constructor_pollution, json_merge, introspection, batch_query, nested_query_dos, field_suggestion, alias_dos, alg_none, alg_confusion, kid_injection, jwk_injection, jku_spoofing, origin_reflection, null_origin, subdomain_wildcard, credential_leak, toctou, parallel_request, double_spend, cl_te, te_cl, te_te, h2_downgrade, unkeyed_header, unkeyed_cookie, fat_get, no_token, expired_token, method_override, rate_limit_bypass, ws_injection, ws_hijack, ws_origin_check, grpc_reflection, grpc_plaintext |
| injection_surface | query, path, header, cookie, json_body, form_body, xml_body, file_upload, websocket, graphql_query, grpc_unary |
| encoding | raw, url, double_url, unicode, hex, base64, html_entity, js_escape, null_byte |
| string_boundary | single_quote, double_quote, unquoted, numeric |
| evidence_type | timing, boolean_diff, error, content_match, dns_hit, oob, status_diff, header_match, redirect, response_diff, callback_hit, dom_execution |

## Query Semantics

```
ensphere payloads <vuln_type>
  --db <db_engine>
  --runtime <runtime>
  --technique <technique>
  --surface <injection_surface>
  --content-type <content_type>
  --encoding <encoding>
  --boundary <string_boundary>
  --tag <tag>
  --max-risk <1-5>    (default 3)
  --limit <N>          (default 20)
```

Output always JSON. No `--format` flag.

**Filter logic:**
- Nullable columns (db_engine, runtime, content_type, string_boundary): when filter set, match exact value OR NULL (engine-agnostic payloads always included). When unset, no constraint.
- Non-nullable columns (technique, injection_surface, encoding): when filter set, exact match only. When unset, no constraint.
- `--tag`: single value, filters via subquery on payload_tags.

**Ranking:** `ORDER BY rank_score ASC, risk ASC, id ASC`. Rank score = sum of CASE expressions (0 for exact match on nullable field, 1 for NULL fallback).

**JSON output:**
```json
{
  "query": { /* echoed non-empty filters */ },
  "count": 5,
  "results": [
    {
      "id": "...",
      "payload": "...",
      "technique": "blind_time",
      "injection_surface": "query",
      "encoding": "raw",
      "string_boundary": "single_quote",
      "evidence_type": "timing",
      "risk": 2,
      "placeholders": ["SLEEP_SECONDS"],
      "notes": "...",
      "source": "ensphere",
      "tags": ["pg_sleep"]
    }
  ]
}
```

## Key Design Glue Fields

- **risk** (1-5): Probe ordering. Safe first, destructive last. Default max-risk 3 prevents accidental damage.
- **evidence_type**: Contract between payloads and verification. "If timing payload → measure response delay; if error → look for DB error strings."
- **string_boundary**: First-class filter that cuts false negatives by avoiding quoting-context guessing.

## Evidence System

JSONL format. Each entry:
```json
{
  "id": "EVID-001",
  "session_number": 2,
  "finding_ref": "VULN-001",
  "timestamp": "2025-01-01T00:00:00Z",
  "probe_type": "sqli",
  "technique": "blind_time",
  "url": "http://target/api",
  "param": "id",
  "request_hash": "sha256:...",
  "response_hash": "sha256:...",
  "status_code": 200,
  "duration": "5.2s",
  "result": "probe",
  "notes": "...",
  "prev_hash": "a1b2c3...",
  "hash": "d4e5f6..."
}
```

Secret redaction applied automatically to URLs and Notes via `evidence.RedactSecrets()`. Request/response hashes capture proof without storing full payloads.

## Safety

- `--in-scope` mandatory on all verify commands
- Default throttle 500ms between probes
- Default max-risk 3
- Evidence JSONL with automatic secret redaction
- Exit codes (verify): 0 = probes completed (JSON on stdout), 2 = scope/usage error, 3 = runtime/probe failure
- Exit codes (evidence verify): 0 = chain valid, 1 = chain broken
