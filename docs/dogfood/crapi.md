# crAPI Dogfood Runbook

Purpose: verify Ensphere against an API-heavy target with authentication, authorization, SSRF, and PostgreSQL-oriented injection surfaces.

## Target

Start crAPI locally using the upstream project instructions. The common local gateway is:

```bash
export BASE_URL="http://localhost:8888"
```

If your local deployment uses HTTPS or a different port, set `BASE_URL` accordingly.

Use:

```bash
export EVIDENCE="ensphere-pentest/crapi/evidence.jsonl"
mkdir -p ensphere-pentest/crapi/transcripts
export SCOPE_FLAGS="--in-scope localhost --in-scope 127.0.0.1"
```

## Baseline Inventory

```bash
ensphere checklist --list > ensphere-pentest/crapi/transcripts/checklists-available.json
ensphere payloads sqli --db postgres --technique blind_boolean --limit 5 > ensphere-pentest/crapi/transcripts/postgres-sqli-payloads.json
ensphere payloads nosql --limit 5 > ensphere-pentest/crapi/transcripts/nosql-payloads.json
```

If the local deployment stack maps cleanly to one of Ensphere's framework checklists, also save that checklist, for example `ensphere checklist django`.

## Auth Setup

Create normal test users through the local UI or API and store tokens outside git. Do not paste raw bearer tokens into reports.

```bash
export CRAPI_TOKEN="<local test JWT>"
```

## SQLi Notes

Current `ensphere verify sqli` supports query parameters and form body parameters. For JSON-only crAPI endpoints, use `ensphere payloads sqli --db postgres --surface json_body` to select payloads, execute the HTTP request manually, then log the raw measurement with `ensphere evidence log`.

Query/form endpoints can use the verifier directly:

```bash
ensphere verify sqli \
  --url "$BASE_URL/some/query/path?id=1" \
  --param id \
  --db postgres \
  --technique blind_boolean \
  --header "Authorization: Bearer $CRAPI_TOKEN" \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/crapi/transcripts/sqli-query-boolean.json
```

For JSON endpoints, save both the payload selection and HTTP transcript:

```bash
ensphere payloads sqli \
  --db postgres \
  --technique blind_boolean \
  --surface json_body \
  --limit 10 \
  | tee ensphere-pentest/crapi/transcripts/sqli-json-payloads.json
```

Then log the measured request:

```bash
ensphere evidence log \
  --file "$EVIDENCE" \
  --probe-type sqli \
  --technique manual_json_body \
  --url "$BASE_URL/<json-endpoint>" \
  --param "<json-field>" \
  --status-code 200 \
  --duration "<measured-ms>" \
  --result probe \
  --notes "See transcripts/<saved-curl-transcript>.txt"
```

## API Probes

Run authorization and SSRF probes only after config captures valid users, object IDs, and token constraints.

```bash
ensphere verify cors \
  --url "$BASE_URL/identity/api/auth/login" \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/crapi/transcripts/cors-login.json
```

## Evidence Gate

```bash
ensphere evidence verify --file "$EVIDENCE"
ensphere evidence query --file "$EVIDENCE" --summary
```

Complete Sessions 01–09, freeze the local report, and then score it with
[../../skills/evaluation/README.md](../../skills/evaluation/README.md). Do not
consult target ground truth before the report is frozen.
