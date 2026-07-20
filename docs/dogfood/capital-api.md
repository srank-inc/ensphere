# Capital API Dogfood Runbook

Purpose: verify Ensphere against the Capital API sandbox using real local evidence.

## Target

The benchmark workspace uses:

```bash
export BASE_URL="http://capital-api.sandbox.local:8000"
```

Set the actual local sandbox URL before running probes.

```bash
export EVIDENCE="ensphere-pentest/capital-api/evidence.jsonl"
mkdir -p ensphere-pentest/capital-api/transcripts
export SCOPE_FLAGS="--in-scope capital-api.sandbox.local --in-scope localhost --in-scope 127.0.0.1"
```

## Baseline Inventory

```bash
ensphere checklist --list > ensphere-pentest/capital-api/transcripts/checklists-available.json
ensphere payloads cmdi --limit 5 > ensphere-pentest/capital-api/transcripts/cmdi-payloads.json
ensphere payloads sqli --db postgres --limit 5 > ensphere-pentest/capital-api/transcripts/sqli-payloads.json
```

If the local implementation framework is known, save the matching framework checklist as an additional transcript.

## Auth Setup

Use dedicated disposable accounts. Store access tokens in environment variables, not in the repo.

```bash
export CAPITAL_TOKEN="<local test JWT>"
```

## API Probes

Run probes against endpoints confirmed in the local config.

```bash
ensphere verify cors \
  --url "$BASE_URL/api/health" \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/capital-api/transcripts/cors-health.json
```

For command injection or SSRF paths that require JSON request bodies, save a manual transcript and log the deterministic measurement:

```bash
ensphere evidence log \
  --file "$EVIDENCE" \
  --probe-type cmdi \
  --technique manual_json_body \
  --url "$BASE_URL/<endpoint>" \
  --param "<json-field>" \
  --status-code 200 \
  --duration "<measured-ms>" \
  --result probe \
  --notes "See transcripts/<saved-curl-transcript>.txt"
```

## Evidence Gate

```bash
ensphere evidence verify --file "$EVIDENCE"
ensphere evidence query --file "$EVIDENCE" --summary
```

Complete Sessions 01–09 and score the local report with
[../../skills/evaluation/README.md](../../skills/evaluation/README.md). Keep the
report local unless its evidence workspace is also ready for review.
