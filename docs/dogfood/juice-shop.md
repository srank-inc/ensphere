# Juice Shop Dogfood Runbook

Purpose: verify that Ensphere works on a real intentionally vulnerable web/API app without relying on canned findings.

## Target

Default local target:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Use:

```bash
export BASE_URL="http://localhost:3000"
export EVIDENCE="ensphere-pentest/juice-shop/evidence.jsonl"
mkdir -p ensphere-pentest/juice-shop/transcripts
```

Scope flags:

```bash
export SCOPE_FLAGS="--in-scope localhost --in-scope 127.0.0.1"
```

## Smoke Checks

```bash
ensphere payloads sqli --db sqlite --technique blind_boolean --limit 3
ensphere payloads xss --limit 3
ensphere checklist express-js > ensphere-pentest/juice-shop/transcripts/checklist-express-js.md
```

## SQLi Probes

Juice Shop has SQLite-style SQLi paths. Prefer boolean and error probes first because SQLite timing payloads are environment-sensitive.

```bash
ensphere verify sqli \
  --url "$BASE_URL/rest/products/search?q=apple" \
  --param q \
  --db sqlite \
  --technique blind_boolean \
  --string-boundary single_quote \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/juice-shop/transcripts/sqli-products-search-boolean.json
```

```bash
ensphere verify sqli \
  --url "$BASE_URL/rest/products/search?q=apple" \
  --param q \
  --db sqlite \
  --technique error_based \
  --string-boundary single_quote \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/juice-shop/transcripts/sqli-products-search-error.json
```

## Web/API Probes

Run only probes that match the endpoint shape and authorization state in the local config. Examples:

```bash
ensphere verify xss \
  --url "$BASE_URL/#/search?q=test" \
  --param q \
  --payload "<img src=x onerror=alert(1)>" \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/juice-shop/transcripts/xss-search.json
```

```bash
ensphere verify cors \
  --url "$BASE_URL/rest/products/search?q=apple" \
  $SCOPE_FLAGS \
  --evidence "$EVIDENCE" \
  | tee ensphere-pentest/juice-shop/transcripts/cors-products-search.json
```

## Evidence Gate

```bash
ensphere evidence verify --file "$EVIDENCE"
ensphere evidence query --file "$EVIDENCE" --summary
```

Complete Sessions 01–09, freeze the local report, and then score it with
[../../skills/evaluation/README.md](../../skills/evaluation/README.md). Do not
consult target ground truth before the report is frozen.
