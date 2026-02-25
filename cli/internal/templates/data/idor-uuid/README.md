# IDOR UUID Enumeration

Tests whether API endpoints enforce tenant isolation by attempting to access
tenant B's resource using tenant A's credentials.

## Setup

1. Obtain bearer tokens for two different tenants (A and B)
2. Identify a resource UUID belonging to tenant B
3. Edit `exploit.py` and fill in the configuration variables

## Usage

```bash
python3 exploit.py
```

## Parameters

| Name | Required | Description |
|------|----------|-------------|
| BASE_URL | Yes | Target base URL |
| ENDPOINT | Yes | API endpoint with `{id}` placeholder |
| TOKEN_A | Yes | Bearer token for tenant A |
| RESOURCE_ID_B | Yes | UUID of tenant B's resource |
| TOKEN_B | No | Tenant B's token for baseline comparison |

## Output

JSON with `schema_version: 2` and `measurements` containing per-request `round` results (status_code, elapsed_ms, body_hash, body_length) and a response snippet. No status or confidence — the AI reads measurements to classify.

## Exit Codes

- `0` — probes completed (JSON on stdout)
- `2` — configuration error
