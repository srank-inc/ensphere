# PostgreSQL Time-Based Blind SQL Injection

Injects `pg_sleep()` payloads and measures response timing to confirm blind SQLi.

## Setup

1. Identify a URL with a query parameter that reaches a SQL query
2. Edit `exploit.py` and fill in TARGET_URL, PARAM, and optionally AUTH_HEADER
3. Choose the correct BOUNDARY for the injection context

## Usage

```bash
python3 exploit.py
```

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| TARGET_URL | Yes | — | Full URL with injectable parameter |
| PARAM | Yes | — | Query parameter name |
| SLEEP_SECONDS | No | 5 | Seconds for pg_sleep |
| BOUNDARY | No | single_quote | String boundary context |
| AUTH_HEADER | No | — | Authorization header |

## How It Works

1. **Baseline**: 3 normal requests to establish average response time
2. **Payload**: 3 requests with `pg_sleep(N)` — should delay by N seconds
3. **Control**: 1 request with `pg_sleep(0)` — should be fast (confirms syntax is valid)

## Interpreting Results

- **confirmed**: Consistent delay matching sleep duration across all rounds
- **potential**: Some delay but inconsistent — could be network jitter
- **safe**: No significant timing difference
