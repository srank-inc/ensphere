# Authentication Header Replay

Tests whether swapping authentication tokens between users grants unauthorized access.

## Setup

1. Obtain bearer tokens for two different users (A and B)
2. Identify API endpoints that should return user-scoped data
3. Edit `exploit.py` and fill in the configuration variables

## Usage

```bash
python3 exploit.py
```

## Parameters

| Name | Required | Description |
|------|----------|-------------|
| BASE_URL | Yes | Target base URL |
| ENDPOINTS | Yes | Comma-separated API endpoint paths |
| TOKEN_A | Yes | Bearer token for user A |
| TOKEN_B | Yes | Bearer token for user B |

## What It Tests

For each endpoint:
1. Request with user A's token (baseline A)
2. Request with user B's token (baseline B)
3. Compare — if responses are identical, the endpoint may not be filtering by user

## Interpreting Results

- **safe**: Responses differ between users — data is user-scoped
- **potential**: Identical responses for different users — needs manual review
