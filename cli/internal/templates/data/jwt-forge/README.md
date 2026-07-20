# JWT Forge (alg=none)

Tests JWT algorithm none vulnerability by stripping the signature, setting
the algorithm to "none" variants, and comparing server responses to the
original authenticated request.

## Setup

1. Identify an authenticated endpoint that validates JWTs
2. Edit `probe.py` and fill in TARGET_URL and TOKEN (a valid JWT)
3. Optionally set AUTH_HEADER prefix (defaults to "Bearer")

## Usage

```bash
python3 probe.py
```

## Probes

Tests 5 alg=none variants:
- `alg: "none"` with empty signature
- `alg: "None"` -- capitalized
- `alg: "NONE"` -- all caps
- `alg: "nOnE"` -- mixed case
- `alg: "none"` with original signature preserved

Also tests baseline with original token and with no token for comparison.

## Output

JSON with `measurements` containing original token round, no-token round, and per-variant results with `status_matches_original`, `hash_matches_original`, and `status_matches_no_token`. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
- `2` -- config error (invalid JWT structure)
