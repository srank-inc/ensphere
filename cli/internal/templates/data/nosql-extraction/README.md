# NoSQL Extraction

Tests NoSQL injection by sending MongoDB-style operator payloads ($ne, $gt, $regex,
$exists, $in) in JSON body parameters and comparing responses to a baseline.

## Setup

1. Identify a JSON API endpoint that queries a NoSQL database (e.g., login, search)
2. Edit `probe.py` and fill in TARGET_URL and PARAM
3. Optionally set AUTH_HEADER for authenticated endpoints

## Usage

```bash
python3 probe.py
```

## Probes

Tests 7 operator injection variants plus array type coercion:
- `{"$ne": ""}` and `{"$ne": null}` -- not-equal operators
- `{"$gt": ""}` -- greater-than operator
- `{"$regex": ".*"}` -- regex wildcard match
- `{"$exists": true}` -- field existence check
- `{"$in": [...]}` and `{"$nin": []}` -- set membership operators
- Array injection -- send parameter as array instead of string

## Output

JSON with `measurements` containing baseline round, per-operator probe results with `status_matches_baseline`, `hash_matches_baseline`, and `length_delta`. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
