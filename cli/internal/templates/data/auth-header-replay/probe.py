#!/usr/bin/env python3
"""Auth header replay — test cross-user access with swapped tokens.

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
BASE_URL = "https://app.example.com"
ENDPOINTS = "/api/profile,/api/invoices,/api/settings"
TOKEN_A = "eyJ..."  # User A's bearer token
TOKEN_B = "eyJ..."  # User B's bearer token

def make_request(url, token):
    """Send GET request with bearer token, return round result dict and body."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
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
    endpoints = [e.strip() for e in ENDPOINTS.split(",") if e.strip()]
    probe_count = 0
    endpoint_measurements = []

    for endpoint in endpoints:
        url = BASE_URL + endpoint

        # Step 1: User A accessing with own token
        probe_count += 1
        a_round, a_body = make_request(url, TOKEN_A)

        # Step 2: User B accessing with own token
        probe_count += 1
        b_round, b_body = make_request(url, TOKEN_B)

        time.sleep(0.5)

        print(f"[{endpoint}] A={a_round['status_code']}({a_round['body_length']}B) B={b_round['status_code']}({b_round['body_length']}B)", file=sys.stderr)

        endpoint_measurements.append({
            "endpoint": endpoint,
            "user_a_round": a_round,
            "user_b_round": b_round,
            "hashes_match": a_round["body_hash"] == b_round["body_hash"],
            "body_length_delta": a_round["body_length"] - b_round["body_length"],
        })

    result = {
        "vuln_type": "authz",
        "technique": "cross_tenant",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "endpoints_tested": len(endpoints),
            "endpoints": endpoint_measurements,
        },
    }

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
