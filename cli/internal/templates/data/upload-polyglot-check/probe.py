#!/usr/bin/env python3
"""Upload polyglot check — test file upload validation with mismatched types.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed.
"""

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error
import uuid

# Configuration — replace before running
UPLOAD_URL = "http://localhost:3000/api/upload"
AUTH_HEADER = ""  # Optional
FIELD_NAME = "file"

# Test cases: (name, filename, content_type, content)
# Each tests a different bypass vector
TEST_CASES = [
    ("html_as_image", "test.png", "image/png",
     b"<html><body><script>alert(1)</script></body></html>"),
    ("svg_xss", "test.svg", "image/svg+xml",
     b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    ("exe_as_pdf", "test.pdf", "application/pdf",
     b"MZ\x90\x00\x03\x00\x00\x00"),
    ("double_extension", "test.php.png", "image/png",
     b"<?php echo 'test'; ?>"),
    ("null_byte", "test.php%00.png", "image/png",
     b"<?php echo 'test'; ?>"),
    ("html_content_type", "test.txt", "text/html",
     b"<script>alert(document.cookie)</script>"),
]

def build_multipart(field_name, filename, content_type, content):
    """Build multipart/form-data body manually (stdlib only)."""
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return body, boundary

def make_upload(url, field_name, filename, content_type, content, headers=None):
    """Upload a file and return round result dict and body."""
    body, boundary = build_multipart(field_name, filename, content_type, content)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    start = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        resp_body = resp.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": resp.status,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(resp_body.encode()).hexdigest(),
            "body_length": len(resp_body),
        }, resp_body
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", errors="replace")
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "status_code": e.code,
            "elapsed_ms": elapsed,
            "body_hash": hashlib.sha256(resp_body.encode()).hexdigest(),
            "body_length": len(resp_body),
        }, resp_body
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
    test_results = []

    for name, filename, content_type, content in TEST_CASES:
        probe_count += 1
        rr, resp_body = make_upload(UPLOAD_URL, FIELD_NAME, filename, content_type, content, headers)
        print(f"[{name}] status={rr['status_code']}", file=sys.stderr)
        time.sleep(0.5)

        test_results.append({
            "test": name,
            "filename": filename,
            "content_type": content_type,
            "round": rr,
        })

    result = {
        "vuln_type": "upload",
        "technique": "polyglot_bypass",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "tests_run": len(TEST_CASES),
            "test_results": test_results,
        },
    }

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
