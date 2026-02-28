# XXE OOB Extract

Tests XML External Entity injection by sending XML payloads with external entity
references. Uses out-of-band callbacks for blind detection and checks responses
for file content and XML parser error signatures.

## Setup

1. Identify an endpoint that accepts XML input (e.g., import, SOAP, file upload)
2. Edit `exploit.py` and fill in TARGET_URL and CALLBACK_URL
3. Set up a listener on CALLBACK_URL to detect OOB requests (e.g., `python3 -m http.server 8888`)
4. Optionally set METHOD (defaults to POST)

## Usage

```bash
python3 exploit.py
```

## Probes

Tests 8 XXE variants:
- Basic external entity via SYSTEM identifier
- Parameter entity for OOB extraction
- Direct file read (`/etc/passwd`, `win.ini`)
- OOB data exfiltration via parameter entity chaining
- XInclude for non-DTD parsers
- SVG-embedded XXE
- UTF-7 encoding bypass

Each OOB probe includes a unique probe ID and path for callback correlation.

Checks error responses for 12 XML parser signatures (SAXParseException, DOCTYPE, etc.)
and response bodies for known file content (passwd entries, win.ini sections).

## Output

JSON with `schema_version: 2` and `measurements` containing probe_id, callback_url, baseline round, and per-probe results with `matched_error_signatures`, `file_content_signatures`, `hash_matches_baseline`, and `response_snippet`. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
