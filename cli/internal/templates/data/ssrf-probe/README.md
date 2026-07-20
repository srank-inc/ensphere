# SSRF Probe

Tests server-side request forgery by sending internal URL payloads and comparing
responses to an external baseline.

## Setup

1. Identify an endpoint that takes a URL parameter (e.g., link preview, webhook test, proxy)
2. Edit `probe.py` and fill in TARGET_URL and PARAM
3. Optionally set AUTH_HEADER and EXTERNAL_URL

## Usage

```bash
python3 probe.py
```

## Probes

Tests 9 internal URL variants:
- `127.0.0.1`, `localhost`, `0.0.0.0` — direct loopback
- `[::1]` — IPv6 loopback
- `0x7f000001`, `2130706433`, `127.1` — encoding bypasses
- AWS/GCP metadata endpoints

## Output

JSON with `measurements` containing a baseline round result, per-probe round results with `hashes_match_baseline` and `matched_signatures` for each internal URL tested. No status or confidence — the AI reads measurements to classify.

## Exit Codes

- `0` — probes completed (JSON on stdout)
