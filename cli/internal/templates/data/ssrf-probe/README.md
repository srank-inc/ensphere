# SSRF Probe

Tests server-side request forgery by sending internal URL payloads and comparing
responses to an external baseline.

## Setup

1. Identify an endpoint that takes a URL parameter (e.g., link preview, webhook test, proxy)
2. Edit `exploit.py` and fill in TARGET_URL and PARAM
3. Optionally set AUTH_HEADER and EXTERNAL_URL

## Usage

```bash
python3 exploit.py
```

## Probes

Tests 9 internal URL variants:
- `127.0.0.1`, `localhost`, `0.0.0.0` — direct loopback
- `[::1]` — IPv6 loopback
- `0x7f000001`, `2130706433`, `127.1` — encoding bypasses
- AWS/GCP metadata endpoints

## Interpreting Results

- **confirmed**: 2+ probes returned different responses than external baseline
- **potential**: 1 probe showed differences — may be false positive
- **safe**: All probes returned consistent responses matching external baseline
